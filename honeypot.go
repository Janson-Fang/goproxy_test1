package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
蜜罐端口（port trap）

解决的问题很具体：**纯 L4 扫描在应用层完全看不见**。Go 的 http server 只有
收到请求才进 handler，connect 完就关的 TCP 扫描一个字节都不留 —— 被动检测
这条路在这里是断的。行为评分（另一条路）也只能覆盖「发起了 HTTP 请求」的探测。

于是换个思路：不去被动检测，而是**提供一个不该有人访问的端口**。
正常用户没有任何理由连一个没有服务的端口，所以「连上了」这件事本身就是
扫描的充分证据 —— 不需要评分、不需要频率阈值、不需要观察窗口。
这是整条链路里最可靠的一个信号，代价只是占一个端口号。

「伪装成开放」靠的是一次成功的 accept：内核替我们回了 SYN-ACK，对方的
connect() 因此成功、判定端口 open。随后我们立刻关掉连接、一个字节都不发 ——
不给对方任何可以用来做指纹识别的材料。

想让「一整段端口看起来都开着」不必在这里开一堆 listener，交给部署侧的
端口重定向即可（用 nft/iptables 把整段端口转到本机一个端口上），这里只需要一个真实端口。

UDP 的规矩只有一条：**绝不回包**。UDP 源地址可以伪造，回包会打到受害者身上，
我们几个字节的响应就能变成一次反射放大。收下、记账、封禁，然后什么都不发。
*/

const (
	// honeypotReadWait 是 accept 之后等对方说第一句话的时间。
	//
	// 多数扫描器连上就关，不值得为它们各挂一个 goroutine 等太久；而愿意
	// 说话的（TLS ClientHello、HTTP 请求行、SSH 版本串）是更值钱的证据，
	// 所以留一个很短的窗口把它们收下来。
	honeypotReadWait = 150 * time.Millisecond

	// honeypotMaxInflight 限制同时处理的连接数。
	//
	// 蜜罐端口本身是个显眼的靶子：不设上限的话，往它灌连接就能让 goroutine
	// 与内存无上限增长。超过上限就直接关，不读、不记样本 —— 反正这些来源
	// 早就在第一批里被封了。
	honeypotMaxInflight = 512

	// honeypotDrainMax 是一次连接最多读掉多少字节才关闭。
	//
	// 存在的理由只有一个：**不读完就关会让内核发 RST**，而 RST 会让对方
	// 认定端口不是开放的（诱饵失效，见 handleTCP 的说明）。
	// 8 KB 足够吃下 TLS ClientHello、HTTP 请求头这类典型探测，
	// 又不会让一个持续灌数据的连接把内存占住。
	honeypotDrainMax = 8 << 10

	// honeypotRecentKeep 是给控制台看的最近命中条数。
	honeypotRecentKeep = 200

	// honeypotLogPerWindow / honeypotLogWindow 是日志限流：蜜罐被刷的时候
	// 每个包写一行日志，等于把日志系统变成攻击者的写入放大器。
	honeypotLogPerWindow = 5
	honeypotLogWindow    = 10 * time.Second
)

// honeypotPort 是一个要伪装的端口。
type honeypotPort struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"` // tcp | udp
	Note  string `json:"note"`
}

func (p honeypotPort) key() string {
	proto := strings.ToLower(strings.TrimSpace(p.Proto))
	if proto == "" {
		proto = "tcp"
	}
	return proto + "/" + strconv.Itoa(p.Port)
}

// honeypotProbe 是一次命中。
type honeypotProbe struct {
	Time  time.Time `json:"time"`
	IP    string    `json:"ip"`
	Port  int       `json:"port"`
	Proto string    `json:"proto"`
	// Head 是 TCP 上收到的前几个字节（多数扫描器连上就关，这里是空的）。
	Head string `json:"head,omitempty"`
}

// honeypotStat 是单个端口的统计快照。
type honeypotStat struct {
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Note      string `json:"note"`
	Listening bool   `json:"listening"`
	Hits      int64  `json:"hits"`
	Distinct  int    `json:"distinct_ips"`
	FirstAt   string `json:"first_at,omitempty"`
	LastAt    string `json:"last_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

type trap struct {
	spec honeypotPort

	mu       sync.Mutex
	hits     int64
	distinct map[string]struct{}
	firstAt  time.Time
	lastAt   time.Time
	bindErr  string

	logWindow time.Time
	logCount  int
}

func newTrap(p honeypotPort) *trap {
	return &trap{spec: p, distinct: map[string]struct{}{}}
}

// record 记一次命中。返回「是否已被封禁过的重复来源」之外的信息不重要，
// 调用方只关心要不要写日志，交给 allowLog。
func (t *trap) record(ip string) {
	t.mu.Lock()
	t.hits++
	if ip != "" {
		t.distinct[ip] = struct{}{}
	}
	now := time.Now()
	if t.firstAt.IsZero() {
		t.firstAt = now
	}
	t.lastAt = now
	t.mu.Unlock()
}

// allowLog 做日志限流：窗口内只允许少量几条日志。
func (t *trap) allowLog() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if now.Sub(t.logWindow) > honeypotLogWindow {
		t.logWindow = now
		t.logCount = 0
	}
	t.logCount++
	return t.logCount <= honeypotLogPerWindow
}

func (t *trap) snapshot(listening bool) honeypotStat {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := honeypotStat{
		Port: t.spec.Port, Proto: t.spec.Proto, Note: t.spec.Note,
		Listening: listening, Hits: t.hits, Distinct: len(t.distinct),
		Error: t.bindErr,
	}
	if !t.firstAt.IsZero() {
		st.FirstAt = formatLogTime(t.firstAt)
	}
	if !t.lastAt.IsZero() {
		st.LastAt = formatLogTime(t.lastAt)
	}
	return st
}

type honeypot struct {
	// onProbe 是命中上报。蜜罐不自己决定封谁 —— 那是 banList 与 App 的事。
	onProbe func(honeypotProbe)

	mu     sync.Mutex
	traps  map[string]*trap
	lns    map[string]net.Listener
	pkts   map[string]net.PacketConn
	recent []honeypotProbe
	closed bool

	sem chan struct{}
}

func newHoneypot(onProbe func(honeypotProbe)) *honeypot {
	return &honeypot{
		onProbe: onProbe,
		traps:   map[string]*trap{},
		lns:     map[string]net.Listener{},
		pkts:    map[string]net.PacketConn{},
		sem:     make(chan struct{}, honeypotMaxInflight),
	}
}

// Sync 让正在监听的集合等于传入的列表（幂等）。
//
// conflict 由调用方注入：它负责回答「这个端口是不是本进程自己要用」。
// 冲突是**配置错误**，必须拦住而不是硬绑 —— 蜜罐占了真实服务的端口，
// 结果是那条路由静默失效，比不生效糟得多。
//
// 返回的错误汇总了所有问题端口，但**能起的都起了**：和 listeners.Sync 一样，
// 单个端口的问题不该让整次重载失败。
func (h *honeypot) Sync(ports []honeypotPort, conflict func(honeypotPort) string) error {
	if h == nil {
		if len(ports) == 0 {
			return nil
		}
		return errors.New("蜜罐未初始化")
	}
	desired := map[string]honeypotPort{}
	var problems []string

	for _, p := range ports {
		p.Proto = strings.ToLower(strings.TrimSpace(p.Proto))
		if p.Proto == "" {
			p.Proto = "tcp"
		}
		if p.Proto != "tcp" && p.Proto != "udp" {
			problems = append(problems, fmt.Sprintf("端口 %d：proto 只能是 tcp|udp，收到 %q", p.Port, p.Proto))
			continue
		}
		if p.Port < 1 || p.Port > 65535 {
			problems = append(problems, fmt.Sprintf("%s：端口号超出 1-65535", p.key()))
			continue
		}
		if conflict != nil {
			if why := conflict(p); why != "" {
				problems = append(problems, fmt.Sprintf("%s：%s", p.key(), why))
				continue
			}
		}
		if _, dup := desired[p.key()]; dup {
			problems = append(problems, fmt.Sprintf("%s：重复", p.key()))
			continue
		}
		desired[p.key()] = p
	}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return errors.New("蜜罐已经关闭")
	}

	// 关掉不再需要的
	for key, ln := range h.lns {
		if _, ok := desired[key]; !ok {
			_ = ln.Close()
			delete(h.lns, key)
			delete(h.traps, key)
			slog.Info("蜜罐端口已下线", "trap", key)
		}
	}
	for key, pc := range h.pkts {
		if _, ok := desired[key]; !ok {
			_ = pc.Close()
			delete(h.pkts, key)
			delete(h.traps, key)
			slog.Info("蜜罐端口已下线", "trap", key)
		}
	}
	h.mu.Unlock()

	// 起新的
	for key, p := range desired {
		h.mu.Lock()
		_, hasTCP := h.lns[key]
		_, hasUDP := h.pkts[key]
		h.mu.Unlock()
		if hasTCP || hasUDP {
			continue
		}

		t := newTrap(p)
		if p.Proto == "udp" {
			pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", p.Port))
			if err != nil {
				t.bindErr = err.Error()
				problems = append(problems, fmt.Sprintf("%s：监听失败 %v", key, err))
				h.setTrap(key, t)
				continue
			}
			h.setConn(key, nil, pc)
			h.setTrap(key, t)
			go h.serveUDP(t, pc)
			slog.Info("蜜罐端口已开启（UDP）", "port", p.Port)
			continue
		}

		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p.Port))
		if err != nil {
			t.bindErr = err.Error()
			problems = append(problems, fmt.Sprintf("%s：监听失败 %v", key, err))
			h.setTrap(key, t)
			continue
		}
		h.setConn(key, ln, nil)
		h.setTrap(key, t)
		go h.serveTCP(t, ln)
		slog.Info("蜜罐端口已开启（TCP）", "port", p.Port)
	}

	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "；"))
	}
	return nil
}

func (h *honeypot) setTrap(key string, t *trap) {
	h.mu.Lock()
	h.traps[key] = t
	h.mu.Unlock()
}

func (h *honeypot) setConn(key string, ln net.Listener, pc net.PacketConn) {
	h.mu.Lock()
	if ln != nil {
		h.lns[key] = ln
	}
	if pc != nil {
		h.pkts[key] = pc
	}
	h.mu.Unlock()
}

func (h *honeypot) serveTCP(t *trap, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// 临时错误（EMFILE 之类）：歇一下再来，不要退化成忙轮询。
			slog.Debug("蜜罐端口 accept 失败", "port", t.spec.Port, "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case h.sem <- struct{}{}:
			go func() {
				defer func() { <-h.sem }()
				h.handleTCP(t, conn)
			}()
		default:
			// 在途连接太多：直接关。不读、不记样本 —— 这个来源早在第一批里
			// 已经被封了，这里再花资源就是替攻击者干活。
			_ = conn.Close()
		}
	}
}

func (h *honeypot) handleTCP(t *trap, conn net.Conn) {
	defer conn.Close()

	_, ipStr := peerIP(conn.RemoteAddr())

	// 把对方发来的东西读掉再关 —— 这一段是「伪装」是否成立的关键。
	//
	// 读掉不是为了看内容（内容只留前 64 字节做样本），而是因为**没读完就关
	// 会让内核发 RST**：对方看到的是一次连接错误，而不是「端口开着、对面主动
	// 断开」。区别很实际：
	//   - RST 会让某些客户端（实测 Windows）在 connect() 阶段就报错，
	//     扫描器据此把这个端口判成 closed/filtered，诱饵当场露馅；
	//   - 而「连上之后被对面关掉」正是没人维护的真实服务最常见的样子。
	//
	// 所以既不能设 SetLinger(0)（那是主动求一个 RST），也不能只读一小段就走
	// （TLS ClientHello 通常几百字节，剩下的留在缓冲区里照样触发 RST）。
	head := ""
	buf := make([]byte, 512)
	drained := 0
	_ = conn.SetReadDeadline(time.Now().Add(honeypotReadWait))
	for drained < honeypotDrainMax {
		n, err := conn.Read(buf)
		if n > 0 {
			drained += n
			if head == "" {
				head = summarizeBytes(buf[:minInt(n, 64)])
			}
		}
		if err != nil {
			break
		}
	}

	t.record(ipStr)
	h.report(honeypotProbe{
		Time: time.Now(), IP: ipStr, Port: t.spec.Port, Proto: "tcp", Head: head,
	})
}

func (h *honeypot) serveUDP(t *trap, pc net.PacketConn) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Debug("蜜罐端口读包失败", "port", t.spec.Port, "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		_, ipStr := peerIP(addr)
		t.record(ipStr)
		// 刻意不回包。UDP 源地址可伪造，回包是替攻击者打受害者。
		// 这一行不是遗漏，是设计。
		head := buf[:minInt(n, 64)]
		h.report(honeypotProbe{
			Time: time.Now(), IP: ipStr, Port: t.spec.Port, Proto: "udp",
			Head: summarizeBytes(head),
		})
	}
}

func (h *honeypot) report(p honeypotProbe) {
	h.mu.Lock()
	h.recent = append(h.recent, p)
	if len(h.recent) > honeypotRecentKeep {
		h.recent = h.recent[len(h.recent)-honeypotRecentKeep:]
	}
	fn := h.onProbe
	h.mu.Unlock()
	if fn != nil {
		fn(p)
	}
}

// Stats 返回每个端口的统计（给控制台）。
func (h *honeypot) Stats() []honeypotStat {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	traps := make([]*trap, 0, len(h.traps))
	listening := map[string]bool{}
	for k := range h.lns {
		listening[k] = true
	}
	for k := range h.pkts {
		listening[k] = true
	}
	for _, t := range h.traps {
		traps = append(traps, t)
	}
	h.mu.Unlock()

	out := make([]honeypotStat, 0, len(traps))
	for _, t := range traps {
		out = append(out, t.snapshot(listening[t.spec.key()]))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

// Recent 返回最近的命中样本。
func (h *honeypot) Recent() []honeypotProbe {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]honeypotProbe, len(h.recent))
	copy(out, h.recent)
	return out
}

func (h *honeypot) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	for _, ln := range h.lns {
		_ = ln.Close()
	}
	for _, pc := range h.pkts {
		_ = pc.Close()
	}
	h.lns = map[string]net.Listener{}
	h.pkts = map[string]net.PacketConn{}
	h.mu.Unlock()
}

// ---------- 小工具 ----------

// peerIP 从 net.Addr 里取出对端 IP。蜜罐没有 XFF 可看（不是 HTTP），
// 所以这里拿到的就是**直连对端** —— 若蜜罐端口挂在 CDN/Lucky 后面，
// 那看到的是上一跳的地址 —— 封禁会打在上游代理身上，别把它放在另一层反代后面。
func peerIP(addr net.Addr) (net.IP, string) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP, a.IP.String()
	case *net.UDPAddr:
		return a.IP, a.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, addr.String()
	}
	ip := net.ParseIP(host)
	return ip, host
}

// summarizeBytes 把收到的字节压成一段可读、可进日志与界面的文本。
func summarizeBytes(b []byte) string {
	out := make([]rune, 0, len(b))
	for _, c := range b {
		switch {
		case c == '\r' || c == '\n':
			out = append(out, ' ')
		case c >= 0x20 && c < 0x7f:
			out = append(out, rune(c))
		default:
			out = append(out, '.')
		}
	}
	return strings.TrimSpace(string(out))
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
