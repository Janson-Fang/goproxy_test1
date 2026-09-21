package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

/*
App 侧的接线：把 banList（机制）与 honeypot（监听）接到请求管线和管理接口上。

分成三层是刻意的：
	banlist.go  只认「谁被封了、封多久」—— 不知道 HTTP，也不知道端口
	honeypot.go 只认「谁碰了不该碰的端口」—— 不决定封谁，通过回调上报
	banapi.go   这一层才把两者与 App 的知识接起来：谁该豁免、拒绝请求怎么回、
	            哪些端口不能占、控制台怎么读写
这样「谁不该被封」的判断只写一遍，且写在唯一能同时看到配置与运行态的地方。
*/

// honeypotRuntime 是蜜罐配置的运行时快照（含预解析好的豁免网段）。
// 不可变 + 原子指针，同 RouteTable：蜜罐路径只读它，不取任何锁。
type honeypotRuntime struct {
	cfg        honeypotConfig
	exemptNets []*net.IPNet
}

// applyHoneypot 让运行态等于给定配置。reload 与写接口都走它。
//
// base 用来判断端口冲突，只读不持有 —— 调用方可能正持着 a.mu（reload 路径），
// 这里再取一次就是死锁。
func (a *App) applyHoneypot(cfg honeypotConfig, base *Config) error {
	if err := cfg.normalize(); err != nil {
		return err
	}

	rt := &honeypotRuntime{cfg: cfg}
	for _, s := range cfg.Exempt {
		if _, n, err := net.ParseCIDR(s); err == nil {
			rt.exemptNets = append(rt.exemptNets, n)
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			rt.exemptNets = append(rt.exemptNets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	a.honeypotCfg.Store(rt)
	a.bans.SetBase(time.Duration(cfg.BanSecs) * time.Second)

	if !cfg.Enabled {
		// 关掉蜜罐只撤监听，**不动已有的封禁**：关掉一个探测手段不等于大赦，
		// 那些地址确实在扫。要不要解封是另一个决定（控制台或 -unban）。
		return a.trap.Sync(nil, nil)
	}

	// 本进程自己要用的端口，一个都不能被蜜罐占掉。
	//
	// 这类冲突必须拦住而不是硬绑：蜜罐抢了真实服务的端口，结果是那条路由
	// 静默失效 —— 比蜜罐不生效糟得多，而且现象会指向完全无关的方向。
	taken := map[int]string{}
	if base != nil {
		for _, p := range base.allListenPorts() {
			taken[p] = "已经有一条路由要监听这个端口"
		}
		if base.TLS.Enabled {
			for p := range base.tlsPorts() {
				taken[p] = "这是 TLS 端口"
			}
		}
		if p := addrPort(base.AdminAddr); p > 0 {
			taken[p] = "这是管理端口（控制台）"
		}
	}
	return a.trap.Sync(cfg.Ports, func(p honeypotPort) string { return taken[p.Port] })
}

// banExempt 判断一个地址是否享受自动封禁豁免，返回 (豁免, 原因)。
//
// 顺序就是优先级，短路在最前面。每一条都对应一种「误封的代价比误放大」的场景：
// 封错一个真实用户是十分钟的 403，封错一个可信代理是整个入口消失。
//
// 只走原子读（a.table / a.trusted / recentIPs 自己的锁），**不碰 a.mu** ——
// 蜜罐的 goroutine 会在 reload 持锁期间回调进来（端口刚在 Sync 里打开就有人连），
// 那里取一次 a.mu 就是死锁。
func (a *App) banExempt(ip net.IP) (bool, string) {
	if ip == nil {
		return true, "地址解析不出来"
	}
	if isLocalNet(ip) {
		return true, "回环/私网/保留地址 —— 自动封禁只管外部来源，封内网只会误伤自己人"
	}
	// 蜜罐看到的是**直连对端**（不是 HTTP，没有 XFF 可解析）。前面挂反代时
	// 那就是反代自己 —— 封了它等于封掉整个入口。
	if ipInNets(ip, a.trustedNets()) {
		return true, "在 trusted_proxies 里（上一跳是可信代理）"
	}
	// 白名单是人工声明的「自己人」，不该被自动判据推翻。
	if tbl := a.table.Load(); tbl != nil {
		if name, ok := tbl.allowHit(ip); ok {
			return true, "命中白名单「" + name + "」"
		}
	}
	// 正在操作控制台的人：自动判据不该把你关在门外。
	// （guardSelfLockout 挡的是「保存一份会把自己挡住的配置」，
	//   这里挡的是「自动判据把你封了」，两条路都得有。）
	if a.consoleSeen.has(ip.String()) {
		return true, "最近用过控制台（防止把自己锁在外面）"
	}
	if rt := a.honeypotCfg.Load(); rt != nil {
		for _, n := range rt.exemptNets {
			if n.Contains(ip) {
				return true, "命中显式豁免 " + n.String()
			}
		}
	}
	return false, ""
}

// onTrapProbe 是蜜罐命中的处置入口。
//
// 这里没有评分、没有频率阈值：正常用户没有任何理由连一个没有服务的端口，
// 所以「连上了」本身就是充分证据。频率只影响日志与阶梯，不影响「封不封」。
func (a *App) onTrapProbe(p honeypotProbe) {
	rt := a.honeypotCfg.Load()
	if rt == nil || !rt.cfg.Enabled {
		return
	}

	trap := fmt.Sprintf("%s/%d", p.Proto, p.Port)
	sample := p.Head
	if sample == "" {
		// TCP 连上就关（多数扫描器如此）或空 UDP 包。留个标记，
		// 免得控制台上看到一条没有样本的记录以为采集坏了。
		sample = "(connect)"
	}

	if rt.cfg.Mode != honeypotModeEnforce {
		// 观察模式：只记录，一个都不封。控制台据此显示「如果开启会封哪些」——
		// 「哪些端口算没人访问」是你说了算的，先看一轮再开更稳。
		//
		// 日志要限流：蜜罐被刷的时候每个包写一行，日志系统就成了攻击者的写入放大器。
		if a.trapLog.allow() {
			slog.Info("蜜罐命中（观察模式，未封禁）", "ip", p.IP, "trap", trap, "head", sample)
		}
		a.trapObserved.Add(1)
		return
	}

	entry, added := a.bans.add(p.IP, trap, banSourceHoneypot, sample)
	if !added {
		// 三种情况会走到这：命中豁免、突发熔断中、已经在生效期内。
		// 一律只留 debug —— 这也是重复命中的日志限流。
		slog.Debug("蜜罐命中（未新封禁）", "ip", p.IP, "trap", trap)
		return
	}
	slog.Warn("蜜罐命中：已封禁该来源",
		"ip", p.IP, "trap", trap, "level", entry.Level,
		"until", formatLogTime(entry.ExpiresAt), "head", sample)
}

// checkAutoBan 是请求管线的第 0.5 关：自动封禁。
//
// 位置的两个约束：
//   - 必须在路由匹配**之前**：扫描流量大多匹配不到任何路由，放在后面
//     就等于对它们完全失效 —— 与 checkGlobalDeny 同一个理由。
//   - 放在人工黑名单**之后**：人工声明是权威、自动判据是临时态。
//     日志里该看到的是「我封的」，而不是「它自己封的」。
func (a *App) checkAutoBan(rec *statusRecorder, r *http.Request, ip string, blocked *string) bool {
	entry, ok := a.bans.lookup(ip)
	if !ok {
		return false
	}
	*blocked = "auto_ban"
	a.metrics.IncRejected("", "auto_ban")
	a.metrics.IncRequest("", http.StatusForbidden)
	refuseAutoBanned(rec, r, ip, entry)
	return true
}

// refuseAutoBanned 回一个「什么都不说」的 403。
//
// 刻意不带 reason、不带 JSON、不带 Content-Type：对方已经被判定为扫描来源，
// 没有理由再帮它确认任何事情。Connection: close 让连接立刻结束，
// 不让它在一个连接上继续试。具体原因进访问日志和控制台（运维看得到，
// 对面学不到）—— 与全局黑名单那条注释同一个取舍。
//
// 「先把请求体丢掉再关」不是可选的细节：POST 带了 body 而我们不读就关连接，
// 内核会直接发 RST（缓冲区里还有没被读走的数据），客户端看到的是
// 「连接被重置」而不是这条 403。对我们想表达的「明确拒绝」来说，
// 一个连接重置反而是更差的反馈 —— 它跟网络故障长得一模一样。
func refuseAutoBanned(w http.ResponseWriter, r *http.Request, ip string, entry banEntry) {
	slog.Debug("自动封禁拦截请求",
		"ip", ip, "reason", entry.Reason, "level", entry.Level,
		"until", formatLogTime(entry.ExpiresAt))
	if r != nil && r.Body != nil {
		// 限量：没必要为了讲礼貌被一个几百 MB 的 body 拖住。
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 64<<10))
		_ = r.Body.Close()
	}
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusForbidden)
}

// rememberConsoleSource 记下「正在用控制台的人」的来源地址，供自动封禁豁免。
//
// 只在**鉴权通过之后**调用。放在鉴权之前是不行的：管理端口上的 /metrics
// 与 /healthz 不需要认证，任何人扫一下就能给自己换来十分钟的封禁豁免 ——
// 那是一条现成的绕过路径。
func (a *App) rememberConsoleSource(r *http.Request) {
	if a.consoleSeen == nil {
		return
	}
	for _, ip := range a.consoleClientIPs(r) {
		a.consoleSeen.remember(ip)
	}
}

// ---------- 日志限流 ----------

type logLimiter struct {
	mu     sync.Mutex
	span   time.Duration
	per    int
	window time.Time
	count  int
}

func newLogLimiter(per int, span time.Duration) *logLimiter {
	return &logLimiter{per: per, span: span}
}

func (l *logLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.window) > l.span {
		l.window = now
		l.count = 0
	}
	l.count++
	return l.count <= l.per
}

// ---------- HTTP 接口 ----------

// handleBansState 是控制台「封禁」页的数据源，一次给全。
func (a *App) handleBansState(w http.ResponseWriter, r *http.Request) {
	cfg := defaultHoneypotConfig()
	if rt := a.honeypotCfg.Load(); rt != nil {
		cfg = rt.cfg
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":  cfg,
		"stats":   a.bans.stats(),
		"entries": a.bans.list(),
		"traps":   a.trap.Stats(),
		"recent":  a.trap.Recent(),
		"ladder":  banLadderLabels(cfg.BanSecs),
	})
}

// handleBanCreate 手动封禁一个地址。
func (a *App) handleBanCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
		Secs   int    `json:"secs"`
	}
	if err := readOptionalJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	ip := strings.TrimSpace(req.IP)
	if net.ParseIP(ip) == nil {
		writeErr(w, badRequest("bad_ip", "%q 不是一个 IP 地址", req.IP))
		return
	}
	if req.Secs <= 0 {
		req.Secs = int(24 * time.Hour / time.Second)
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "manual"
	}
	entry, ok := a.bans.addManual(ip, reason, time.Duration(req.Secs)*time.Second)
	if !ok {
		writeErr(w, badRequest("bad_ip", "%q 不是一个 IP 地址", ip))
		return
	}
	// 人工动作立刻落盘，不等攒批。
	//
	// 自动封禁是「攒一会儿再写」（保护被扫时的写压力），但人点了按钮之后
	// 期望的是「现在就生效、现在就在库里」—— 否则紧接着用 goproxy -bans
	// 看会是空的，看起来像没封上。
	a.bans.flush()

	actor := actorLabel(a.identifyAdminRequest(r, sessionHandleFrom(r)))
	slog.Info("人工封禁", "actor", actor, "ip", ip, "reason", reason,
		"until", formatLogTime(entry.ExpiresAt))
	writeJSON(w, http.StatusOK, entry)
}

// handleBanRemove 解封。ip 传 "all" 清空全部。
func (a *App) handleBanRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	if err := readOptionalJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		writeErr(w, badRequest("bad_ip", "要指定 ip（或用 \"all\" 清空）"))
		return
	}
	actor := actorLabel(a.identifyAdminRequest(r, sessionHandleFrom(r)))

	if ip == "all" {
		n := a.bans.clear()
		a.bans.flush()
		slog.Warn("清空全部自动封禁", "actor", actor, "count", n)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": n})
		return
	}
	was := a.bans.remove(ip)
	a.bans.flush()
	slog.Info("解封", "actor", actor, "ip", ip, "was_active", was)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "was_active": was})
}

// handleHoneypotUpdate 读写蜜罐配置（端口列表、开关、模式、豁免）。
func (a *App) handleHoneypotUpdate(w http.ResponseWriter, r *http.Request) {
	var req honeypotConfig
	if err := readOptionalJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if err := req.normalize(); err != nil {
		writeErr(w, badRequest("bad_honeypot_config", "%v", err))
		return
	}
	st := a.store
	if st == nil {
		writeErr(w, errors.New("配置库不可用"))
		return
	}
	if err := st.writeHoneypot(req); err != nil {
		writeErr(w, err)
		return
	}

	// 落库成功后立刻生效，不等重启。
	//
	// 冲突或绑定失败只作为 problems 报出去，**不整体回滚**：配置已经写进库了，
	// 回滚会让「库里是 A、实际行为是 B」这种最难排查的状态出现。
	// 用户看到 problems 就知道哪个端口没起来，改掉再存一次即可。
	base, _ := loadConfig(a.configDB)
	resp := map[string]any{"ok": true, "config": req}
	if err := a.applyHoneypot(req, base); err != nil {
		resp["problems"] = err.Error()
		slog.Warn("蜜罐端口部分未能生效", "err", err)
	}
	resp["traps"] = a.trap.Stats()

	actor := actorLabel(a.identifyAdminRequest(r, sessionHandleFrom(r)))
	slog.Info("蜜罐配置已更新", "actor", actor, "enabled", req.Enabled,
		"mode", req.Mode, "ports", len(req.Ports))
	writeJSON(w, http.StatusOK, resp)
}

// ---------- 命令行 ----------

// openBansForCLI 打开一个只用于命令行的封禁集合。
//
// 命令行与运行中的服务可能同时在写这张表，但两边都不会跑太久：
// 服务侧是「攒一会儿、一次事务」，命令行是「一条语句」。SQLite 的单写者
// 会串行化它们，冲突时靠 busy timeout 等一小会儿。
func openBansForCLI(configDB string) (*banList, error) {
	st, err := storeFor(configDB)
	if err != nil {
		return nil, err
	}
	b := newBanList(st, time.Now)
	if err := b.load(); err != nil {
		return nil, err
	}
	return b, nil
}

// runBanList 打印当前封禁。服务在不在跑都能用。
func runBanList(configDB string) error {
	b, err := openBansForCLI(configDB)
	if err != nil {
		return err
	}
	entries := b.list()
	if len(entries) == 0 {
		fmt.Println("当前没有任何封禁记录。")
		return nil
	}
	now := time.Now()
	fmt.Printf("%-42s %-8s %-16s %-6s %s\n", "IP", "状态", "原因", "次数", "到期")
	for _, e := range entries {
		state := "已过期"
		left := "（仅保留阶梯记忆）"
		if e.CreatedAt.After(time.Time{}) && now.Before(e.ExpiresAt) {
			state = "生效中"
			left = formatLogTime(e.ExpiresAt) + "（还剩 " + humanDur(e.ExpiresAt.Sub(now)) + "）"
		}
		fmt.Printf("%-42s %-8s %-16s %-6d %s\n", e.IP, state, e.Reason, e.Hits, left)
	}
	fmt.Printf("\n共 %d 条（其中生效 %d 条）。解封：goproxy -c <库> -unban <IP|all>\n",
		len(entries), b.activeCount())
	return nil
}

// runUnban 解封一个地址或清空全部。
func runUnban(configDB, target string) error {
	b, err := openBansForCLI(configDB)
	if err != nil {
		return err
	}
	if target == "all" {
		n := b.clear()
		b.flush()
		fmt.Printf("已清空 %d 条封禁记录。\n", n)
		return nil
	}
	if net.ParseIP(target) == nil {
		return fmt.Errorf("%q 不是一个 IP 地址（要清空全部请写 all）", target)
	}
	was := b.remove(target)
	b.flush()
	if was {
		fmt.Printf("已解封 %s。\n", target)
		return nil
	}
	fmt.Printf("%s 本来就不在生效中的封禁里（记录已删除，如果存在的话）。\n", target)
	return nil
}

// runHoneypotSet 设置蜜罐端口 / 开关 / 模式。
func runHoneypotSet(configDB, spec, mode string, enabled *bool) error {
	st, err := storeFor(configDB)
	if err != nil {
		return err
	}
	cfg, err := st.readHoneypot()
	if err != nil {
		return err
	}
	if spec != "" {
		ports, err := parseHoneypotSpec(spec)
		if err != nil {
			return err
		}
		cfg.Ports = ports
		// 给了端口就等于想用它。
		//
		// 否则「我明明设了端口，怎么什么都没发生」—— 因为蜜罐默认是关的，
		// 而 -honeypot-set 的名字里没有「启用」的意思。要只改端口不启用，
		// 显式带上 -honeypot-mode off。
		//
		// 自动启用只到**观察模式**：悄悄切到 enforce 会让人在不知情的情况下
		// 开始封禁真实来源，那不是命令行工具该做的决定。
		if enabled == nil && !cfg.Enabled {
			cfg.Enabled = true
			cfg.Mode = honeypotModeObserve
		}
	}
	if mode != "" {
		cfg.Mode = mode
	}
	if enabled != nil {
		cfg.Enabled = *enabled
	}
	if err := st.writeHoneypot(cfg); err != nil {
		return err
	}
	fmt.Printf("已保存：enabled=%v mode=%s 端口=%d 个\n", cfg.Enabled, cfg.Mode, len(cfg.Ports))
	for _, p := range cfg.Ports {
		fmt.Printf("  %s\n", p.key())
	}
	if !cfg.Enabled {
		fmt.Println("\n注意：蜜罐当前是关闭的（只存了端口，不会监听）。")
	} else if cfg.Mode == honeypotModeObserve {
		fmt.Println("\n当前是观察模式（observe）：会监听并记录，但一个都不封。")
		fmt.Println("先让它跑一段，用 goproxy -c <库> -bans 看命中，确认没有误报后再切 enforce。")
	}
	fmt.Println("\n重启服务或调一次 POST /_goproxy/reload 让它生效。")
	return nil
}

// parseHoneypotSpec 解析 "23,3389,5900/udp" 这样的端口列表。
// 分隔符取逗号、分号与任意空白（含制表符）—— 从命令行、配置文件、
// 界面上复制过来的写法都要能直接吃进去。
func parseHoneypotSpec(spec string) ([]honeypotPort, error) {
	fields := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ';' || unicode.IsSpace(r)
	})
	out := make([]honeypotPort, 0, len(fields))
	seen := map[string]bool{}
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		proto := "tcp"
		portStr := f
		if i := strings.IndexByte(f, '/'); i >= 0 {
			portStr = strings.TrimSpace(f[:i])
			proto = strings.ToLower(strings.TrimSpace(f[i+1:]))
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("%q 不是一个合法端口（1-65535）", f)
		}
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("%q 的协议只能是 tcp 或 udp", f)
		}
		p := honeypotPort{Port: port, Proto: proto}
		if seen[p.key()] {
			continue
		}
		seen[p.key()] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out, nil
}

// ---------- 小工具 ----------

func humanDur(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%d 天", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%d 小时", int(d.Hours()))
	case d >= time.Minute:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	default:
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	}
}

// banLadderLabels 把阶梯算成人话，给界面直接显示。
func banLadderLabels(baseSecs int) []string {
	out := make([]string, 0, len(banLadderRatios))
	for i := 1; i <= len(banLadderRatios); i++ {
		out = append(out, fmt.Sprintf("第 %d 次 %s", i, humanDur(banDuration(time.Duration(baseSecs)*time.Second, i))))
	}
	return out
}
