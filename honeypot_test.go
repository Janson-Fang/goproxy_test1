package main

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// ---------- 蜜罐端口本身 ----------

// freeTCPPort 要一个当前没人用的 TCP 端口。
// 取到与用上之间有一瞬间的空档，测试里够用（真机上端口是配置写死的）。
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口失败: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲 UDP 端口失败: %v", err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// newTestHoneypot 造一个把命中送进 channel 的蜜罐。
// 用 channel 而不是计数：命中发生在 accept 的 goroutine 里，测试要能等它。
func newTestHoneypot() (*honeypot, chan honeypotProbe) {
	ch := make(chan honeypotProbe, 32)
	h := newHoneypot(func(p honeypotProbe) {
		select {
		case ch <- p:
		default:
		}
	})
	return h, ch
}

func waitProbe(t *testing.T, ch chan honeypotProbe) honeypotProbe {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(3 * time.Second):
		t.Fatal("3 秒内没有收到蜜罐命中上报")
		return honeypotProbe{}
	}
}

func TestHoneypotTCPReportsProbe(t *testing.T) {
	h, ch := newTestHoneypot()
	defer h.Close()

	port := freeTCPPort(t)
	if err := h.Sync([]honeypotPort{{Port: port, Proto: "tcp", Note: "测试"}}, nil); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// 一次成功的 connect 就是这个端口的全部意义：内核替我们回了 SYN-ACK，
	// 扫描器据此判定端口 open，而我们什么都没发。
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 2*time.Second)
	if err != nil {
		t.Fatalf("拨号失败（说明蜜罐没在监听）: %v", err)
	}
	_ = conn.Close()

	p := waitProbe(t, ch)
	if p.Port != port || p.Proto != "tcp" {
		t.Errorf("命中信息不对：%+v", p)
	}
	if p.IP != "127.0.0.1" {
		t.Errorf("来源地址应当是直连对端，实际 %q", p.IP)
	}
	if p.Head != "" {
		t.Errorf("客户端什么都没发，样本应当是空的，实际 %q", p.Head)
	}

	// 统计要跟上
	stats := h.Stats()
	if len(stats) != 1 || stats[0].Hits != 1 || stats[0].Distinct != 1 {
		t.Errorf("端口统计不对：%+v", stats)
	}
	if !stats[0].Listening {
		t.Error("统计应当报告这个端口正在监听")
	}
}

func TestHoneypotTCPCapturesFirstBytes(t *testing.T) {
	h, ch := newTestHoneypot()
	defer h.Close()

	port := freeTCPPort(t)
	if err := h.Sync([]honeypotPort{{Port: port, Proto: "tcp"}}, nil); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 2*time.Second)
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	if _, err := conn.Write([]byte("GET /admin HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	_ = conn.Close()

	p := waitProbe(t, ch)
	if p.Head == "" {
		t.Error("应当采集到对方发的头几个字节（它是更有价值的证据）")
	}
	// 换行要被压成空格，方便进日志与界面
	for _, c := range p.Head {
		if c == '\r' || c == '\n' {
			t.Errorf("样本里不该有换行：%q", p.Head)
			break
		}
	}
}

func TestHoneypotUDPReportsProbeAndNeverReplies(t *testing.T) {
	h, ch := newTestHoneypot()
	defer h.Close()

	port := freeUDPPort(t)
	if err := h.Sync([]honeypotPort{{Port: port, Proto: "udp"}}, nil); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	conn, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("\x00\x01probe")); err != nil {
		t.Fatalf("发送失败: %v", err)
	}

	p := waitProbe(t, ch)
	if p.Proto != "udp" || p.Port != port {
		t.Errorf("UDP 命中信息不对：%+v", p)
	}

	// 绝不回包：UDP 源地址可伪造，回包就是替攻击者打受害者。
	// 这条断言是「我们不会成为反射放大器」的可验证形式。
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 64)
	if n, err := conn.Read(buf); err == nil {
		t.Errorf("蜜罐绝不能回 UDP 包，却收到了 %d 字节：%q", n, buf[:n])
	}
}

func TestHoneypotSyncIsIdempotentAndRemoves(t *testing.T) {
	h, _ := newTestHoneypot()
	defer h.Close()

	p1, p2 := freeTCPPort(t), freeTCPPort(t)
	if err := h.Sync([]honeypotPort{{Port: p1}, {Port: p2}}, nil); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	// 重复 Sync 同样的集合不该报错、也不该重复监听（重复监听会 bind 失败）
	if err := h.Sync([]honeypotPort{{Port: p1}, {Port: p2}}, nil); err != nil {
		t.Fatalf("重复 Sync 应当幂等，实际 %v", err)
	}

	// 去掉 p2
	if err := h.Sync([]honeypotPort{{Port: p1}}, nil); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p2), 300*time.Millisecond); err == nil {
		t.Error("移出列表的端口应当停止监听（否则蜜罐会一直占着它）")
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p1), 2*time.Second); err != nil {
		t.Errorf("保留的端口应当还在监听: %v", err)
	}
}

func TestHoneypotRejectsConflictingPort(t *testing.T) {
	h, _ := newTestHoneypot()
	defer h.Close()

	port := freeTCPPort(t)
	// 冲突回调是注入的：App 用它挡住「蜜罐抢走真实路由端口 / 管理端口」。
	conflict := func(p honeypotPort) string {
		if p.Port == port {
			return "已经有一条路由要监听这个端口"
		}
		return ""
	}
	err := h.Sync([]honeypotPort{{Port: port}}, conflict)
	if err == nil {
		t.Fatal("端口冲突必须报错（fail-closed），不能硬绑")
	}
	if len(h.Stats()) != 0 {
		t.Errorf("冲突的端口不该被监听：%+v", h.Stats())
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 300*time.Millisecond); err == nil {
		t.Error("冲突端口上不该有监听")
	}
}

func TestHoneypotBindFailureIsNotFatal(t *testing.T) {
	// 先自己占住一个端口，模拟「这个端口上有别人的服务」
	taken, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("占位监听失败: %v", err)
	}
	defer taken.Close()
	takenPort := taken.Addr().(*net.TCPAddr).Port

	h, ch := newTestHoneypot()
	defer h.Close()
	good := freeTCPPort(t)

	err = h.Sync([]honeypotPort{{Port: takenPort}, {Port: good}}, nil)
	if err == nil {
		t.Error("绑定失败应当被报出来")
	}
	// 但好端口必须照常工作 —— 单个端口失败不该让整次同步失败
	conn, derr := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(good), 2*time.Second)
	if derr != nil {
		t.Fatalf("另一个端口应当照常监听: %v", derr)
	}
	_ = conn.Close()
	waitProbe(t, ch)

	// 失败原因要留在统计里，控制台才说得清「为什么这个端口没在跑」
	var found bool
	for _, s := range h.Stats() {
		if s.Port == takenPort && s.Error != "" && !s.Listening {
			found = true
		}
	}
	if !found {
		t.Errorf("绑定失败的端口应当在统计里带出原因：%+v", h.Stats())
	}
}

func TestHoneypotClosesCleanlyEvenIfClientSentALot(t *testing.T) {
	h, ch := newTestHoneypot()
	defer h.Close()

	port := freeTCPPort(t)
	if err := h.Sync([]honeypotPort{{Port: port, Proto: "tcp"}}, nil); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// 发一大段（远超我们留作样本的 64 字节，也超过一次 read 的量）。
	// 这条用例守的是「诱饵必须看起来像端口开着」：
	//   - 如果关连接时输入缓冲区里还有没读走的数据，内核会发 RST；
	//   - 客户端（实测 Windows）会在 connect() 或首次 read 时报
	//     「连接被重置」，扫描器据此把端口判成 closed/filtered —— 诱饵失效。
	// 正确行为是：对方读到的是**干净的 EOF**（FIN），不是 RST。
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 2*time.Second)
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	p := waitProbe(t, ch)
	if p.Head == "" {
		t.Error("应当采集到样本")
	}

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("设置读超时失败: %v", err)
	}
	buf := make([]byte, 64)
	for {
		n, rerr := conn.Read(buf)
		if n > 0 {
			continue
		}
		if rerr == nil {
			continue
		}
		if rerr == io.EOF {
			break // 干净的 FIN：正是我们要的
		}
		t.Fatalf("读到的应当是干净的 EOF，而不是 %v —— "+
			"这说明关连接时发了 RST，扫描器会把端口判成没开、诱饵失效", rerr)
	}
}

func TestHoneypotRejectsBadPortSpec(t *testing.T) {
	h, _ := newTestHoneypot()
	defer h.Close()
	if err := h.Sync([]honeypotPort{{Port: 0}}, nil); err == nil {
		t.Error("端口 0 应当被拒绝")
	}
	if err := h.Sync([]honeypotPort{{Port: 70000}}, nil); err == nil {
		t.Error("越界端口应当被拒绝")
	}
	if err := h.Sync([]honeypotPort{{Port: 1234, Proto: "sctp"}}, nil); err == nil {
		t.Error("未知协议应当被拒绝")
	}
}

// ---------- 与 App 的接线 ----------

func TestAppHoneypotEnforceBansPublicSource(t *testing.T) {
	db := tempConfigDB(t)
	seedRawConfig(t, db, []byte(`{"admin_addr":"127.0.0.1:19180"}`))
	app, err := NewApp(db)
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	t.Cleanup(func() { app.bans.Close(); app.trap.Close() })

	base, err := loadConfig(db)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	// 端口留空：这里验的是「命中之后封不封」，不需要真的开监听
	cfg := honeypotConfig{Enabled: true, Mode: honeypotModeEnforce, BanSecs: 3600}
	if err := app.applyHoneypot(cfg, base); err != nil {
		t.Fatalf("applyHoneypot: %v", err)
	}

	app.onTrapProbe(honeypotProbe{
		Time: time.Now(), IP: pubIP1, Port: 3389, Proto: "tcp", Head: "(connect)",
	})

	e, ok := app.bans.lookup(pubIP1)
	if !ok {
		t.Fatal("enforce 模式下，蜜罐命中应当立刻封禁该来源")
	}
	if e.Reason != "tcp/3389" || e.Source != banSourceHoneypot {
		t.Errorf("封禁原因不对：%+v", e)
	}
}

func TestAppHoneypotObserveModeDoesNotBan(t *testing.T) {
	db := tempConfigDB(t)
	seedRawConfig(t, db, []byte(`{"admin_addr":"127.0.0.1:19180"}`))
	app, err := NewApp(db)
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	t.Cleanup(func() { app.bans.Close(); app.trap.Close() })

	base, _ := loadConfig(db)
	cfg := honeypotConfig{Enabled: true, Mode: honeypotModeObserve}
	if err := app.applyHoneypot(cfg, base); err != nil {
		t.Fatalf("applyHoneypot: %v", err)
	}

	app.onTrapProbe(honeypotProbe{Time: time.Now(), IP: pubIP1, Port: 23, Proto: "tcp"})
	if _, ok := app.bans.lookup(pubIP1); ok {
		t.Error("观察模式下一个都不该封 —— 它是用来先看真实流量的")
	}
	if app.trapObserved.Load() == 0 {
		t.Error("观察模式仍应记下命中次数，否则「如果开启会封谁」就答不出来")
	}
}

func TestAppHoneypotDisabledIgnoresProbes(t *testing.T) {
	db := tempConfigDB(t)
	seedRawConfig(t, db, []byte(`{"admin_addr":"127.0.0.1:19180"}`))
	app, err := NewApp(db)
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	t.Cleanup(func() { app.bans.Close(); app.trap.Close() })

	// 连 applyHoneypot 都不调：默认就是关闭状态
	app.onTrapProbe(honeypotProbe{Time: time.Now(), IP: pubIP1, Port: 3389, Proto: "tcp"})
	if n := app.bans.activeCount(); n != 0 {
		t.Errorf("功能没开时不该有任何封禁，实际 %d", n)
	}
}

func TestAppBanExemptCoversLocalNets(t *testing.T) {
	db := tempConfigDB(t)
	seedRawConfig(t, db, []byte(`{
		"admin_addr": "127.0.0.1:19180",
		"ip_lists": [{"name":"office","kind":"allow","rules":[{"cidr":"10.0.0.0/8"}]}],
		"routes": [{"id":"r1","listen_port":18081,"path_prefix":"/","target":"http://127.0.0.1:19001",
		            "acl":{"lists":["office"]}}]
	}`))
	app, err := NewApp(db)
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	t.Cleanup(func() { app.bans.Close(); app.trap.Close() })

	// banExempt 要读路由表（白名单那一关），所以先把表建起来。
	//
	// 用 buildTable 而不是 reload：reload 会真的去监听端口，而这里要验的
	// 只是「判定」—— 让测试去占端口只会带来偶发的端口冲突。
	cfg, err := loadConfig(db)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	tbl, err := buildTable(cfg, nil, app.transport)
	if err != nil {
		t.Fatalf("buildTable: %v", err)
	}
	app.table.Store(tbl)

	cases := []struct {
		ip     string
		exempt bool
		why    string
	}{
		{"127.0.0.1", true, "回环"},
		{"10.1.2.3", true, "私网 + 白名单"},
		{"192.168.1.5", true, "私网"},
		{pubIP1, false, "公网地址，没在任何豁免里 —— 该封就得封"},
	}
	for _, c := range cases {
		got, why := app.banExempt(net.ParseIP(c.ip))
		if got != c.exempt {
			t.Errorf("%s（%s）：豁免=%v，期望 %v（原因：%s）", c.ip, c.why, got, c.exempt, why)
		}
	}
}

func TestAppConsoleSourceIsExempt(t *testing.T) {
	db := tempConfigDB(t)
	seedRawConfig(t, db, []byte(`{"admin_addr":"127.0.0.1:19180"}`))
	app, err := NewApp(db)
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	t.Cleanup(func() { app.bans.Close(); app.trap.Close() })

	if got, _ := app.banExempt(net.ParseIP(pubIP1)); got {
		t.Fatal("公网地址本来不该被豁免")
	}
	// 记一笔「这个地址正在用控制台」之后，它就豁免了
	app.consoleSeen.remember(pubIP1)
	if got, why := app.banExempt(net.ParseIP(pubIP1)); !got {
		t.Errorf("用过控制台的来源必须豁免，否则会把自己锁在门外（原因：%s）", why)
	}
}
