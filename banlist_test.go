package main

import (
	"database/sql"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeClock 是可推进的时钟。阶梯与过期全靠时间，而它们又是这个模块的核心，
// 所以必须能把时间往前拨（与 sessionStore.now 同一个思路）。
type fakeClock struct{ t time.Time }

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// 测试里用的「公网地址」。刻意避开 192.0.2/198.51.100/203.0.113 那三段：
// 它们是文档保留段，在 isLocalNet 里被豁免了（见 localNets 的说明）。
const (
	pubIP1 = "93.184.216.34"
	pubIP2 = "45.33.32.156"
)

func TestIsLocalNetExemptsWhatItShould(t *testing.T) {
	local := []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.0.9", "192.168.1.1",
		"169.254.1.1", "100.64.0.1", "0.0.0.0", "fc00::1", "fe80::1",
		"224.0.0.1", "192.0.2.5", "198.51.100.7", "203.0.113.9",
	}
	for _, s := range local {
		if !isLocalNet(net.ParseIP(s)) {
			t.Errorf("%s 应当被当作本地/保留地址（自动封禁不管它）", s)
		}
	}
	global := []string{pubIP1, pubIP2, "8.8.8.8", "2001:4860:4860::8888", "1.1.1.1"}
	for _, s := range global {
		if isLocalNet(net.ParseIP(s)) {
			t.Errorf("%s 是公网地址，不该被豁免", s)
		}
	}
	if !isLocalNet(nil) {
		t.Error("解析不出来的地址必须按「不封」处理，这是 fail-closed 的反面：封了就无法解封")
	}
}

func TestBanLadderEscalatesAfterExpiry(t *testing.T) {
	clk := newFakeClock()
	b := newBanList(nil, clk.now)
	if b.base != time.Hour {
		t.Fatalf("默认基准时长应当是 1 小时，实际 %v", b.base)
	}

	// 第 1 次：1 小时
	e1, ok := b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "connect")
	if !ok || e1.Level != 1 {
		t.Fatalf("首次封禁应当是第 1 级，得到 %+v", e1)
	}
	if got := e1.ExpiresAt.Sub(e1.CreatedAt); got != time.Hour {
		t.Errorf("第 1 级时长应为 1 小时，实际 %v", got)
	}

	// 生效期内重复命中：只累计，不升级、不续期
	before := e1.ExpiresAt
	e2, _ := b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "connect")
	if e2.Level != 1 || e2.Hits != 2 {
		t.Errorf("生效期内重复命中不该升级，实际 %+v", e2)
	}
	if !e2.ExpiresAt.Equal(before) {
		t.Errorf("生效期内重复命中不该续期：%v -> %v", before, e2.ExpiresAt)
	}

	// 到期后重来：升一级（6 小时）
	clk.advance(time.Hour + time.Minute)
	if _, ok := b.lookup(pubIP1); ok {
		t.Fatal("过期后快照里不该还有它")
	}
	e3, _ := b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "connect")
	if e3.Level != 2 {
		t.Errorf("到期后再来应当升到第 2 级，实际 %+v", e3)
	}
	if got := e3.ExpiresAt.Sub(e3.CreatedAt); got != 6*time.Hour {
		t.Errorf("第 2 级时长应为 6 小时，实际 %v", got)
	}

	// 一路升到上限（7 天），不再增长
	clk.advance(48 * time.Hour)
	e4, _ := b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "connect")
	clk.advance(8 * 24 * time.Hour)
	e5, _ := b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "connect")
	if got := e5.ExpiresAt.Sub(e5.CreatedAt); got > 8*24*time.Hour {
		t.Errorf("阶梯必须有上限（自动封禁不该变成永久封禁），实际 %v（%+v / %+v）", got, e4, e5)
	}
}

func TestBanForgetsLevelAfterKeepWindow(t *testing.T) {
	clk := newFakeClock()
	b := newBanList(nil, clk.now)
	b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "connect")

	// 过了记忆窗口（7 天）再来，按第一次处理 —— 否则一个很久以前的事件
	// 会让今天的封禁直接跳到很高级别。
	clk.advance(banRowKeep + time.Hour)
	e, _ := b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "connect")
	if e.Level != 1 {
		t.Errorf("记忆窗口外应当按第 1 次处理，实际 %+v", e)
	}
}

func TestBanSweepDropsStaleEntries(t *testing.T) {
	clk := newFakeClock()
	b := newBanList(nil, clk.now)
	b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "connect")
	b.add(pubIP2, "honeypot/tcp/23", banSourceHoneypot, "connect")

	clk.advance(2 * time.Hour) // 都过期了，但还在记忆窗口内
	b.sweep()
	if n := b.activeCount(); n != 0 {
		t.Errorf("过期后生效数应为 0，实际 %d", n)
	}
	if n := len(b.list()); n != 2 {
		t.Errorf("过期但仍在记忆窗口内的记录应当保留（阶梯要用），实际 %d", n)
	}

	clk.advance(banRowKeep + time.Hour)
	b.sweep()
	if n := len(b.list()); n != 0 {
		t.Errorf("过了记忆窗口应当被遗忘，实际还剩 %d 条", n)
	}
}

func TestBanManualBypassesExemption(t *testing.T) {
	clk := newFakeClock()
	b := newBanList(nil, clk.now)
	// 豁免一切 —— 模拟「这个地址在白名单/内网/可信代理里」
	b.SetExempt(func(net.IP) (bool, string) { return true, "测试用：全部豁免" })

	if _, ok := b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "connect"); ok {
		t.Error("自动封禁必须尊重豁免")
	}
	// 人工封禁不看豁免：那是人明确做出的决定（同 guardSelfLockout 的取舍）
	if _, ok := b.addManual(pubIP1, "手动封禁测试", time.Hour); !ok {
		t.Error("人工封禁不该被豁免规则挡住")
	}
	if _, ok := b.lookup(pubIP1); !ok {
		t.Error("人工封禁应当立刻生效")
	}
}

func TestBanBurstPausesAutomaticBanning(t *testing.T) {
	clk := newFakeClock()
	b := newBanList(nil, clk.now)

	added := 0
	for i := 0; i < banBurstLimit+50; i++ {
		ip := fmt.Sprintf("8.8.%d.%d", i/256, i%256)
		if _, ok := b.add(ip, "honeypot/tcp/3389", banSourceHoneypot, "connect"); ok {
			added++
		}
	}
	if added != banBurstLimit {
		t.Errorf("突发熔断应当在 %d 条后停下，实际封了 %d 条", banBurstLimit, added)
	}

	// 人工封禁不受熔断限制 —— 熔断保护的是「别被自动判据撑爆」，
	// 不是「不许人处置」。
	if _, ok := b.addManual(pubIP2, "手动", time.Hour); !ok {
		t.Error("熔断期间人工封禁仍应生效")
	}
}

func TestBanSampleIsSanitized(t *testing.T) {
	clk := newFakeClock()
	b := newBanList(nil, clk.now)
	// 样本来自网络字节，要进内存、进库、最后进浏览器
	dirty := "GET /\x00\x07 HTTP/1.0\r\nHost: x\r\n" + strings.Repeat("A", 500)
	e, _ := b.add(pubIP1, "honeypot/tcp/8080", banSourceHoneypot, dirty)
	if len(e.Samples) != 1 {
		t.Fatalf("应当留一条样本，实际 %v", e.Samples)
	}
	s := e.Samples[0]
	if strings.ContainsAny(s, "\x00\x07\r\n") {
		t.Errorf("控制字符必须被清掉，实际 %q", s)
	}
	if len(s) > 130 {
		t.Errorf("样本必须被截断，实际长度 %d", len(s))
	}
}

func TestBanSamplesAreDedupedAndCapped(t *testing.T) {
	clk := newFakeClock()
	b := newBanList(nil, clk.now)
	b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "A")
	b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "A")
	e, _ := b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "A")
	if len(e.Samples) != 1 {
		t.Errorf("重复样本不该堆叠，实际 %v", e.Samples)
	}
	for i := 0; i < 20; i++ {
		b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, fmt.Sprintf("样本 %d", i))
	}
	e, _ = b.lookup(pubIP1)
	if len(e.Samples) > banSampleKeep {
		t.Errorf("样本条数应当有上限 %d，实际 %d", banSampleKeep, len(e.Samples))
	}
}

// ---------- 持久化与外部同步 ----------

func newBanStore(t *testing.T) *configStore {
	t.Helper()
	db := tempConfigDB(t)
	seedRawConfig(t, db, []byte(`{"admin_addr":"127.0.0.1:19180"}`))
	st, err := storeFor(db)
	if err != nil {
		t.Fatalf("打开配置库失败: %v", err)
	}
	return st
}

func TestBanPersistsAndReloads(t *testing.T) {
	st := newBanStore(t)
	clk := newFakeClock()

	b := newBanList(st, clk.now)
	b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "connect")
	b.flush()

	// 新进程：同一个库，新对象
	b2 := newBanList(st, clk.now)
	if err := b2.load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	e, ok := b2.lookup(pubIP1)
	if !ok {
		t.Fatal("重启后封禁应当仍在 —— 否则打崩进程就等于免费解封")
	}
	if e.Reason != "honeypot/tcp/3389" || e.Level != 1 {
		t.Errorf("恢复出来的内容不对：%+v", e)
	}
}

func TestBanExternallyRemovedConverges(t *testing.T) {
	st := newBanStore(t)
	clk := newFakeClock()
	b := newBanList(st, clk.now)
	b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "connect")
	b.flush()

	// 模拟「服务运行期间，另一个进程（命令行 -unban）删掉了这条」
	if err := st.withTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM ban_entries WHERE ip = ?`, pubIP1)
		return err
	}); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if _, ok := b.lookup(pubIP1); !ok {
		t.Fatal("重读之前，内存里应当还在封着")
	}

	if err := b.resync(); err != nil {
		t.Fatalf("resync: %v", err)
	}
	if _, ok := b.lookup(pubIP1); ok {
		t.Error("resync 之后应当承认外部解封 —— 否则命令行解封在服务运行时是无效的")
	}
}

func TestBanExternallyAddedIsPickedUp(t *testing.T) {
	st := newBanStore(t)
	clk := newFakeClock()
	b := newBanList(st, clk.now)

	// 模拟「命令行封了一个人」
	other := newBanList(st, time.Now)
	other.addManual(pubIP2, "命令行封禁", time.Hour)
	other.flush()

	if _, ok := b.lookup(pubIP2); ok {
		t.Fatal("重读之前不该看见")
	}
	if err := b.resync(); err != nil {
		t.Fatalf("resync: %v", err)
	}
	if e, ok := b.lookup(pubIP2); !ok || e.Source != banSourceManual {
		t.Errorf("应当载入外部写入的封禁，实际 %+v ok=%v", e, ok)
	}
}

func TestBanUnflushedEntrySurvivesResync(t *testing.T) {
	st := newBanStore(t)
	clk := newFakeClock()
	b := newBanList(st, clk.now)

	// 刚封的、还没落盘：resync 不能拿「库里没有」把它当成「被外部删了」
	b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "connect")
	if err := b.resync(); err != nil {
		t.Fatalf("resync: %v", err)
	}
	if _, ok := b.lookup(pubIP1); !ok {
		t.Error("还没落盘的封禁必须留住 —— 否则刚封完的一次重读就会把它抹掉")
	}
}

func TestBanRemoveAndClear(t *testing.T) {
	clk := newFakeClock()
	b := newBanList(nil, clk.now)
	b.add(pubIP1, "honeypot/tcp/3389", banSourceHoneypot, "connect")
	b.add(pubIP2, "honeypot/tcp/23", banSourceHoneypot, "connect")

	if !b.remove(pubIP1) {
		t.Error("remove 应当报告「删掉的是一条生效中的」")
	}
	if _, ok := b.lookup(pubIP1); ok {
		t.Error("解封后不该还能查到")
	}
	if n := b.clear(); n != 1 {
		t.Errorf("清空应当返回剩余的 1 条，实际 %d", n)
	}
	if n := b.activeCount(); n != 0 {
		t.Errorf("清空后生效数应为 0，实际 %d", n)
	}
}

// ---------- 配置校验 ----------

func TestHoneypotConfigNormalize(t *testing.T) {
	cases := []struct {
		name string
		in   honeypotConfig
		ok   bool
	}{
		{"默认值补齐", honeypotConfig{}, true},
		{"合法", honeypotConfig{Mode: "enforce", BanSecs: 600, Exempt: []string{"203.0.113.0/24"}}, true},
		{"单个 IP 也接受", honeypotConfig{Exempt: []string{"1.2.3.4"}}, true},
		{"模式不认识", honeypotConfig{Mode: "半开"}, false},
		{"时长太短", honeypotConfig{BanSecs: 1}, false},
		{"时长太长", honeypotConfig{BanSecs: honeypotMaxBanSecs + 1}, false},
		{"豁免写错", honeypotConfig{Exempt: []string{"不是网段"}}, false},
		{"端口越界", honeypotConfig{Ports: []honeypotPort{{Port: 70000}}}, false},
		{"协议写错", honeypotConfig{Ports: []honeypotPort{{Port: 23, Proto: "sctp"}}}, false},
	}
	for _, c := range cases {
		err := c.in.normalize()
		if c.ok && err != nil {
			t.Errorf("%s：应当通过，实际 %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s：应当失败（fail-closed，不静默纠正）", c.name)
		}
	}
}

func TestParseHoneypotSpec(t *testing.T) {
	got, err := parseHoneypotSpec("23, 3389, 5900/udp\t8080")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("应当解析出 4 个端口，实际 %v", got)
	}
	// 排序后第一个是 23
	if got[0].Port != 23 || got[0].Proto != "tcp" {
		t.Errorf("默认协议应当是 tcp：%+v", got[0])
	}
	var udp *honeypotPort
	for i := range got {
		if got[i].Port == 5900 {
			udp = &got[i]
		}
	}
	if udp == nil || udp.Proto != "udp" {
		t.Errorf("5900/udp 应当被解析成 UDP：%+v", got)
	}

	if _, err := parseHoneypotSpec("23,abc"); err == nil {
		t.Error("非法端口应当报错")
	}
	if _, err := parseHoneypotSpec("23/sctp"); err == nil {
		t.Error("非法协议应当报错")
	}
	// 重复项去重而不是报错
	dup, err := parseHoneypotSpec("23,23,23")
	if err != nil || len(dup) != 1 {
		t.Errorf("重复端口应当去重，实际 %v err=%v", dup, err)
	}
}
