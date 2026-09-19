package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------- 熔断 ----------

func TestCircuitBreakerTripsOnErrorRate(t *testing.T) {
	cb := NewCircuitBreaker(CBConfig{ErrorRate: 0.5, MinCalls: 10, OpenSecs: 30, HalfOpenCalls: 3})

	// MinCalls=10：前 10 次放行，第 10 次 Record 后错误率 100% 触发跳闸
	for i := 0; i < 10; i++ {
		if !cb.Allow() {
			t.Fatalf("第 %d 次调用不应被拒绝（还没到 MinCalls）", i+1)
		}
		cb.Record(true)
	}

	if cb.State() != cbOpen {
		t.Fatalf("错误率 100%% 且调用数达标，应处于 open，实际 %s", cb.State())
	}
	if cb.Allow() {
		t.Error("open 状态下应拒绝请求（快速失败）")
	}
	if cb.openedTotal.Load() != 1 {
		t.Errorf("跳闸次数应为 1，实际 %d", cb.openedTotal.Load())
	}
}

func TestCircuitBreakerNotTripBelowMinCalls(t *testing.T) {
	// MinCalls=100，只打 5 次失败不足以跳闸，避免刚启动就被零星错误打挂
	cb := NewCircuitBreaker(CBConfig{ErrorRate: 0.5, MinCalls: 100})
	for i := 0; i < 5; i++ {
		cb.Allow()
		cb.Record(true)
	}
	if cb.State() != cbClosed {
		t.Errorf("调用数不足时不应跳闸，实际状态 %s", cb.State())
	}
}

func TestCircuitBreakerNotTripBelowErrorRate(t *testing.T) {
	cb := NewCircuitBreaker(CBConfig{ErrorRate: 0.5, MinCalls: 10})
	// 10 次里只错 2 次（20%），低于 50% 阈值
	for i := 0; i < 10; i++ {
		cb.Allow()
		cb.Record(i < 2)
	}
	if cb.State() != cbClosed {
		t.Errorf("错误率 20%% 未达阈值，不应跳闸，实际 %s", cb.State())
	}
}

func TestCircuitBreakerHalfOpenRecovery(t *testing.T) {
	// OpenSecs=1 缩短测试耗时
	cb := NewCircuitBreaker(CBConfig{ErrorRate: 0.5, MinCalls: 5, OpenSecs: 1, HalfOpenCalls: 2})

	for i := 0; i < 5; i++ {
		cb.Allow()
		cb.Record(true)
	}
	if cb.State() != cbOpen {
		t.Fatalf("前置条件失败：应处于 open，实际 %s", cb.State())
	}

	time.Sleep(1100 * time.Millisecond)

	if !cb.Allow() {
		t.Fatal("冷却结束后应放行探测请求并进入 half-open")
	}
	if cb.State() != cbHalfOpen {
		t.Fatalf("应处于 half_open，实际 %s", cb.State())
	}

	// 探测全部成功 → 恢复 closed
	cb.Record(false)
	cb.Record(false)
	if cb.State() != cbClosed {
		t.Errorf("探测成功后应恢复 closed，实际 %s", cb.State())
	}
}

func TestCircuitBreakerHalfOpenFailsBackToOpen(t *testing.T) {
	cb := NewCircuitBreaker(CBConfig{ErrorRate: 0.5, MinCalls: 5, OpenSecs: 1, HalfOpenCalls: 2})
	for i := 0; i < 5; i++ {
		cb.Allow()
		cb.Record(true)
	}
	time.Sleep(1100 * time.Millisecond)
	cb.Allow()
	cb.Record(true) // 探测失败
	if cb.State() != cbOpen {
		t.Errorf("half-open 探测失败应回到 open，实际 %s", cb.State())
	}
}

func TestIsBackendFailure(t *testing.T) {
	cases := []struct {
		code int
		want bool
	}{
		{200, false},
		{404, false}, // 客户端错误不怪后端
		{429, false}, // 限流不算后端故障，否则会误触发熔断
		{500, true},
		{503, true},
		{0, true}, // 连不上后端
	}
	for _, c := range cases {
		if got := isBackendFailure(c.code); got != c.want {
			t.Errorf("code=%d 期望 %v，实际 %v", c.code, c.want, got)
		}
	}
}

// ---------- IP 名单（全局黑名单 / 白名单 / 黑名单 三层） ----------

// mustList 建一份名单，省掉测试里到处判 err。
func mustList(t *testing.T, rules ...string) *IPList {
	t.Helper()
	rs := make([]IPRule, 0, len(rules))
	for _, r := range rules {
		rs = append(rs, IPRule{CIDR: r})
	}
	l, err := NewIPList(rs)
	if err != nil {
		t.Fatalf("构建名单失败: %v", err)
	}
	return l
}

// mustACL 建一份路由级名单。
//
// v0.8.0 起路由不再内联写规则，只引用命名名单，所以这里按「建名单 + 引用」
// 两步走，和线上路径完全一致 —— 测试里另走一条捷径的话，捷径本身就成了
// 没被测过的代码。allow / deny 传 nil 表示「这一层不引用任何名单」。
func mustACL(t *testing.T, allow, deny []string) *ACL {
	t.Helper()
	var defs []IPListDef
	var refs []string
	add := func(kind, name string, rules []string) {
		if rules == nil {
			return
		}
		rs := make([]IPRule, 0, len(rules))
		for _, s := range rules {
			rs = append(rs, IPRule{CIDR: s})
		}
		defs = append(defs, IPListDef{Name: name, Kind: kind, Rules: rs})
		refs = append(refs, name)
	}
	add(IPListKindAllow, "allow-1", allow)
	add(IPListKindDeny, "deny-1", deny)

	set, err := NewIPListSet(defs)
	if err != nil {
		t.Fatalf("构建名单库失败: %v", err)
	}
	a, err := set.Resolve(refs)
	if err != nil {
		t.Fatalf("展开名单引用失败: %v", err)
	}
	return a
}

// TestACLThreeLayerOrder 是这次改动的核心断言：三层名单的判定顺序。
//
// 顺序本身就是规格 —— 改它等于改线上行为。所以这里用一个覆盖全部分支的表
// 把它钉死：将来谁调整了 decideIP 的顺序，这个测试会立刻变红。
func TestACLThreeLayerOrder(t *testing.T) {
	global := mustList(t, "203.0.113.0/24")
	route := mustACL(t,
		[]string{"10.0.0.0/8", "203.0.113.66"}, // 白名单
		[]string{"10.0.0.66"})                  // 黑名单

	cases := []struct {
		ip      string
		allowed bool
		layer   string
		reason  string
		why     string
	}{
		{"10.1.2.3", true, "", "",
			"白名单内，两份黑名单都没命中"},
		{"10.0.0.66", false, layerDeny, reasonACLRouteDeny,
			"白名单里的例外被路由黑名单追加禁掉"},
		{"203.0.113.66", false, layerGlobalDeny, reasonACLGlobalDeny,
			"同时命中全局黑名单和白名单 —— 全局优先，白名单救不回来"},
		{"192.168.1.9", false, layerAllow, reasonACLAllowMiss,
			"白名单已启用但不在名单内"},
		{"203.0.113.7", false, layerGlobalDeny, reasonACLGlobalDeny,
			"全局黑名单命中，连白名单那一层都不用看"},
	}
	for _, c := range cases {
		got := decideIP(global, route, c.ip, false)
		if got.Allowed != c.allowed || got.Layer != c.layer || got.Reason != c.reason {
			t.Errorf("ip=%s（%s）:\n  期望 allowed=%v layer=%q reason=%q\n  实际 allowed=%v layer=%q reason=%q",
				c.ip, c.why, c.allowed, c.layer, c.reason, got.Allowed, got.Layer, got.Reason)
		}
	}
}

// TestACLGlobalDenyIsNotExemptable 单独钉住「全局黑名单不可被白名单豁免」。
//
// 这是三层模型里唯一带着强烈取舍的规则。代价是「想给某个被封的地址开口子，
// 必须先去全局名单里删掉它」；换来的是「封禁一定生效」—— 紧急处置攻击源时
// 最需要的性质。如果有人把它改成「白名单可以豁免」，这个测试会红。
func TestACLGlobalDenyIsNotExemptable(t *testing.T) {
	global := mustList(t, "1.2.3.4")
	// 白名单里**明确写了**同一个 IP，也不能把它捞回来
	route := mustACL(t, []string{"1.2.3.4"}, nil)

	got := decideIP(global, route, "1.2.3.4", false)
	if got.Allowed {
		t.Fatal("全局黑名单必须优先于白名单：白名单里写了同一个 IP 也不能放行")
	}
	if got.Layer != layerGlobalDeny {
		t.Errorf("应当由全局黑名单拦下，实际层名 %q", got.Layer)
	}
	if got.Rule != "1.2.3.4" {
		t.Errorf("应当报告命中的具体规则，实际 %q", got.Rule)
	}
}

// TestACLNotConfiguredMeansUnrestricted 守住「没配 ≠ 空白」。
//
// 这两种状态在 JSON 里只差一个字符，语义却相反，是这套模型里最容易写错的地方。
func TestACLNotConfiguredMeansUnrestricted(t *testing.T) {
	// 整个 ACL 为 nil，和两侧名单都没配，都表示不做 IP 限制
	for _, acl := range []*ACL{nil, mustACL(t, nil, nil)} {
		if got := decideIP(nil, acl, "8.8.8.8", false); !got.Allowed {
			t.Errorf("没配任何名单时不应拦请求，实际被 %q 拦下", got.Layer)
		}
	}

	// 只配黑名单：名单外放行，名单内拒绝
	only := mustACL(t, nil, []string{"8.8.8.8"})
	if !decideIP(nil, only, "1.1.1.1", false).Allowed {
		t.Error("只配黑名单时，名单外的地址应放行")
	}
	if decideIP(nil, only, "8.8.8.8", false).Allowed {
		t.Error("黑名单内的地址应被拒绝")
	}
}

// TestACLAllowOnly 覆盖只配白名单的情形（对应 v0.6.x 的 mode=allow）。
func TestACLAllowOnly(t *testing.T) {
	a := mustACL(t, []string{"10.0.0.0/8", "192.168.1.5"}, nil)
	cases := map[string]bool{
		"10.1.2.3":    true,
		"192.168.1.5": true, // 单个 IP 的简写形式
		"192.168.1.6": false,
		"8.8.8.8":     false,
		"172.16.0.1":  false,
	}
	for ip, want := range cases {
		if got := decideIP(nil, a, ip, false).Allowed; got != want {
			t.Errorf("白名单模式 ip=%s 期望 %v，实际 %v", ip, want, got)
		}
	}
}

// TestACLUnknownIPFailsClosedForAllow：解析不出客户端 IP 时，
// 只要配了白名单就必须按「不在名单内」处理。
//
// 反过来的 fail-open 会把「拿不到来源」变成绕过白名单的手段。
func TestACLUnknownIPFailsClosedForAllow(t *testing.T) {
	if decideIP(nil, mustACL(t, []string{"10.0.0.0/8"}, nil), "", false).Allowed {
		t.Error("解析不出 IP 时，配了白名单就必须拒绝，不能放行")
	}
	// 没有白名单可比对时，取不到来源不至于要拒绝
	if !decideIP(nil, mustACL(t, nil, []string{"10.0.0.0/8"}), "", false).Allowed {
		t.Error("只配黑名单且解析不出 IP 时，不应拒绝")
	}
}

// TestACLDecisionTrace：命中测试要用的 trace 只在需要时才建。
func TestACLDecisionTrace(t *testing.T) {
	global := mustList(t, "203.0.113.0/24")
	route := mustACL(t, []string{"10.0.0.0/8"}, []string{"10.0.0.66"})

	// 热路径不带 trace，避免每个请求都白建一个切片
	if d := decideIP(global, route, "10.1.2.3", false); d.Steps != nil {
		t.Errorf("trace=false 时不应填 Steps，实际 %d 步", len(d.Steps))
	}

	// 命中测试要能看到三层各自的结论
	d := decideIP(global, route, "203.0.113.7", true)
	if len(d.Steps) != 1 {
		t.Fatalf("命中全局黑名单应只记 1 步就结束，实际 %d 步", len(d.Steps))
	}
	if d.Steps[0].Layer != layerGlobalDeny || !d.Steps[0].Matched {
		t.Errorf("第一步应当是「全局黑名单命中」，实际 %+v", d.Steps[0])
	}

	// 放行时三层都要有记录，排查「为什么它进来了」才有的看
	d = decideIP(global, route, "10.1.2.3", true)
	if len(d.Steps) != 3 {
		t.Fatalf("放行时应记满三层，实际 %d 步", len(d.Steps))
	}
	if !d.Steps[1].Matched || d.Steps[1].Rule != "10.0.0.0/8" {
		t.Errorf("第二步应当是在白名单命中并给出规则，实际 %+v", d.Steps[1])
	}
}

// TestIPRuleAcceptsStringAndObject 覆盖名单条目的两种写法与序列化取舍。
func TestIPRuleAcceptsStringAndObject(t *testing.T) {
	var rules []IPRule
	raw := `["10.0.0.0/8", {"cidr": "1.2.3.4", "note": "爬虫"}]`
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		t.Fatalf("两种写法都应当能解析: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("期望解析出 2 条，实际 %d", len(rules))
	}
	if rules[0].CIDR != "10.0.0.0/8" || rules[0].Note != "" {
		t.Errorf("字符串简写解析结果不对: %+v", rules[0])
	}
	if rules[1].CIDR != "1.2.3.4" || rules[1].Note != "爬虫" {
		t.Errorf("对象写法解析结果不对: %+v", rules[1])
	}

	// 序列化：没有备注时必须回到字符串简写。
	// 否则一次控制台保存就把 ["10.0.0.0/8"] 撑成 [{"cidr":"10.0.0.0/8"}]，
	// 配置文件越存越长。
	b, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	want := `["10.0.0.0/8",{"cidr":"1.2.3.4","note":"爬虫"}]`
	if string(b) != want {
		t.Errorf("序列化期望 %s，实际 %s", want, string(b))
	}
}

// TestIPRuleRejectsGarbage：既不合法也不是对象的写法必须报错。
func TestIPRuleRejectsGarbage(t *testing.T) {
	var rules []IPRule
	if err := json.Unmarshal([]byte(`[123]`), &rules); err == nil {
		t.Error("数字既不是字符串也不是对象，应当报错")
	}
	// 缺 cidr 的条目：反序列化能过，但构建名单时必须拦下 ——
	// 否则它会变成一条谁都匹配不上的死规则，看起来配了其实没配。
	if _, err := NewIPList([]IPRule{{Note: "只有备注"}}); err == nil {
		t.Error("cidr 为空的条目应当在构建名单时报错")
	}
}

// TestIPListRejectsMalformed 覆盖 CIDR 解析的合法与非法边界。
func TestIPListRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"not-an-ip", "", "10.0.0.0/33", "300.1.1.1"} {
		if _, err := NewIPList([]IPRule{{CIDR: bad}}); err == nil {
			t.Errorf("%q 不是合法的 IP 或 CIDR，应当报错", bad)
		}
	}
	for _, ok := range []string{
		"10.0.0.0/8", "192.168.1.5", "0.0.0.0/0",
		"2001:db8::/32", "::1", "::ffff:10.0.0.1",
	} {
		if _, err := NewIPList([]IPRule{{CIDR: ok}}); err != nil {
			t.Errorf("%q 应当是合法条目，实际报错: %v", ok, err)
		}
	}
	// nil 表示「这份名单没配」，不是「空名单」
	l, err := NewIPList(nil)
	if err != nil || l != nil {
		t.Errorf("NewIPList(nil) 应当返回 (nil, nil)，实际 (%v, %v)", l, err)
	}
}

// TestIPListMatchesMappedIPv6 覆盖 IPv4-mapped IPv6 的匹配。
//
// 实测确认 Go 的 net.IPNet.Contains 对这四种组合都能正确匹配，且 ParseIP
// 本身就把 ::ffff:1.2.3.4 归一化成 1.2.3.4。所以这里**不需要**任何地址归一化
// 代码 —— 写成测试是为了防止将来有人「顺手加一层归一化」，那反而会引入
// 新的边界问题（比如把 ::ffff:10.0.0.0/120 这种写法弄坏）。
func TestIPListMatchesMappedIPv6(t *testing.T) {
	cases := []struct{ cidr, ip string }{
		{"10.0.0.0/24", "::ffff:10.0.0.5"},
		{"::ffff:10.0.0.0/120", "10.0.0.5"},
		{"::ffff:10.0.0.0/120", "::ffff:10.0.0.5"},
		{"::ffff:10.0.0.5/128", "10.0.0.5"},
	}
	for _, c := range cases {
		l, err := NewIPList([]IPRule{{CIDR: c.cidr}})
		if err != nil {
			t.Errorf("list=%s 应当合法: %v", c.cidr, err)
			continue
		}
		if _, ok := l.Match(net.ParseIP(c.ip)); !ok {
			t.Errorf("list=%s 应当匹配 ip=%s", c.cidr, c.ip)
		}
	}
}

// TestRouteACLReferences：路由只能引用**存在**的名单，悬空引用必须报错。
//
// 这条比它看起来重要：一条 allow 引用写错了名字，如果被当成「没引用」，
// 结果是这条路由不限制来源 —— 一次无声的放行。涉及白名单效力的事情一律 fail-closed，
// 宁可启动失败也不猜。
func TestRouteACLReferences(t *testing.T) {
	base := func(refs []string) *Config {
		return &Config{
			IPLists: []IPListDef{
				{Name: "办公网", Kind: IPListKindAllow, Rules: []IPRule{{CIDR: "10.0.0.0/8"}}},
				{Name: "爬虫", Kind: IPListKindDeny, Rules: []IPRule{{CIDR: "203.0.113.66"}}},
			},
			Routes: []RouteConfig{{
				ID: "r", Target: "http://127.0.0.1:9000", PathPrefix: "/",
				ACL: &RouteACLConfig{Lists: refs},
			}},
		}
	}

	if err := base([]string{"办公网", "爬虫"}).validate(); err != nil {
		t.Errorf("引用已定义的名单应当合法: %v", err)
	}

	err := base([]string{"办公网", "打错的名字"}).validate()
	if err == nil {
		t.Fatal("引用不存在的名单必须报错，不能当成「没引用」静默放行")
	}
	if !strings.Contains(err.Error(), "打错的名字") {
		t.Errorf("报错里应点名是哪份名单不存在，实际: %v", err)
	}
	// 名单少的时候顺手把可选项报出来，省得用户去翻配置文件
	if !strings.Contains(err.Error(), "办公网") {
		t.Errorf("报错里应列出当前可用的名单，实际: %v", err)
	}

	if err := base([]string{"  "}).validate(); err == nil {
		t.Error("acl.lists 里的空名字应当报错")
	}
	if err := base(nil).validate(); err != nil {
		t.Errorf("不引用任何名单 = 不做 IP 限制，应当合法: %v", err)
	}
}

// TestIPListDefValidated：名单库自身的校验（名字、角色、规则、空名单）。
func TestIPListDefValidated(t *testing.T) {
	bad := []struct {
		name string
		cfg  *Config
		why  string
	}{
		{"名字重复", &Config{IPLists: []IPListDef{
			{Name: "x", Kind: IPListKindDeny, Rules: []IPRule{{CIDR: "10.0.0.0/8"}}},
			{Name: "x", Kind: IPListKindDeny, Rules: []IPRule{{CIDR: "10.0.0.0/8"}}},
		}}, "名字是引用键，不能重名"},
		{"名字为空", &Config{IPLists: []IPListDef{
			{Name: "  ", Kind: IPListKindDeny},
		}}, "路由靠名字引用，空名字无从引用"},
		{"名字首尾有空白", &Config{IPLists: []IPListDef{
			{Name: "办公网 ", Kind: IPListKindDeny, Rules: []IPRule{{CIDR: "10.0.0.0/8"}}},
		}}, "静默 trim 会让「写了一样的名字却引用不到」更难查"},
		{"kind 非法", &Config{IPLists: []IPListDef{
			{Name: "x", Kind: "black", Rules: []IPRule{{CIDR: "10.0.0.0/8"}}},
		}}, "kind 只能是 allow|deny"},
		{"kind 缺失", &Config{IPLists: []IPListDef{
			{Name: "x", Rules: []IPRule{{CIDR: "10.0.0.0/8"}}},
		}}, "不给 kind 猜默认值，猜错的后果是放行"},
		{"CIDR 非法", &Config{IPLists: []IPListDef{
			{Name: "x", Kind: IPListKindDeny, Rules: []IPRule{{CIDR: "not-an-ip"}}},
		}}, "坏 CIDR 要在写盘前拦下"},
		{"空白名单", &Config{IPLists: []IPListDef{
			{Name: "x", Kind: IPListKindAllow, Rules: []IPRule{}},
		}}, "白名单一旦被引用就只有「只允许名单内地址」一个含义，空名单会让路由拒绝所有请求"},
		{"名字太长", &Config{IPLists: []IPListDef{
			{Name: strings.Repeat("长", 65), Kind: IPListKindDeny},
		}}, "名字会进日志，限制长度"},
		{"名字带斜杠", &Config{IPLists: []IPListDef{
			{Name: "办公网/内网", Kind: IPListKindDeny},
		}}, "斜杠会让「按名字定位一份名单」产生歧义"},
		{"名字带换行", &Config{IPLists: []IPListDef{
			{Name: "办公网\n伪造日志", Kind: IPListKindDeny},
		}}, "名单名会和规则打进日志的同一行，换行能伪造出一条不存在的记录"},
	}
	for _, c := range bad {
		c.cfg.applyDefaults()
		if err := c.cfg.validate(); err == nil {
			t.Errorf("%s：应当校验失败（%s）但通过了", c.name, c.why)
		}
	}

	// 对照：空的黑名单只是什么都不禁，没有危害，放行
	// （与空白的白名单相反，后者会让引用它的路由拒绝所有请求）
	ok := &Config{IPLists: []IPListDef{{Name: "空黑名单", Kind: IPListKindDeny, Rules: []IPRule{}}}}
	ok.applyDefaults()
	if err := ok.validate(); err != nil {
		t.Errorf("空的黑名单应当合法: %v", err)
	}
}

// TestGlobalIPDenyValidated：全局黑名单里的坏 CIDR 必须在写盘前被拦下。
//
// 写接口的顺序是「先落盘、再 reload」。校验漏掉这一层的话，坏配置会先写进
// 文件、然后 reload 才失败，进程停在一个半坏的状态上。
func TestGlobalIPDenyValidated(t *testing.T) {
	if err := (&Config{GlobalIPDeny: []IPRule{{CIDR: "300.1.1.1"}}}).validate(); err == nil {
		t.Error("非法的 global_ip_deny CIDR 应当在校验时报错")
	}
	ok := &Config{GlobalIPDeny: []IPRule{{CIDR: "203.0.113.0/24", Note: "扫描源"}}}
	if err := ok.validate(); err != nil {
		t.Errorf("合法的 global_ip_deny 不应报错: %v", err)
	}
	// 空数组是合法的：什么都不禁，没有危害（白名单不同，空数组会拒绝所有人）
	if err := (&Config{GlobalIPDeny: []IPRule{}}).validate(); err != nil {
		t.Errorf("空的 global_ip_deny 应当合法: %v", err)
	}
}

// TestLegacyACLRejected：两代旧 acl 写法都必须显式报错，且给出迁移映射。
//
// 这是本次改动里最要紧的一条防线。旧配置里 mode=allow 表达的是一条**白名单**，
// 内联的 allow 同理。新结构没有这些字段，静默忽略的后果是白名单不再生效、
// 所有来源都能访问 —— 一次无声的安全降级。配置文件还在、启动也不报错，
// 但防护已经没了，比启动失败危险得多。
func TestLegacyACLRejected(t *testing.T) {
	// v0.6.x：mode + cidrs
	for _, mode := range []string{"allow", "deny"} {
		raw := []byte(`{"routes":[{"id":"r","acl":{"mode":"` + mode + `","cidrs":["10.0.0.0/8"]}}]}`)
		err := rejectLegacyACL(raw)
		if err == nil {
			t.Fatalf("旧的 acl.mode=%s + cidrs 必须报错，不能静默失效", mode)
		}
		if !strings.Contains(err.Error(), "acl.lists") {
			t.Errorf("报错信息里应当给出当前写法的迁移映射，实际: %v", err)
		}
	}

	// v0.7.x：内联的 allow / deny
	for _, field := range []string{"allow", "deny"} {
		raw := []byte(`{"routes":[{"id":"r","acl":{"` + field + `":["10.0.0.0/8"]}}]}`)
		err := rejectLegacyACL(raw)
		if err == nil {
			t.Fatalf("内联的 acl.%s 必须报错 —— 静默忽略等于这份名单不再生效", field)
		}
		if !strings.Contains(err.Error(), "ip_lists") {
			t.Errorf("报错信息里应当说明规则现在写在顶层 ip_lists 里，实际: %v", err)
		}
	}
	// 写成空数组也算写了：那正是「谁都进不来」的事故写法，更不能放过
	if err := rejectLegacyACL([]byte(`{"routes":[{"id":"r","acl":{"allow":[]}}]}`)); err == nil {
		t.Error("内联 acl.allow 写成空数组也必须报错")
	}

	// 纯 mode=none 的残留是空操作，放行 —— 免得为一行无意义的遗留卡住升级
	if err := rejectLegacyACL([]byte(`{"routes":[{"id":"r","acl":{"mode":"none"}}]}`)); err != nil {
		t.Errorf("mode=none 的残留不应阻塞升级，实际报错: %v", err)
	}
	// 当前写法当然要能过
	if err := rejectLegacyACL([]byte(`{"routes":[{"id":"r","acl":{"lists":["办公网"]}}]}`)); err != nil {
		t.Errorf("当前写法不应被拦，实际报错: %v", err)
	}
	// 完全没有 acl 的路由
	if err := rejectLegacyACL([]byte(`{"routes":[{"id":"r"}]}`)); err != nil {
		t.Errorf("没有 acl 的路由不应被拦，实际报错: %v", err)
	}
}

// ---------- JWT ----------

func b64url(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// makeHS256Token 手工构造一个 HS256 token 用于测试
func makeHS256Token(t *testing.T, secret string, header map[string]any, claims map[string]any) string {
	t.Helper()
	h := b64url(t, header)
	p := b64url(t, claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(h + "." + p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func jwtCfg(secret string) JWTConfig {
	c := JWTConfig{Secret: secret}
	return c
}

func TestJWTValid(t *testing.T) {
	v, err := NewJWTVerifier(jwtCfg("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	tok := makeHS256Token(t, "s3cret",
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "u1", "exp": time.Now().Add(time.Hour).Unix()},
	)
	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("合法 token 应通过: %v", err)
	}
	if claims["sub"] != "u1" {
		t.Errorf("sub 应为 u1，实际 %v", claims["sub"])
	}
}

func TestJWTExpired(t *testing.T) {
	v, _ := NewJWTVerifier(jwtCfg("s3cret"))
	tok := makeHS256Token(t, "s3cret",
		map[string]any{"alg": "HS256"},
		map[string]any{"sub": "u1", "exp": time.Now().Add(-time.Hour).Unix()},
	)
	if _, err := v.Verify(tok); err != ErrTokenExpired {
		t.Errorf("过期 token 应返回 ErrTokenExpired，实际 %v", err)
	}
}

func TestJWTBadSignature(t *testing.T) {
	v, _ := NewJWTVerifier(jwtCfg("s3cret"))
	tok := makeHS256Token(t, "wrong-secret",
		map[string]any{"alg": "HS256"},
		map[string]any{"sub": "u1", "exp": time.Now().Add(time.Hour).Unix()},
	)
	if _, err := v.Verify(tok); err != ErrTokenSignature {
		t.Errorf("签名错误应返回 ErrTokenSignature，实际 %v", err)
	}
}

// alg=none 是经典的 JWT 漏洞：把 alg 改成 none 并去掉签名就能伪造身份
func TestJWTAlgNoneRejected(t *testing.T) {
	v, _ := NewJWTVerifier(jwtCfg("s3cret"))
	tok := b64url(t, map[string]any{"alg": "none"}) + "." +
		b64url(t, map[string]any{"sub": "admin"}) + "."
	if _, err := v.Verify(tok); err != ErrTokenAlgNotAllowed {
		t.Errorf("alg=none 必须被拒绝，实际 %v", err)
	}
}

// 算法混淆：服务端配了 RSA 公钥，攻击者用公钥当 HMAC 密钥签名
func TestJWTAlgorithmConfusionRejected(t *testing.T) {
	v, _ := NewJWTVerifier(jwtCfg("public-key-as-secret"))
	tok := makeHS256Token(t, "public-key-as-secret",
		map[string]any{"alg": "HS256"}, // 故意声明成 RS256
		map[string]any{"sub": "admin", "exp": time.Now().Add(time.Hour).Unix()},
	)
	// 把 alg 换成 RS256 但签名仍是 HMAC —— 白名单里没有 RS256，应被拒
	parts := strings.Split(tok, ".")
	tok = b64url(t, map[string]any{"alg": "RS256"}) + "." + parts[1] + "." + parts[2]
	if _, err := v.Verify(tok); err != ErrTokenAlgNotAllowed {
		t.Errorf("算法混淆应被拒绝，实际 %v", err)
	}
}

func TestJWTIssuerAudience(t *testing.T) {
	cfg := jwtCfg("s3cret")
	cfg.Issuer = "my-issuer"
	cfg.Audience = "my-api"
	v, _ := NewJWTVerifier(cfg)

	good := makeHS256Token(t, "s3cret", map[string]any{"alg": "HS256"},
		map[string]any{"sub": "u", "iss": "my-issuer", "aud": "my-api"})
	if _, err := v.Verify(good); err != nil {
		t.Errorf("iss/aud 匹配应通过，实际 %v", err)
	}

	bad := makeHS256Token(t, "s3cret", map[string]any{"alg": "HS256"},
		map[string]any{"sub": "u", "iss": "someone-else", "aud": "my-api"})
	if _, err := v.Verify(bad); err == nil {
		t.Error("issuer 不匹配应被拒绝")
	}
}

func TestJWTForwardClaims(t *testing.T) {
	cfg := jwtCfg("s3cret")
	cfg.ForwardClaims = map[string]string{"sub": "X-User-Id"}
	auth, err := NewJWTAuthenticator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tok := makeHS256Token(t, "s3cret", map[string]any{"alg": "HS256"},
		map[string]any{"sub": "user-42", "exp": time.Now().Add(time.Hour).Unix()})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	claims, ok, reason := auth.Authenticate(req)
	if !ok {
		t.Fatalf("认证应通过，实际失败: %s", reason)
	}
	auth.OnSuccess(req, claims)
	if got := req.Header.Get("X-User-Id"); got != "user-42" {
		t.Errorf("claim 应透传到 X-User-Id，实际 %q", got)
	}
}

// ---------- Basic ----------

func TestBasicAuth(t *testing.T) {
	a, err := NewBasicAuthenticator([]BasicAuthEntry{
		{Username: "admin", Password: "s3cret"},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "s3cret")
	if _, ok, reason := a.Authenticate(req); !ok {
		t.Errorf("正确密码应通过，实际 %s", reason)
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "wrong")
	if _, ok, _ := a.Authenticate(req); ok {
		t.Error("错误密码应被拒绝")
	}

	req = httptest.NewRequest("GET", "/", nil)
	if _, ok, reason := a.Authenticate(req); ok || reason != "missing_credentials" {
		t.Errorf("缺少凭据应返回 missing_credentials，实际 %s", reason)
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("nobody", "x")
	if _, ok, reason := a.Authenticate(req); ok || reason != "unknown_user" {
		t.Errorf("未知用户应返回 unknown_user，实际 %s", reason)
	}
}

// 缓存是为了避免每个请求都跑 bcrypt，但不能把错误结果永久记住
func TestBasicAuthCache(t *testing.T) {
	a, err := NewBasicAuthenticator([]BasicAuthEntry{{Username: "u", Password: "p"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("u", "p")
	for i := 0; i < 20; i++ {
		if _, ok, _ := a.Authenticate(req); !ok {
			t.Fatal("缓存命中后不应失败")
		}
	}
	// 直接查缓存条目数，而不是测耗时：
	// bcrypt 单次在慢机器（尤其开 -race）能到上百毫秒，用墙钟阈值判断会误报。
	if got := len(a.cache); got != 1 {
		t.Errorf("同一凭据重复认证应只产生 1 条缓存，实际 %d", got)
	}

	// 换密码应单独缓存一条 —— key 必须包含密码，只按用户名缓存会串号
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.SetBasicAuth("u", "wrong")
	for i := 0; i < 3; i++ {
		if _, ok, _ := a.Authenticate(req2); ok {
			t.Fatal("错误密码不应通过认证")
		}
	}
	if got := len(a.cache); got != 2 {
		t.Errorf("正确与错误密码应各缓存一条，实际 %d", got)
	}
	// 错误密码的结果同样要缓存，否则拿同一错误密码反复打就等于绕过了缓存保护
	if c := a.cache["u\x00wrong"]; !c.exp.After(time.Now()) {
		t.Error("错误密码的认证结果也应写入缓存并设置过期时间")
	}
}

func TestBasicAuthNoAccounts(t *testing.T) {
	if _, err := NewBasicAuthenticator(nil, ""); err == nil {
		t.Error("没有账号应报错")
	}
}

// ---------- 配置校验 ----------

func TestAuthConfigValidation(t *testing.T) {
	bad := []Config{
		{Routes: []RouteConfig{{
			ID: "a", Target: "http://x",
			Auth: &RouteAuthConfig{Mode: "basic"}, // 没配账号
		}}},
		{Routes: []RouteConfig{{
			ID: "b", Target: "http://x",
			Auth: &RouteAuthConfig{Mode: "jwt"}, // 没配 jwt
		}}},
		{Routes: []RouteConfig{{
			ID: "c", Target: "http://x",
			Auth: &RouteAuthConfig{Mode: "kerberos"},
		}}},
		{Routes: []RouteConfig{{
			ID: "d", Target: "http://x",
			CircuitBreaker: &CBConfig{ErrorRate: 1.5}, // 越界
		}}},
		{Routes: []RouteConfig{{
			ID: "e", Target: "http://x",
			ACL: &RouteACLConfig{Lists: []string{"x"}},
		}}, IPLists: []IPListDef{{Name: "x", Kind: IPListKindDeny,
			Rules: []IPRule{{CIDR: "not-an-ip"}}}}, // 名单里 CIDR 非法
		},
		{Routes: []RouteConfig{{
			ID: "f", Target: "http://x",
			ACL: &RouteACLConfig{Lists: []string{"没这份"}}, // 引用了不存在的名单
		}}},
		// 顶层全局黑名单里的坏 CIDR 同样要在写盘前拦下
		{GlobalIPDeny: []IPRule{{CIDR: "10.0.0.0/40"}}},
	}
	for i, c := range bad {
		c.applyDefaults()
		if err := c.validate(); err == nil {
			t.Errorf("用例 %d 应当校验失败但通过了", i)
		}
	}
}

// 配置没变时热重载应复用熔断器，否则一次重载就把统计清空了
func TestCircuitBreakerReusedAcrossReload(t *testing.T) {
	cfg := &Config{Routes: []RouteConfig{{
		ID: "r1", PathPrefix: "/", Target: "http://127.0.0.1:9000",
		CircuitBreaker: &CBConfig{ErrorRate: 0.5, MinCalls: 10},
	}}}
	cfg.applyDefaults()

	t1, err := buildTable(cfg, nil, newTransport())
	if err != nil {
		t.Fatal(err)
	}
	cb1 := t1.routes[0].cb
	if cb1 == nil {
		t.Fatal("熔断器未创建")
	}

	t2, _ := buildTable(cfg, t1, newTransport())
	if t2.routes[0].cb != cb1 {
		t.Error("配置未变化时热重载应复用熔断器")
	}

	cfg.Routes[0].CircuitBreaker.ErrorRate = 0.9
	t3, _ := buildTable(cfg, t2, newTransport())
	if t3.routes[0].cb == cb1 {
		t.Error("配置变化后应重建熔断器")
	}
}
