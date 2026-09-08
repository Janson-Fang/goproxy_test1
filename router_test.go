package main

import "testing"

func mustTable(t *testing.T, routes ...RouteConfig) *RouteTable {
	t.Helper()
	cfg := &Config{Routes: routes}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatalf("配置校验失败: %v", err)
	}
	tbl, err := buildTable(cfg, nil, newTransport())
	if err != nil {
		t.Fatalf("构建路由表失败: %v", err)
	}
	return tbl
}

func rc(id string, port int, host, path, target string) RouteConfig {
	return RouteConfig{ID: id, ListenPort: port, Host: host, PathPrefix: path, Target: target}
}

// 场景 C 的核心：同一个 IP，不同端口 → 不同后端
func TestPortBasedRouting(t *testing.T) {
	tbl := mustTable(t,
		rc("svc-a", 8081, "", "/", "http://127.0.0.1:9001"),
		rc("svc-b", 8082, "", "/", "http://127.0.0.1:9002"),
		rc("svc-c", 8083, "", "/", "http://127.0.0.1:9003"),
	)

	cases := []struct {
		port int
		want string
	}{
		{8081, "svc-a"},
		{8082, "svc-b"},
		{8083, "svc-c"},
	}
	for _, c := range cases {
		got := tbl.Match(c.port, "1.2.3.4", "/")
		if got == nil {
			t.Fatalf("端口 %d 未匹配到任何路由", c.port)
		}
		if got.ID != c.want {
			t.Errorf("端口 %d 期望路由 %s，实际 %s", c.port, c.want, got.ID)
		}
	}

	// 未监听的端口不应该匹配
	if r := tbl.Match(9999, "1.2.3.4", "/"); r != nil {
		t.Errorf("未声明的端口 9999 不应命中，实际命中 %s", r.ID)
	}
}

// listen_port=0 的全局路由要挂到每个端口上，且端口专属路由优先
func TestGlobalRouteFallback(t *testing.T) {
	tbl := mustTable(t,
		rc("global", 0, "", "/", "http://127.0.0.1:9000"),
		rc("p8081", 8081, "", "/", "http://127.0.0.1:9001"),
	)

	if got := tbl.Match(8081, "", "/").ID; got != "p8081" {
		t.Errorf("端口专属路由应优先于全局路由，实际 %s", got)
	}
	// 80 是默认端口，虽然没有被任何路由显式引用，但全局路由同样生效
	if got := tbl.Match(80, "", "/").ID; got != "global" {
		t.Errorf("默认端口应命中全局路由，实际 %s", got)
	}

	// 全局路由只挂在「实际监听的端口」上：8082 没被任何路由引用，
	// 不会开监听，也就不该被匹配到。
	ports := tbl.ListenPorts()
	want := []int{80, 8081}
	if len(ports) != len(want) || ports[0] != 80 || ports[1] != 8081 {
		t.Errorf("监听端口应为 %v，实际 %v", want, ports)
	}
	if r := tbl.Match(8082, "", "/"); r != nil {
		t.Errorf("未监听的端口 8082 不应命中，实际 %s", r.ID)
	}
}

func TestHostMatching(t *testing.T) {
	tbl := mustTable(t,
		rc("any", 0, "", "/", "http://127.0.0.1:9000"),
		rc("wild", 0, "*.example.com", "/", "http://127.0.0.1:9001"),
		rc("exact", 0, "api.example.com", "/", "http://127.0.0.1:9002"),
	)

	cases := []struct{ host, want string }{
		{"api.example.com", "exact"},      // 精确优先
		{"a.example.com", "wild"},         // 通配次之
		{"example.com", "any"},            // *.example.com 不匹配裸域名
		{"other.com", "any"},              // 兜底
		{"API.EXAMPLE.COM", "exact"},      // 大小写不敏感
		{"api.example.com:8080", "exact"}, // 去掉端口
	}
	for _, c := range cases {
		if got := tbl.Match(80, c.host, "/").ID; got != c.want {
			t.Errorf("host=%s 期望 %s，实际 %s", c.host, c.want, got)
		}
	}
}

// /api 不能匹配 /apixxx —— 这是前缀匹配最容易写错的地方
func TestPathBoundary(t *testing.T) {
	tbl := mustTable(t,
		rc("api", 0, "", "/api", "http://127.0.0.1:9001"),
		rc("root", 0, "", "/", "http://127.0.0.1:9000"),
	)

	cases := []struct{ path, want string }{
		{"/api", "api"},
		{"/api/", "api"},
		{"/api/users", "api"},
		{"/apixxx", "root"}, // 关键：不属于 /api
		{"/ap", "root"},
		{"/", "root"},
	}
	for _, c := range cases {
		if got := tbl.Match(80, "", c.path).ID; got != c.want {
			t.Errorf("path=%s 期望 %s，实际 %s", c.path, c.want, got)
		}
	}
}

func TestLongestPrefixWins(t *testing.T) {
	tbl := mustTable(t,
		rc("root", 0, "", "/", "http://127.0.0.1:9000"),
		rc("api", 0, "", "/api", "http://127.0.0.1:9001"),
		rc("api-v2", 0, "", "/api/v2", "http://127.0.0.1:9002"),
	)
	if got := tbl.Match(80, "", "/api/v2/users").ID; got != "api-v2" {
		t.Errorf("最长前缀应优先，期望 api-v2，实际 %s", got)
	}
	if got := tbl.Match(80, "", "/api/v1").ID; got != "api" {
		t.Errorf("期望 api，实际 %s", got)
	}
}

// 热重载时如果限流器被重建，客户端改一次配置就能绕过限流
func TestLimiterReusedAcrossReload(t *testing.T) {
	cfg := &Config{Routes: []RouteConfig{
		{ID: "r1", PathPrefix: "/", Target: "http://127.0.0.1:9000",
			RateLimit: &RateLimitConfig{RPS: 1, Burst: 1}},
	}}
	cfg.applyDefaults()

	t1, err := buildTable(cfg, nil, newTransport())
	if err != nil {
		t.Fatal(err)
	}
	l1 := t1.routes[0].limiter
	if l1 == nil {
		t.Fatal("限流器未创建")
	}

	// 模拟一次热重载，配置内容不变
	t2, err := buildTable(cfg, t1, newTransport())
	if err != nil {
		t.Fatal(err)
	}
	if t2.routes[0].limiter != l1 {
		t.Error("配置未变化时，热重载应复用原限流器（否则限流计数被清零）")
	}

	// 配置变了（rps 调整）才允许重建
	cfg.Routes[0].RateLimit.RPS = 100
	t3, _ := buildTable(cfg, t2, newTransport())
	if t3.routes[0].limiter == l1 {
		t.Error("限流参数变化后应重建限流器")
	}
}

func TestTokenBucket(t *testing.T) {
	l := NewIPLimiter(2, 2, false)
	defer l.Close()

	// 桶容量 2，先打满
	if !l.Allow("1.1.1.1") || !l.Allow("1.1.1.1") {
		t.Fatal("前两次请求应当放行（桶容量为 2）")
	}
	if l.Allow("1.1.1.1") {
		t.Error("第三次请求应被限流")
	}
	// 另一个 IP 有独立配额
	if !l.Allow("2.2.2.2") {
		t.Error("不同 IP 应各自独立计数")
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []struct {
		name string
		cfg  Config
	}{
		{"target 缺少协议", Config{Routes: []RouteConfig{{ID: "a", Target: "127.0.0.1:80"}}}},
		{"path 不以 / 开头", Config{Routes: []RouteConfig{{ID: "a", PathPrefix: "api", Target: "http://x"}}}},
		{"id 重复", Config{Routes: []RouteConfig{
			{ID: "a", Target: "http://x"}, {ID: "a", Target: "http://y"},
		}}},
		{"端口越界", Config{Routes: []RouteConfig{{ID: "a", ListenPort: 70000, Target: "http://x"}}}},
	}
	for _, c := range bad {
		c.cfg.applyDefaults()
		if err := c.cfg.validate(); err == nil {
			t.Errorf("%s: 应当校验失败，但通过了", c.name)
		}
	}
}
