package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

// ---------- ACL ----------

func TestACLAllowMode(t *testing.T) {
	a, err := NewACL("allow", []string{"10.0.0.0/8", "192.168.1.5"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"10.1.2.3":    true,
		"192.168.1.5": true,  // 单个 IP 写法
		"192.168.1.6": false, // 不在白名单
		"8.8.8.8":     false,
		"172.16.0.1":  false,
	}
	for ip, want := range cases {
		if got := a.Allowed(ip); got != want {
			t.Errorf("allow 模式 ip=%s 期望 %v，实际 %v", ip, want, got)
		}
	}
}

func TestACLDenyMode(t *testing.T) {
	a, err := NewACL("deny", []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Allowed("10.0.0.1") {
		t.Error("黑名单内的 IP 应被拒绝")
	}
	if !a.Allowed("8.8.8.8") {
		t.Error("黑名单外的 IP 应放行")
	}
}

func TestACLEmptyCIDRsRejected(t *testing.T) {
	// allow 模式配空列表会拒绝所有流量，属于明显的配置错误，应当在启动时报错
	if _, err := NewACL("allow", nil); err == nil {
		t.Error("allow 模式但 cidrs 为空，应当报错而不是静默拒绝所有请求")
	}
	if _, err := NewACL("bogus", []string{"10.0.0.0/8"}); err == nil {
		t.Error("非法 mode 应报错")
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
	start := time.Now()
	for i := 0; i < 20; i++ {
		if _, ok, _ := a.Authenticate(req); !ok {
			t.Fatal("缓存命中后不应失败")
		}
	}
	// bcrypt 单次约 50ms+，20 次全算要 1 秒以上；有缓存应该很快
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("20 次认证耗时 %v，缓存似乎没生效", d)
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
			ACL: &ACLConfig{Mode: "whatever", CIDRs: []string{"10.0.0.0/8"}},
		}}},
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
