package main

// 管理端登录 / 会话的测试。
//
// 覆盖四个层面的不变量：
//  1. 会话存储本身：签发、校验、空闲超时、绝对超时、改令牌即全员下线、登出
//  2. Cookie 属性：HttpOnly / SameSite 一定对；Path 必须是 /_goproxy/（不是 ui/）；
//     Secure 只在 TLS 请求上加
//  3. 登录接口加固：失败限流、恒定响应时间、错误文案不泄露信息
//  4. CSRF：带着会话 Cookie 的跨源写请求必须被拒
//
// 这些用例里凡是「防绕过」性质的，都配了负向验证脚本（见本轮交付说明），
// 确认它们真的会因为对应防护被拿掉而变红。

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------- 会话存储 ----------

// constFP 返回一个「永远算出同一个指纹」的回调。
//
// lookup 的第二个参数是回调而不是字符串，是因为两种登录方式的指纹算法不同
// （用户名密码登录绑账号密码哈希，Bearer 登录绑令牌）。会话存的是指纹结果，
// 不记得当初用的是哪种方式，所以由调用方按会话里记的用户名决定怎么算。
//
// 对「只测会话存储本身」的用例来说，指纹怎么算无关紧要 —— 重要的是
// 「当前算出来的值」和「创建时存下的值」是否相同。所以这里固定返回一个值，
// 就能精确模拟「凭据没变」（返回值不变）和「凭据变了」（换成另一个值）两种情况。
func constFP(v string) func(string) string {
	return func(string) string { return v }
}

// sessionValid 是 lookup 的单值封装，只关心「有没有通过」。
//
// lookup 本身返回 (是否有效, 用户名)，因为鉴权之后还要知道「是谁」。
// 会话存储这层的用例大多只关心前者，用这个封装能让断言保持原来的写法：
//
//	s.lookup(...)  ->  sessionValid(s, ...)
func sessionValid(s *sessionStore, handle string, fp func(string) string) bool {
	ok, _ := s.lookup(handle, fp)
	return ok
}

func TestSessionCreateAndLookup(t *testing.T) {
	s := newSessionStore()

	handle, expires, err := s.create("", "tok", "1.2.3.4", "test-ua")
	if err != nil {
		t.Fatalf("create 失败: %v", err)
	}
	if handle == "" {
		t.Fatal("句柄为空")
	}
	if !expires.After(time.Now()) {
		t.Errorf("过期时间应该在将来，实际 %v", expires)
	}
	if got := s.count(); got != 1 {
		t.Errorf("会话数应为 1，实际 %d", got)
	}

	if !sessionValid(s, handle, constFP("tok")) {
		t.Error("刚创建的会话应该校验通过")
	}
	if sessionValid(s, "not-a-real-handle", constFP("tok")) {
		t.Error("不存在的句柄不该通过")
	}
	if sessionValid(s, "", constFP("tok")) {
		t.Error("空句柄不该通过")
	}
}

// 服务端只存 sha256(handle)：内存被读走也不能直接拿来冒用。
func TestSessionStoresOnlyHandleHash(t *testing.T) {
	s := newSessionStore()
	handle, _, err := s.create("", "tok", "1.2.3.4", "ua")
	if err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.sessions {
		if k == handle {
			t.Fatal("map 的 key 是明文句柄 —— 必须只存 sha256")
		}
		if k != hashHandle(handle) {
			t.Fatalf("key 不是 sha256(handle)：%s", k)
		}
	}
}

// 改 admin_token = 所有会话立即下线（不需要额外的吊销机制）。
func TestSessionInvalidatedByTokenChange(t *testing.T) {
	s := newSessionStore()
	handle, _, err := s.create("", "old-token", "1.2.3.4", "ua")
	if err != nil {
		t.Fatal(err)
	}
	if !sessionValid(s, handle, constFP("old-token")) {
		t.Fatal("换令牌前应该有效")
	}
	if sessionValid(s, handle, constFP("new-token")) {
		t.Error("换了 admin_token 之后旧会话必须失效 —— 这是「改令牌即全员下线」的全部实现")
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newSessionStore()
	s.now = func() time.Time { return now }

	handle, _, err := s.create("", "tok", "1.2.3.4", "ua")
	if err != nil {
		t.Fatal(err)
	}

	// 空闲但没超时：一轮「用一下 → 等」应该能一直续下去
	now = now.Add(sessionIdleTimeout - time.Minute)
	if !sessionValid(s, handle, constFP("tok")) {
		t.Fatal("空闲未超时应仍然有效")
	}

	// 超过空闲上限
	now = now.Add(sessionIdleTimeout + time.Minute)
	if sessionValid(s, handle, constFP("tok")) {
		t.Error("空闲超过 30 分钟必须失效")
	}
}

// 绝对上限不因为「一直在用」而被无限续命。
func TestSessionAbsoluteTimeout(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newSessionStore()
	s.now = func() time.Time { return now }

	handle, _, err := s.create("", "tok", "1.2.3.4", "ua")
	if err != nil {
		t.Fatal(err)
	}

	// 持续活跃（每次都没超过空闲上限），但累计超过绝对上限。
	//
	// 步长取 sessionIdleTimeout/2 = 15 分钟，必须走上超过 12 小时的轮数才够。
	// 这里按绝对上限算轮数再留 2 轮余量，而不是写死一个数字 ——
	// 写死 30 轮时实际只累积了 7.5 小时（不到 12 小时），断言看上去在测
	// 绝对上限，其实根本没触到，是个假通过。
	steps := int(sessionAbsoluteTimeout/(sessionIdleTimeout/2)) + 2
	for i := 0; i < steps; i++ {
		now = now.Add(sessionIdleTimeout / 2)
		sessionValid(s, handle, constFP("tok"))
	}
	elapsed := time.Duration(steps) * (sessionIdleTimeout / 2)
	if elapsed <= sessionAbsoluteTimeout {
		t.Fatalf("测试自身有误：累计 %v 未超过绝对上限 %v，"+
			"这个用例证明不了任何事", elapsed, sessionAbsoluteTimeout)
	}
	if sessionValid(s, handle, constFP("tok")) {
		t.Errorf("累计活跃 %v 超过绝对上限 %v 后必须失效，不能靠活跃无限续期",
			elapsed, sessionAbsoluteTimeout)
	}
}

func TestSessionRevoke(t *testing.T) {
	s := newSessionStore()
	h1, _, _ := s.create("", "tok", "1.2.3.4", "ua")
	h2, _, _ := s.create("", "tok", "1.2.3.4", "ua")

	s.revoke(h1)
	if sessionValid(s, h1, constFP("tok")) {
		t.Error("被登出的会话必须立即失效")
	}
	if !sessionValid(s, h2, constFP("tok")) {
		t.Error("登出一个会话不该影响另一个")
	}

	s.revokeAll()
	if sessionValid(s, h2, constFP("tok")) {
		t.Error("revokeAll 之后所有会话都该失效")
	}
}

func TestSessionSweepRemovesExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newSessionStore()
	s.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		if _, _, err := s.create("", "tok", "1.2.3.4", "ua"); err != nil {
			t.Fatal(err)
		}
	}
	if s.count() != 5 {
		t.Fatalf("应有 5 条，实际 %d", s.count())
	}

	now = now.Add(sessionAbsoluteTimeout + time.Hour)
	s.sweep()
	if got := s.count(); got != 0 {
		t.Errorf("sweep 后应清空，实际还剩 %d 条", got)
	}
}

// 会话数上限：防止有人反复登录把内存撑爆。
func TestSessionCountCap(t *testing.T) {
	s := newSessionStore()
	created := 0
	for i := 0; i < maxSessions+20; i++ {
		if _, _, err := s.create("", "tok", "1.2.3.4", "ua"); err == nil {
			created++
		}
	}
	if created > maxSessions {
		t.Errorf("创建的会话数 %d 超过上限 %d", created, maxSessions)
	}
	if s.count() > maxSessions {
		t.Errorf("存活会话数 %d 超过上限 %d", s.count(), maxSessions)
	}
}

// ---------- 登录限流 ----------

func TestLoginRateLimitPerIP(t *testing.T) {
	s := newSessionStore()
	ip := "9.9.9.9"

	for i := 0; i < loginMaxFailuresPerIP; i++ {
		if blocked, _ := s.loginBlocked(ip); blocked {
			t.Fatalf("第 %d 次失败前不该被封", i+1)
		}
		s.recordLoginFailure(ip)
	}
	blocked, wait := s.loginBlocked(ip)
	if !blocked {
		t.Fatalf("%d 次失败后应封禁该 IP", loginMaxFailuresPerIP)
	}
	if wait <= 0 {
		t.Errorf("封禁剩余时间应为正，实际 %v", wait)
	}

	// 别的 IP 不受影响 —— 否则一个人爆破就把大家都锁在外面
	if blocked, _ := s.loginBlocked("8.8.8.8"); blocked {
		t.Error("一个 IP 被封不该牵连其它 IP")
	}
}

func TestLoginGlobalLimit(t *testing.T) {
	s := newSessionStore()
	// 每个 IP 只试一次，换 IP 池绕过 per-IP 限制 —— 全局计数要能兜住
	for i := 0; i < loginMaxFailuresGlobal; i++ {
		s.recordLoginFailure(strings.Repeat("x", i%5) + string(rune('a'+i%26)))
	}
	blocked, _ := s.loginBlocked("fresh-ip-never-seen")
	if !blocked {
		t.Error("换 IP 池绕过 per-IP 限制时，全局限制必须兜住")
	}
}

func TestLoginSuccessClearsFailures(t *testing.T) {
	s := newSessionStore()
	ip := "7.7.7.7"
	s.recordLoginFailure(ip)
	s.recordLoginFailure(ip)
	s.recordLoginSuccess(ip)
	// 成功后计数清零，所以再失败 4 次仍不该封
	for i := 0; i < loginMaxFailuresPerIP-1; i++ {
		s.recordLoginFailure(ip)
	}
	if blocked, _ := s.loginBlocked(ip); blocked {
		t.Error("登录成功后失败计数应清零")
	}
}

// ---------- Cookie 属性 ----------

func loginAndGetCookie(t *testing.T, e *testEnv, token string, opts ...func(*http.Request)) *http.Cookie {
	t.Helper()
	rr := e.do(t, "POST", "/_goproxy/login", `{"token":"`+token+`"}`,
		append([]func(*http.Request){remote("203.0.113.9:5000")}, opts...)...)
	if rr.Code != http.StatusOK {
		t.Fatalf("登录应成功，实际 %d：%s", rr.Code, rr.Body.String())
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatal("登录响应里没有会话 Cookie")
	return nil
}

func TestLoginSetsHardenedCookie(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	c := loginAndGetCookie(t, e, "s3cret")

	if !c.HttpOnly {
		t.Error("会话 Cookie 必须 HttpOnly —— 这是「XSS 偷不走凭据」的唯一依据")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("会话 Cookie 应 SameSite=Strict，实际 %v", c.SameSite)
	}
	if c.Path != "/_goproxy/" {
		t.Errorf("Cookie Path 应为 /_goproxy/，实际 %q\n"+
			"  写成 /_goproxy/ui/ 会导致接口请求不带 Cookie（接口不在 ui/ 之下），"+
			"  症状是「登录成功但刷新后仍然 401」", c.Path)
	}
	if c.Secure {
		t.Error("明文请求上不该加 Secure（浏览器会直接丢弃该 Cookie）")
	}
	if c.Value == "" {
		t.Error("Cookie 值不应为空")
	}
}

// 走 TLS 时必须带 Secure。
func TestLoginCookieSecureOverTLS(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	c := loginAndGetCookie(t, e, "s3cret", func(r *http.Request) {
		// requestIsTLS 先看 context 里的 ctxKeyTLS，没有才看 r.TLS。
		// 这里用 context 注入，和 tls_test.go 里的做法一致。
		*r = *r.WithContext(withTLS(r.Context(), true))
	})
	if !c.Secure {
		t.Error("TLS 请求上的会话 Cookie 必须带 Secure")
	}
}

// ---------- 端到端的会话鉴权 ----------

func TestSessionGrantsAccessWithoutToken(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	c := loginAndGetCookie(t, e, "s3cret")

	// 外部来源 + 只有 Cookie、没有 Bearer → 应该放行
	rr := e.do(t, "GET", "/_goproxy/routes", "",
		remote("203.0.113.9:5000"),
		func(r *http.Request) { r.AddCookie(c) })
	if rr.Code != http.StatusOK {
		t.Fatalf("带有效会话 Cookie 应放行，实际 %d：%s", rr.Code, rr.Body.String())
	}
}

func TestSessionRejectedAfterLogout(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	c := loginAndGetCookie(t, e, "s3cret")

	rr := e.do(t, "DELETE", "/_goproxy/session", "",
		remote("203.0.113.9:5000"),
		func(r *http.Request) {
			r.AddCookie(c)
			r.Header.Set("Origin", "http://example.com")
			r.Host = "example.com"
		})
	if rr.Code != http.StatusOK {
		t.Fatalf("登出应成功，实际 %d：%s", rr.Code, rr.Body.String())
	}

	// 同一个 Cookie 再用一次必须失效。
	//
	// 必须显式 noAuth()：e.do 默认会带上 Bearer 令牌，
	// 那样请求会靠令牌通过，就测不出「会话有没有真的被吊销」了。
	rr = e.do(t, "GET", "/_goproxy/routes", "",
		remote("203.0.113.9:5000"),
		noAuth(),
		func(r *http.Request) { r.AddCookie(c) })
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("登出后旧会话必须失效，实际 %d", rr.Code)
	}
}

// 改 admin_token 后，手里的会话立刻作废（端到端）。
func TestSessionRejectedAfterTokenRotated(t *testing.T) {
	e := newTestEnv(t, "old-token", "")
	c := loginAndGetCookie(t, e, "old-token")

	// 直接换掉运行时的令牌，模拟管理员改了配置
	e.app.mu.Lock()
	e.app.adminToken = "new-token"
	e.app.mu.Unlock()

	rr := e.do(t, "GET", "/_goproxy/routes", "",
		remote("203.0.113.9:5000"),
		noAuth(),
		func(r *http.Request) { r.AddCookie(c) })
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("换令牌后旧会话必须失效，实际 %d", rr.Code)
	}
}

// 伪造的会话 Cookie 不管用。
func TestForgedSessionRejected(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	for _, bad := range []string{"", "deadbeef", strings.Repeat("a", 43)} {
		rr := e.do(t, "GET", "/_goproxy/routes", "",
			remote("203.0.113.9:5000"),
			noAuth(), // 否则会靠默认带的 Bearer 令牌通过，掩盖伪造会话被判定的结果
			func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: bad})
			})
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("伪造句柄 %q 应被拒，实际 %d", bad, rr.Code)
		}
	}
}

// ---------- CSRF ----------

// 带会话 Cookie 的跨源写请求必须被拒。
//
// SameSite=Strict 已经挡了一层，但那是浏览器行为，不能作为唯一防线 ——
// 这条测试守的是显式的 Origin/Sec-Fetch-Site 校验。
func TestSessionRejectsCrossOriginWrite(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	c := loginAndGetCookie(t, e, "s3cret")

	cases := []struct {
		name   string
		opts   []func(*http.Request)
		expect int
	}{
		{
			name: "跨源 Origin → 拒",
			opts: []func(*http.Request){
				header("Origin", "http://evil.example"),
			},
			expect: http.StatusForbidden,
		},
		{
			name: "Sec-Fetch-Site: cross-site → 拒",
			opts: []func(*http.Request){
				header("Sec-Fetch-Site", "cross-site"),
				header("Origin", "http://evil.example"),
			},
			expect: http.StatusForbidden,
		},
		{
			name: "同源 Origin → 放行",
			opts: []func(*http.Request){
				header("Origin", "http://example.com"),
			},
			expect: http.StatusOK,
		},
		{
			name: "Sec-Fetch-Site: same-origin → 放行",
			opts: []func(*http.Request){
				header("Sec-Fetch-Site", "same-origin"),
			},
			expect: http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]func(*http.Request){
				remote("203.0.113.9:5000"),
				func(r *http.Request) {
					r.AddCookie(c)
					r.Host = "example.com"
				},
			}, tc.opts...)
			// 用 PATCH /config 这种「改了也没关系」的写接口
			rr := e.do(t, "PATCH", "/_goproxy/config", `{"access_log":true}`, opts...)
			if rr.Code != tc.expect {
				t.Errorf("期望 %d，实际 %d：%s", tc.expect, rr.Code, rr.Body.String())
			}
		})
	}
}

// GET 不加 CSRF 校验：它改不了任何东西，而 SSE 长连接不该因为缺 Origin 被拒。
func TestSessionAllowsCrossOriginRead(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	c := loginAndGetCookie(t, e, "s3cret")

	rr := e.do(t, "GET", "/_goproxy/routes", "",
		remote("203.0.113.9:5000"),
		func(r *http.Request) {
			r.AddCookie(c)
			r.Header.Set("Origin", "http://evil.example")
		})
	if rr.Code != http.StatusOK {
		t.Errorf("GET 不该被 CSRF 校验拦下，实际 %d", rr.Code)
	}
}

// Bearer 令牌不该被 CSRF 校验影响：它不随请求自动携带，本来就没有 CSRF 面，
// 给 curl 加这个负担只会让脚本莫名其妙地失败。
func TestBearerUnaffectedByCSRFCheck(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	rr := e.do(t, "PATCH", "/_goproxy/config", `{"access_log":true}`,
		remote("203.0.113.9:5000"),
		header("Authorization", "Bearer s3cret"))
	if rr.Code != http.StatusOK {
		t.Errorf("Bearer 请求不该受 Origin 校验影响，实际 %d：%s", rr.Code, rr.Body.String())
	}
}

// ---------- 经代理访问时的同源判定 ----------

// 经本进程代理进来时，Origin 要和**浏览器实际使用的 host** 比，
// 不能和 r.Host 比 —— 后者已被 Director 改写成内部地址了。
//
// 这是用户报的 bug：把控制台用一条路由发布出去（例如 32000 端口 → 管理端口），
// 浏览器发的 Origin 是 http://<公网IP>:32000，而 r.Host 是 127.0.0.1:<管理端口>，
// 两者永不相等 → 登录 403 cross_origin_rejected → 页面卡在「正在检查管理接口…」。
func TestSessionAcceptsSameOriginBehindProxy(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	c := loginAndGetCookie(t, e, "s3cret")

	const publicHost = "118.190.159.207:32000"

	// 模拟 proxy.go 的 Director 改写后的请求：
	//   Host 被换成内部地址，X-Forwarded-Host 记着浏览器真正访问的地址，
	//   同时带上 internalViaHeader 标记「这是我自己代理转发的」。
	viaProxy := func(r *http.Request) {
		r.AddCookie(c)
		r.Host = "127.0.0.1:19090" // 内网管理端口
		r.Header.Set("X-Forwarded-Host", publicHost)
		r.Header.Set(internalViaHeader, "1")
	}

	// 1) 经代理 + Origin 与浏览器实际访问的 host 一致 → 应当放行
	rr := e.do(t, "PATCH", "/_goproxy/config", `{"access_log":true}`,
		remote("203.0.113.9:5000"),
		viaProxy,
		header("Origin", "http://"+publicHost))
	if rr.Code != http.StatusOK {
		t.Errorf("经代理的同源写请求应当放行，实际 %d：%s", rr.Code, rr.Body.String())
	}

	// 2) 经代理 + Origin 是第三方 → 仍然必须拒绝。
	//    这条是这次修复的**安全边界**：放宽同源判定绝不能变成「一律放行」。
	rr = e.do(t, "PATCH", "/_goproxy/config", `{"access_log":true}`,
		remote("203.0.113.9:5000"),
		viaProxy,
		header("Origin", "http://evil.example"))
	if rr.Code != http.StatusForbidden {
		t.Errorf("经代理但来源是第三方时必须拒绝，实际 %d：%s", rr.Code, rr.Body.String())
	}

	// 3) 经代理 + Origin 指向内网管理端口（即 r.Host 的值）→ 也必须拒绝。
	//    这一条专门守住「别退回去用 r.Host 比」：谁也不该能靠猜内部地址通过校验。
	rr = e.do(t, "PATCH", "/_goproxy/config", `{"access_log":true}`,
		remote("203.0.113.9:5000"),
		viaProxy,
		header("Origin", "http://127.0.0.1:19090"))
	if rr.Code != http.StatusForbidden {
		t.Errorf("Origin 指向内部管理地址时必须拒绝，实际 %d：%s", rr.Code, rr.Body.String())
	}
}

// 伪造 X-Forwarded-Host 不能绕过同源校验。
//
// 前提：攻击者必须**不经本进程代理**（直接打管理端口）才谈得上「伪造」——
// 一旦经代理，Director 会用真实的原始 Host 覆盖掉他写的值。
// 这里覆盖的正是那条「不经代理直接打管理端口 + 自带 X-Forwarded-Host」的路径。
func TestSessionRejectsForgedForwardedHost(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	c := loginAndGetCookie(t, e, "s3cret")

	// 不经代理（没有 internalViaHeader），X-Forwarded-Host 纯属客户端瞎写：
	// 此时它**不该**被采信，判定仍以 r.Host 为准，于是 evil.example 被拒。
	rr := e.do(t, "PATCH", "/_goproxy/config", `{"access_log":true}`,
		remote("203.0.113.9:5000"),
		func(r *http.Request) {
			r.AddCookie(c)
			r.Host = "example.com"
			// 攻击者想用这个头让校验通过
			r.Header.Set("X-Forwarded-Host", "evil.example")
		},
		header("Origin", "http://evil.example"))
	if rr.Code != http.StatusForbidden {
		t.Errorf("未经代理时伪造 X-Forwarded-Host 必须无效，实际 %d：%s", rr.Code, rr.Body.String())
	}

	// 同样不经代理，但 Origin 与真实 Host 一致 → 正常放行（没有误伤）
	rr = e.do(t, "PATCH", "/_goproxy/config", `{"access_log":true}`,
		remote("203.0.113.9:5000"),
		func(r *http.Request) {
			r.AddCookie(c)
			r.Host = "example.com"
			r.Header.Set("X-Forwarded-Host", "evil.example")
		},
		header("Origin", "http://example.com"))
	if rr.Code != http.StatusOK {
		t.Errorf("未经代理时仍应按 r.Host 判定并放行，实际 %d：%s", rr.Code, rr.Body.String())
	}
}

// 登录接口也要能在代理后面正常工作。
func TestLoginViaProxySucceeds(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")

	rr := e.do(t, "POST", "/_goproxy/login", `{"token":"s3cret"}`,
		remote("203.0.113.9:5000"),
		func(r *http.Request) {
			r.Host = "127.0.0.1:19090"
			r.Header.Set("X-Forwarded-Host", "118.190.159.207:32000")
			r.Header.Set(internalViaHeader, "1")
		},
		header("Origin", "http://118.190.159.207:32000"))
	if rr.Code != http.StatusOK {
		t.Fatalf("经代理登录应当成功，实际 %d：%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Set-Cookie"), sessionCookieName) {
		t.Error("登录成功应下发会话 Cookie")
	}
}

// 端口不同就不算同源（同源策略按 scheme+host+port 三元组判定）。
// 防的是「把端口归一化过头」这种过宽实现。
func TestOriginCheckKeepsPortSignificance(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	c := loginAndGetCookie(t, e, "s3cret")

	rr := e.do(t, "PATCH", "/_goproxy/config", `{"access_log":true}`,
		remote("203.0.113.9:5000"),
		func(r *http.Request) {
			r.AddCookie(c)
			r.Host = "127.0.0.1:19090"
			r.Header.Set("X-Forwarded-Host", "118.190.159.207:32000")
			r.Header.Set(internalViaHeader, "1")
		},
		// 同一主机、不同端口 —— 不是同源
		header("Origin", "http://118.190.159.207:32001"))
	if rr.Code != http.StatusForbidden {
		t.Errorf("同主机不同端口不算同源，应拒绝，实际 %d：%s", rr.Code, rr.Body.String())
	}
}

// normalizeHostPort / sameHostPort 的单元测试。
//
// 重点是「缺省端口补齐」这一条：浏览器在 80 端口上会省略 Origin 里的端口，
// 而 Host 可能带着 :80，不归一化就会出现「同一个来源有时判同源有时不判」的抖动。
func TestSameHostPort(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "example.com:80", true}, // 省略的 80 要补上
		{"example.com:80", "example.com:80", true},
		{"EXAMPLE.com", "example.com", true},       // host 大小写不敏感
		{"example.com", "example.com:8080", false}, // 端口不同 → 不同源
		{"example.com", "evil.example", false},     // 主机不同
		{"118.190.159.207:32000", "118.190.159.207:32000", true},
		{"118.190.159.207:32000", "118.190.159.207:32001", false},
		{"example.com:8080", "example.com", false}, // 非默认端口对缺省 → 不等
		{"", "example.com", false},                 // 空值不相等
		{"::1", "::1", true},                       // IPv6 字面量
	}
	for _, tc := range cases {
		if got := sameHostPort(tc.a, tc.b); got != tc.want {
			t.Errorf("sameHostPort(%q, %q) = %v，期望 %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// effectiveRequestHost 的取值规则：只有「经本进程代理」才信 X-Forwarded-Host。
func TestEffectiveRequestHost(t *testing.T) {
	cases := []struct {
		name    string
		viaMark string
		xfh     string
		host    string
		want    string
	}{
		{"不经代理 → 用 r.Host", "", "evil.example", "example.com", "example.com"},
		{"经代理 + 有 XFH → 用 XFH", "1", "118.190.159.207:32000", "127.0.0.1:19090", "118.190.159.207:32000"},
		{"经代理但没 XFH → 退回 r.Host", "1", "", "127.0.0.1:19090", "127.0.0.1:19090"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "http://x/", nil)
			r.Host = tc.host
			if tc.viaMark != "" {
				r.Header.Set(internalViaHeader, tc.viaMark)
			}
			if tc.xfh != "" {
				r.Header.Set("X-Forwarded-Host", tc.xfh)
			}
			if got := effectiveRequestHost(r); got != tc.want {
				t.Errorf("effectiveRequestHost = %q，期望 %q", got, tc.want)
			}
		})
	}
}

// ---------- 登录接口本身 ----------

// 登录接口必须在**没有任何凭据**时就能访问到。
//
// 这条守的是一个真实踩过的坑：/login 曾经注册在 adminGuard 之内的 mux 上，
// 于是未登录的调用方在 Guard 里就被 401 掉，永远走不到 handleLogin ——
// 钥匙被锁在屋里。症状是所有登录相关的测试一起变 401。
//
// 这里从非回环地址发起（回环默认免认证，证明不了什么），
// 且不带 Authorization、不带 Cookie。
func TestLoginReachableWithoutCredentials(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")

	rr := e.do(t, "POST", "/_goproxy/login", `{"token":"s3cret"}`,
		remote("203.0.113.77:5000"))

	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
		t.Fatalf("未认证的登录请求被挡在门外（%d）：%s\n"+
			"  登录接口的职责就是「在还没有凭据时拿到凭据」，"+
			"它必须在 adminGuard 之外（见 main.go 的 isAuthPath）",
			rr.Code, rr.Body.String())
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("登录应成功，实际 %d：%s", rr.Code, rr.Body.String())
	}
	var found bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookieName {
			found = true
		}
	}
	if !found {
		t.Error("登录成功却没下发会话 Cookie")
	}
}

// /session 的 GET 也必须在认证前可访问：前端靠它判断「该不该显示登录页」。
// 未登录时要么给 401，要么给明确的 authenticated:false，不能整个被 Guard 挡掉。
func TestSessionStateReachableWithoutCredentials(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")

	// noAuth() 是这条用例成立的前提：e.do 默认带 Bearer 令牌，
	// 不停用的话请求就是「已认证」，永远测不到未登录分支。
	rr := e.do(t, "GET", "/_goproxy/session", "", remote("203.0.113.78:5000"), noAuth())

	// 被 adminGuard 挡掉的话是「需要登录，或带 Bearer」那条 401；
	// 走通到 handler 的话是「尚未登录。」—— 两者状态码相同但 body 不同。
	if rr.Code == http.StatusUnauthorized &&
		strings.Contains(rr.Body.String(), "Bearer") {
		t.Fatalf("/session 被 adminGuard 挡下了，前端拿不到会话状态：%s", rr.Body.String())
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("未登录时 /session 应回 401 让前端切登录页，实际 %d：%s",
			rr.Code, rr.Body.String())
	}
}

// 登录接口的 CSRF 校验：跨源声明必须被拒，但不带 Origin 的脚本请求要放行。
//
// fail-open 与 fail-closed 的差别就在这里 —— 登录请求本来就不带 Cookie，
// 跨站攻击**一定**会带 Origin/Sec-Fetch-Site，所以「缺头放行」不构成 CSRF 面；
// 而一律 fail-closed 会让 curl 根本没法登录。
func TestLoginCSRFPolicy(t *testing.T) {
	cases := []struct {
		name   string
		opts   []func(*http.Request)
		expect int
	}{
		{
			name:   "不带 Origin（curl/脚本）→ 放行",
			opts:   nil,
			expect: http.StatusOK,
		},
		{
			name: "Sec-Fetch-Site: same-origin → 放行",
			opts: []func(*http.Request){
				header("Sec-Fetch-Site", "same-origin"),
				header("Origin", "http://example.com"),
			},
			expect: http.StatusOK,
		},
		{
			name: "跨源 Origin → 拒",
			opts: []func(*http.Request){
				header("Origin", "http://evil.example"),
			},
			expect: http.StatusForbidden,
		},
		{
			name: "Sec-Fetch-Site: cross-site → 拒",
			opts: []func(*http.Request){
				header("Sec-Fetch-Site", "cross-site"),
				header("Origin", "http://evil.example"),
			},
			expect: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 每个子用例独立环境：避免前一个用例把 IP 打进封禁名单
			e := newTestEnv(t, "s3cret", "")
			opts := append([]func(*http.Request){
				remote("203.0.113.90:5000"),
				func(r *http.Request) { r.Host = "example.com" },
			}, tc.opts...)

			rr := e.do(t, "POST", "/_goproxy/login", `{"token":"s3cret"}`, opts...)
			if rr.Code != tc.expect {
				t.Errorf("期望 %d，实际 %d：%s", tc.expect, rr.Code, rr.Body.String())
			}
			if tc.expect == http.StatusForbidden &&
				strings.Contains(rr.Body.String(), sessionCookieName) {
				t.Error("被拒的登录请求不该下发任何 Cookie")
			}
		})
	}
}

func TestLoginRejectsWrongToken(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	rr := e.do(t, "POST", "/_goproxy/login", `{"token":"wrong"}`, remote("198.51.100.5:5000"))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("错令牌应 401，实际 %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "s3cret") {
		t.Error("响应体泄露了正确的令牌")
	}
}

// 令牌为空和令牌错误必须给完全一样的响应 —— 否则等于告诉攻击者
// 服务端到底有没有配置令牌。
func TestLoginFailureMessagesAreIndistinguishable(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	a := e.do(t, "POST", "/_goproxy/login", `{"token":""}`, remote("198.51.100.1:5000"))
	b := e.do(t, "POST", "/_goproxy/login", `{"token":"nope"}`, remote("198.51.100.2:5000"))

	if a.Code != b.Code {
		t.Errorf("空令牌与错令牌的状态码应一致：%d vs %d", a.Code, b.Code)
	}
	if a.Body.String() != b.Body.String() {
		t.Errorf("空令牌与错令牌的响应体应一致：\n  %s\n  %s", a.Body.String(), b.Body.String())
	}
}

// 恒定响应时间：过快或过慢都不对。给一波宽松的上下界，
// 只要求「确实等待了，且没有离谱地久」—— 它防的是时序侧信道，不是精度。
func TestLoginResponseIsConstantTime(t *testing.T) {
	if testing.Short() {
		t.Skip("耗时测试，-short 下跳过")
	}
	e := newTestEnv(t, "s3cret", "")

	start := time.Now()
	e.do(t, "POST", "/_goproxy/login", `{"token":"wrong"}`, remote("198.51.100.77:5000"))
	elapsed := time.Since(start)

	if elapsed < loginConstantDelay-50*time.Millisecond {
		t.Errorf("登录响应耗时 %v，短于恒定延迟 %v —— 时序侧信道没被抹平", elapsed, loginConstantDelay)
	}
	if elapsed > loginConstantDelay+2*time.Second {
		t.Errorf("登录响应耗时 %v，远超恒定延迟", elapsed)
	}
}

func TestLoginBlockedAfterRepeatedFailures(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	ip := "198.51.100.123:5000"

	for i := 0; i < loginMaxFailuresPerIP; i++ {
		e.do(t, "POST", "/_goproxy/login", `{"token":"wrong"}`, remote(ip))
	}
	rr := e.do(t, "POST", "/_goproxy/login", `{"token":"s3cret"}`, remote(ip))

	// 注意：被封之后**正确令牌也进不来**，这是有意的 ——
	// 否则攻击者只要猜对一次就能立刻继续，限流就没意义了。
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("连续失败后应 429，实际 %d：%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("429 应带 Retry-After")
	}
}

// ---------- 会话状态接口 ----------

// /session 要如实报告「这次请求是靠什么通过认证的」——前端据此决定
// 显示用户名还是「令牌模式」，也用来判断要不要渲染登出按钮。
//
// v0.6.0 的 via 取值只剩三个：session / bearer / ""（未认证）。
// 「loopback」这个值随回环免认证一起去掉了 —— 本机直连现在也必须有凭据，
// 因此它要么是 bearer（配了令牌的脚本）、要么是 session（浏览器登录过）。
func TestSessionEndpointReportsVia(t *testing.T) {
	e := newTestEnv(t, testToken, "")

	// 未认证：via 应该是空的，且明确回 401
	rr := e.do(t, "GET", "/_goproxy/session", "", noAuth())
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("未认证时 /session 应 401，实际 %d", rr.Code)
	}
	got := decode[map[string]any](t, rr)
	if got["via"] != nil && got["via"] != "" {
		t.Errorf("未认证时不该报告 via，实际 %v", got["via"])
	}

	// Bearer 直连：via 是 bearer，且不该被当成有会话
	rr = e.do(t, "GET", "/_goproxy/session", "")
	got = decode[map[string]any](t, rr)
	if got["via"] != "bearer" {
		t.Errorf("带令牌直连的 via 应为 bearer，实际 %v", got["via"])
	}
	if got["has_session"] != false {
		t.Errorf("带令牌直连不该被当成有会话，实际 %v", got["has_session"])
	}

	// 登录之后：via 是 session，并且带得出用户名
	c := loginAndGetCookie(t, e, testToken)
	rr = e.do(t, "GET", "/_goproxy/session", "",
		remote("203.0.113.9:5000"),
		noAuth(), // 只靠 Cookie，不带 Bearer —— 否则测的是令牌那条路
		func(r *http.Request) { r.AddCookie(c) })
	got = decode[map[string]any](t, rr)
	if got["via"] != "session" {
		t.Errorf("登录后 via 应为 session，实际 %v", got["via"])
	}
	if got["has_session"] != true {
		t.Errorf("登录后 has_session 应为 true，实际 %v", got["has_session"])
	}
}

// ---------- 安全响应头 ----------

func TestSecurityHeadersPresent(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")

	for _, path := range []string{"/_goproxy/routes", "/_goproxy/ui/", "/"} {
		rr := e.do(t, "GET", path, "")
		h := rr.Header()

		for _, k := range []string{
			"X-Content-Type-Options", "X-Frame-Options",
			"X-Robots-Tag", "Referrer-Policy", "Content-Security-Policy",
		} {
			if h.Get(k) == "" {
				t.Errorf("%s 缺少安全头 %s", path, k)
			}
		}
		if h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s 的 nosniff 不对：%q", path, h.Get("X-Content-Type-Options"))
		}
	}
}

// CSP 的 script-src 必须收成 'self'。一旦放开 'unsafe-inline'，
// XSS 只要注入一段内联 <script> 就能执行，CSP 基本就白加了。
func TestCSPDoesNotAllowInlineScript(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	rr := e.do(t, "GET", "/_goproxy/ui/", "")
	csp := rr.Header().Get("Content-Security-Policy")

	if !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP 里 script-src 应收成 'self'，实际：%s", csp)
	}
	// 只检查 script-src 那一段，别误伤 style-src 上那个有意的 'unsafe-inline'
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "script-src") && strings.Contains(part, "unsafe-inline") {
			t.Errorf("script-src 不允许出现 unsafe-inline：%s", part)
		}
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP 应含 frame-ancestors 'none'（防点击劫持），实际：%s", csp)
	}
}

// 500 响应不能回显内部错误详情。
func TestInternalErrorDoesNotLeakDetails(t *testing.T) {
	e := newTestEnv(t, "s3cret", "")
	// 用一个会触发内部错误的路径：把配置文件删掉再请求需要读它的接口
	// （handleGetConfig 读文件失败 → writeErr 走 500 分支）
	if err := os.Remove(e.path); err != nil {
		t.Fatalf("删除配置文件失败: %v", err)
	}

	rr := e.do(t, "GET", "/_goproxy/config", "")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("期望 500，实际 %d：%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, e.path) {
		t.Errorf("500 响应泄露了文件路径：%s", body)
	}
	if strings.Contains(body, "no such file") || strings.Contains(body, "cannot find") {
		t.Errorf("500 响应泄露了系统错误原文：%s", body)
	}
	if !strings.Contains(body, "internal") {
		t.Errorf("500 应返回错误码 internal，实际：%s", body)
	}
}
