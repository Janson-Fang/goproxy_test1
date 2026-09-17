package main

// 管理端的会话（登录）支持。
//
// 为什么需要它：在这之前管理端只有 admin_token 一条路径，而前端把令牌明文放在
// localStorage 里，任何一段 JS 都能读到。项目本身有一个已知的存储型 XSS 面
// （访问日志的 path/query/ua 会原样进 /_goproxy/logs 并被控制台渲染），
// 一旦被利用，长期有效的 admin_token 就直接被偷走，直到手动轮换为止。
//
// 会话机制把这个「长期秘密」换成「短期、可吊销、脚本读不到」的句柄：
//
//	HttpOnly  → JS 读不到（XSS 也偷不走）
//	短寿命    → 空闲 30 分钟、绝对 12 小时，被偷了也只在一个窗口内有效
//	可吊销    → 登出即失效；改 admin_token 可以让全部会话立即下线
//
// 三条鉴权路径并存，任一通过即放行（见 adminGuard）：
//
//	回环直连（且非经本进程代理转发）｜ Bearer <admin_token> ｜ 会话 Cookie
//
// Bearer 保留是为了 curl / 脚本 / Prometheus 这些非浏览器客户端，不打算废弃。

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// sessionCookieName 会话 Cookie 名。带 goproxy 前缀避免与其它应用撞名。
	sessionCookieName = "goproxy_admin_session"

	// sessionCookiePath 必须是 /_goproxy/，**不是** /_goproxy/ui/。
	//
	// 这里踩过一次：接口在 /_goproxy/routes、/_goproxy/stats，并不在 ui/ 之下。
	// 如果按「控制台在 ui/ 下」的直觉写成 /_goproxy/ui/，浏览器根本不会把 Cookie
	// 随接口请求发出去 —— 症状是「明明登录成功了，刷新后仍然 401」，
	// 而且因为 Cookie 确实写进去了（在 DevTools 里看得见），特别难查。
	sessionCookiePath = "/_goproxy/"

	// 会话寿命。空闲超时靠滑动续期，绝对上限不续。
	sessionIdleTimeout     = 30 * time.Minute
	sessionAbsoluteTimeout = 12 * time.Hour

	// sessionSweepInterval 后台清理间隔。
	sessionSweepInterval = 5 * time.Minute

	// maxSessions 同时在线的会话上限。单管理员的工具，正常用不到两位数；
	// 设上限是防止有人反复登录把内存撑爆（每次登录都会新建一条）。
	maxSessions = 128

	// 空闲续期的最短间隔。每个请求都写一次 map 和 LastSeen 没有意义，
	// 而且会有并发竞争；超过这个间隔才真正续一次。
	sessionTouchInterval = time.Minute
)

// 登录接口的加固参数
const (
	// loginConstantDelay 固定响应耗时。令牌比对本身是 constant time，
	// 但「格式明显不对」和「比对到最后一个字节才失败」的耗时仍然不同，
	// 用固定延迟把这类时序侧信道抹平。
	loginConstantDelay = 400 * time.Millisecond

	// 每个 IP 的失败限额与封禁时长
	loginMaxFailuresPerIP = 5
	loginIPBlockDuration  = 10 * time.Minute

	// 全局失败限额：防止攻击者换 IP 池绕过 per-IP 限制。
	// 单管理员场景不需要放宽，误伤了自己等一分钟即可。
	loginMaxFailuresGlobal = 50
	loginGlobalBlockTime   = time.Minute
)

// session 是一条登录态。handle 的明文只存在于客户端 Cookie 里，
// 服务端只存 sha256(handle)，所以内存被读走也无法直接冒用。
type session struct {
	// tokenFingerprint 是登录时的 sha256(admin_token)。
	//
	// 会话与令牌绑定：每个请求都会拿当前 admin_token 的指纹和它比对，
	// 不一致即失效。这样「改 admin_token」天然就等于「所有会话立即下线」，
	// 不需要单独实现一套吊销机制，也不会出现「改了令牌但旧会话还活着」的窗口。
	tokenFingerprint string

	createdAt time.Time
	lastSeen  time.Time

	// ip / ua 只用于展示与排查，不参与鉴权判断。
	ip string
	ua string
}

type loginAttempt struct {
	failures int
	blocked  time.Time // 封禁到什么时候；零值表示没被封
	last     time.Time
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session // key = sha256(handle) 的 hex
	attempts map[string]*loginAttempt
	global   loginAttempt

	// now 可注入，测试里用来把时间往前拨。
	now func() time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{
		sessions: make(map[string]*session),
		attempts: make(map[string]*loginAttempt),
		now:      time.Now,
	}
}

// tokenFingerprint 返回 admin_token 的指纹。空令牌返回空串（调用方据此拒绝）。
func tokenFingerprint(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// newSessionHandle 生成 32 字节随机句柄，base64url 编码（Cookie 里安全）。
func newSessionHandle() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func hashHandle(handle string) string {
	sum := sha256.Sum256([]byte(handle))
	return hex.EncodeToString(sum[:])
}

// create 新建一条会话。登录成功时调用。
//
// 登录即轮换句柄：不复用任何客户端提供的值，所以不存在会话固定攻击
// （攻击者先给受害者塞一个自己知道的句柄，等对方登录后被自己接管）。
func (s *sessionStore) create(token, ip, ua string) (string, time.Time, error) {
	handle, err := newSessionHandle()
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// 满了先清过期，还满就只能拒绝 —— 说明有人在暴力登录。
	if len(s.sessions) >= maxSessions {
		s.sweepLocked(now)
	}
	if len(s.sessions) >= maxSessions {
		return "", time.Time{}, fmt.Errorf("会话数已达上限 %d", maxSessions)
	}

	s.sessions[hashHandle(handle)] = &session{
		tokenFingerprint: tokenFingerprint(token),
		createdAt:        now,
		lastSeen:         now,
		ip:               ip,
		ua:               ua,
	}
	return handle, now.Add(sessionAbsoluteTimeout), nil
}

// lookup 校验句柄，返回是否有效。有效时顺带滑动续期。
//
// token 是**当前**的 admin_token：指纹不一致说明令牌被换过，这条会话作废。
func (s *sessionStore) lookup(handle, token string) bool {
	if handle == "" {
		return false
	}
	now := s.now()
	key := hashHandle(handle)

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[key]
	if !ok {
		return false
	}

	// 绝对上限：到点就作废，不因为「一直在用」而无限续命
	if now.Sub(sess.createdAt) > sessionAbsoluteTimeout {
		delete(s.sessions, key)
		return false
	}
	// 空闲上限
	if now.Sub(sess.lastSeen) > sessionIdleTimeout {
		delete(s.sessions, key)
		return false
	}
	// 令牌被换过 → 全部会话下线
	if subtle.ConstantTimeCompare([]byte(sess.tokenFingerprint), []byte(tokenFingerprint(token))) != 1 {
		delete(s.sessions, key)
		return false
	}

	if now.Sub(sess.lastSeen) > sessionTouchInterval {
		sess.lastSeen = now
	}
	return true
}

// revoke 立即失效一条会话（登出）。
func (s *sessionStore) revoke(handle string) {
	if handle == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, hashHandle(handle))
	s.mu.Unlock()
}

// revokeAll 清空所有会话。改 admin_token / 重启后调用。
func (s *sessionStore) revokeAll() {
	s.mu.Lock()
	s.sessions = make(map[string]*session)
	s.mu.Unlock()
}

func (s *sessionStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// sweep 清掉过期会话与陈旧的登录失败记录。
func (s *sessionStore) sweep() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
}

func (s *sessionStore) sweepLocked(now time.Time) {
	for k, sess := range s.sessions {
		if now.Sub(sess.createdAt) > sessionAbsoluteTimeout ||
			now.Sub(sess.lastSeen) > sessionIdleTimeout {
			delete(s.sessions, k)
		}
	}
	// 登录失败记录也要清，否则 attempts 会随 IP 数无限增长
	for k, a := range s.attempts {
		if now.Sub(a.last) > loginIPBlockDuration*2 {
			delete(s.attempts, k)
		}
	}
	if now.Sub(s.global.last) > loginGlobalBlockTime*2 {
		s.global.failures = 0
	}
}

// ---------- 登录限流 ----------

// loginBlocked 返回 (是否被封禁, 还要等多久)。
//
// 两个维度都查：per-IP 挡住单点爆破，全局挡住换 IP 池。
func (s *sessionStore) loginBlocked(ip string) (bool, time.Duration) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.global.blocked.IsZero() && now.Before(s.global.blocked) {
		return true, s.global.blocked.Sub(now)
	}
	if a, ok := s.attempts[ip]; ok && !a.blocked.IsZero() && now.Before(a.blocked) {
		return true, a.blocked.Sub(now)
	}
	return false, 0
}

// recordLoginFailure 记一次失败，必要时升级为封禁。
func (s *sessionStore) recordLoginFailure(ip string) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	a := s.attempts[ip]
	if a == nil {
		a = &loginAttempt{}
		s.attempts[ip] = a
	}
	a.failures++
	a.last = now
	if a.failures >= loginMaxFailuresPerIP {
		a.blocked = now.Add(loginIPBlockDuration)
		a.failures = 0
		slog.Warn("登录失败次数过多，暂时封禁该来源", "ip", ip, "block", loginIPBlockDuration)
	}

	s.global.failures++
	s.global.last = now
	if s.global.failures >= loginMaxFailuresGlobal {
		s.global.blocked = now.Add(loginGlobalBlockTime)
		s.global.failures = 0
		slog.Warn("全局登录失败次数过多，短暂封禁所有登录", "block", loginGlobalBlockTime)
	}
}

// recordLoginSuccess 清掉该 IP 的失败计数。
func (s *sessionStore) recordLoginSuccess(ip string) {
	s.mu.Lock()
	delete(s.attempts, ip)
	s.mu.Unlock()
}

// ---------- HTTP 层 ----------

// setSessionCookie 下发会话 Cookie。
//
// Secure 只在请求本身走 TLS 时加：管理端口如果只跑明文，
// 加了 Secure 浏览器会直接丢弃这个 Cookie，表现为「登录成功但立刻又是未登录」。
// 想强制上 Secure 就让管理面走一条 TLS 代理路由（现在那条路是安全的）。
func setSessionCookie(w http.ResponseWriter, r *http.Request, handle string, expires time.Time) {
	c := &http.Cookie{
		Name:     sessionCookieName,
		Value:    handle,
		Path:     sessionCookiePath,
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		// SameSite=Strict 是 CSRF 的第一道防线：跨站发起的请求不会带上这个 Cookie。
		// 但不能只靠它 —— 见 requireSameOrigin。
		SameSite: http.SameSiteStrictMode,
		Secure:   requestIsTLS(r),
	}
	if c.MaxAge <= 0 {
		c.MaxAge = int(sessionAbsoluteTimeout.Seconds())
	}
	http.SetCookie(w, c)
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     sessionCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   requestIsTLS(r),
	})
}

func sessionHandleFrom(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// requireSameOrigin 校验写请求确实来自控制台自己。
//
// 为什么不能只靠 SameSite=Strict：SameSite 的判定依赖浏览器实现，
// 而且一旦将来有人为了别的需求把 Cookie 调成 Lax，这层防护就没了。
// 显式校验 Origin 是**纵深防御**的第二道，代价几乎为零。
//
// 规则（任一满足即放行）：
//   - Origin 头存在且与请求的 Host 同源
//   - Sec-Fetch-Site 明确是 same-origin / none（老浏览器不发这个头，那时看 Origin）
//
// 注意这里只对**会话/Cookie 鉴权**的写请求强制 —— Bearer 令牌不会随请求
// 自动携带，本来就没有 CSRF 面，不该给 curl 增加负担。
//
// 缺头即拒（fail-closed）在这个场景下是安全的：能走到这个分支说明请求带了
// 会话 Cookie，而浏览器在跨站写请求上一定会发 Origin/Sec-Fetch-Site。
// 但**不要**把它用在登录接口上 —— 那里没有 Cookie 可言，curl/脚本
// 也不发这些头，见 requireCrossSiteNotClaimed。
func requireSameOrigin(r *http.Request) bool {
	// 先看 Fetch Metadata，最可靠（浏览器自动加，页面改不了）
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "cross-site", "same-site":
		return false
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		// 既没有 Origin 也没有 Sec-Fetch-Site：可能是老浏览器，也可能是脚本。
		// 但走到这个分支说明请求带了会话 Cookie（否则不需要 CSRF 校验），
		// 而浏览器在跨站写请求上一定会发 Origin —— 所以缺头本身就可疑，拒绝。
		return false
	}
	u, err := parseOrigin(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u, r.Host)
}

// requireCrossSiteNotClaimed 是给**登录接口**用的同源校验（fail-open）。
//
// 与 requireSameOrigin 的区别只在于「两个头都没有」时怎么办：
//   - 会话写请求：缺头就可疑 → 拒绝
//   - 登录请求：缺头是正常的（curl、脚本、监控探针都不发这两个头）→ 放行
//
// 为什么登录用 fail-open 仍然安全：登录 CSRF 的攻击前提是「攻击者的页面
// 能让受害者浏览器向本服务发请求」。这种请求**一定**带 Origin（跨站写请求
// 浏览器强制加）或 Sec-Fetch-Site: cross-site —— 两者都会被下面拦下。
// 也就是说放行的只是「浏览器之外发起的请求」，而那些请求本来就是攻击者
// 自己就能直接发的，不需要借受害者的身份，因此不构成 CSRF。
//
// 如果一律 fail-closed，代价是 `curl -d '{"token":...}' /_goproxy/login` 直接
// 403，登录接口只能被浏览器使用 —— 这个代价明显大于它换来的那点收益。
func requireCrossSiteNotClaimed(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "cross-site", "same-site":
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := parseOrigin(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u, r.Host)
}

// parseOrigin 取出 origin 里的 host:port，用于和 r.Host 比对。
// 单独写一个函数而不是用 net/url：这里只需要 host 部分，且必须容忍
// 只有 host 没有 scheme 的非标准写法。
func parseOrigin(origin string) (string, error) {
	s := origin
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// 去掉路径部分
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "", fmt.Errorf("空的 origin")
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		// 没有端口：http 默认 80、https 默认 443，两种都可能与 r.Host 相等，
		// 所以原样返回让调用方比对（r.Host 有端口时会不相等，这是保守的正确行为）
		return s, nil
	}
	return s, nil
}

// loginFailureBody 是所有登录失败共用的响应体。
//
// 刻意不区分「令牌错」「令牌为空」「被限流之外的其它原因」：
// 区分开来等于告诉攻击者哪一步猜对了。细节只进服务端日志。
func loginFailureBody() map[string]string {
	return map[string]string{
		"error":   "invalid_credentials",
		"message": "管理令牌不正确",
	}
}

// sleepConstant 把响应耗时补齐到固定值，抹平时序差异。
func sleepConstant(start time.Time) {
	if d := loginConstantDelay - time.Since(start); d > 0 {
		time.Sleep(d)
	}
}

// jitterSeconds 给 Retry-After 加上一点抖动，避免所有客户端同时重试。
func jitterSeconds(d time.Duration) int {
	s := int(math.Ceil(d.Seconds()))
	if s < 1 {
		s = 1
	}
	return s
}
