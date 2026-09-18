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
//	可吊销    → 登出即失效；改密码 / 删账号 / 改 admin_token 都能让相关会话立即下线
//
// 两条鉴权路径并存，任一通过即放行（见 adminGuard）：
//
//	Bearer <admin_token> ｜ 会话 Cookie
//
// v0.6.0 起**回环地址不再免认证**。以前「回环直连」是第三条路径，代价是同一个
// 配置在本机访问和外部访问下表现完全不同（本机直接进、外部被拒或被要求登录），
// 很难排查，也让「登录页到底会不会出现」取决于你从哪台机器打开 —— 用户实际
// 反馈过「没见到登录界面」，根因就在这里。现在一律要凭据，行为各处一致。
//
// Bearer 保留是为了 curl / 脚本 / Prometheus 这些非浏览器客户端。

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
	// loginConstantDelay 固定响应耗时。密码比对走 bcrypt，本身就比字符串比对慢得多，
	// 但「用户名不存在」「密码错」「限流拒绝」这些分支的耗时依然不同，
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
	// fingerprint 是这条会话的「绑定指纹」，登录时算好。
	//
	// 两种登录方式指纹来源不同：
	//   - 用户名密码登录：sessionFingerprintForUser(用户名, 该账号当前密码哈希)
	//   - Bearer 令牌登录：tokenFingerprint(admin_token)
	//
	// 每个请求都会拿**当前配置**重算一次指纹并比对，不一致即失效。于是：
	//   - 改某账号密码 / 删该账号 → 该账号所有会话立刻下线
	//   - 改 admin_token        → 用令牌登录的会话立刻下线
	// 不需要另写一套吊销机制，也不会出现「改了密码但旧会话还活着」的窗口。
	fingerprint string

	// username 是登录者。令牌登录时为空串。
	// 只用于展示（控制台显示「当前登录：alice」）与日志，不参与鉴权判断。
	username string

	createdAt time.Time
	lastSeen  time.Time

	// ip / ua 只用于展示与排查，不参与鉴权判断。
	ip string
	ua string
}

// authVia 说明一个请求是靠什么通过鉴权的。
type authVia string

const (
	viaNone    authVia = "none"
	viaSession authVia = "session"
	viaBearer  authVia = "bearer"
)

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
func (s *sessionStore) create(username, fingerprint, ip, ua string) (string, time.Time, error) {
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
		fingerprint: fingerprint,
		username:    username,
		createdAt:   now,
		lastSeen:    now,
		ip:          ip,
		ua:          ua,
	}
	return handle, now.Add(sessionAbsoluteTimeout), nil
}

// lookup 校验句柄，返回 (是否有效, 登录用户名)。有效时顺带滑动续期。
//
// fingerprintOf 是由调用方传入的**当前指纹回调**，而不是直接传一个字符串。
// 原因是两种登录方式的指纹算法不同（用户名密码 vs Bearer 令牌），
// 而会话里只存了结果、没存它当初用的是哪种方式；把它做成回调，
// 由 adminGuard 按「会话里记的用户名」决定怎么算，这里的校验逻辑就与方式无关了。
//
// 回调返回空串表示「该凭据在当前配置下已不存在」（账号被删了 / 令牌被清空了），
// 这时会话一律拒绝 —— 不需要额外判断。
func (s *sessionStore) lookup(handle string, fingerprintOf func(string) string) (bool, string) {
	if handle == "" {
		return false, ""
	}
	now := s.now()
	key := hashHandle(handle)

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[key]
	if !ok {
		return false, ""
	}

	// 绝对上限：到点就作废，不因为「一直在用」而无限续命
	if now.Sub(sess.createdAt) > sessionAbsoluteTimeout {
		delete(s.sessions, key)
		return false, ""
	}
	// 空闲上限
	if now.Sub(sess.lastSeen) > sessionIdleTimeout {
		delete(s.sessions, key)
		return false, ""
	}
	// 凭据变了（改密码 / 删账号 / 换令牌）→ 这条会话下线
	want := fingerprintOf(sess.username)
	if want == "" || subtle.ConstantTimeCompare([]byte(sess.fingerprint), []byte(want)) != 1 {
		delete(s.sessions, key)
		return false, ""
	}

	if now.Sub(sess.lastSeen) > sessionTouchInterval {
		sess.lastSeen = now
	}
	return true, sess.username
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
//   - Sec-Fetch-Site 明确是 same-origin / none（老浏览器不发这个头，那时看 Origin）
//   - Origin 头存在且与 effectiveRequestHost 相同（见那个函数的注释：
//     不是简单拿 r.Host 比，经代理进来时 r.Host 已被改写）
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
	return sameHostPort(u, effectiveRequestHost(r))
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
	return sameHostPort(u, effectiveRequestHost(r))
}

// effectiveRequestHost 返回「浏览器地址栏里那个 host:port」，
// 用于和 Origin 头比对。**不要**直接拿 r.Host 比 —— 那是这个 bug 的根因。
//
// 背景：控制台的页面和接口都在 /_goproxy/ 下，用户完全可以把整个管理端口
// 用一条代理路由发布出去，于是浏览器访问的是
//
//	http://118.190.159.207:32000/_goproxy/ui/     ← Origin: 118.190.159.207:32000
//
// 而请求被本进程的代理转发到管理端口时，proxy.go 的 Director 会做
// `req.Host = target.Host`，把 Host 改写成**内部地址**（如 127.0.0.1:19090）。
// 结果 Origin 和 r.Host 永远不可能相等，登录请求被 403 拒掉，控制台卡在
// 「正在检查管理接口…」—— 用户实际报的就是这个。
//
// 从哪拿真实的 host：proxy.go 在同一处写了 X-Forwarded-Host（原始 Host）。
// 但**不能无条件相信这个头** —— 它是客户端随手就能加的，直接信任等于把
// CSRF 防护的决定权交给攻击者（攻击者发一个 Origin 和 X-Forwarded-Host
// 都填成自己域名的请求即可绕过）。所以只在两个条件同时成立时才采用：
//
//  1. 请求确实经过本进程的代理（viaOwnProxy）。这个标记由 Director 无条件
//     覆盖写入，外部伪造它只会让自己被按「经代理」处理（更严格），不构成绕过；
//  2. 这个 host 确实是本进程代理时改写的（X-Forwarded-Host 非空）。
//
// 反过来，攻击者想借 X-Forwarded-Host 绕过 CSRF，必须让请求**经本进程代理**
// 进来，而那时 Director 会用**真实的原始 Host** 覆盖掉他伪造的值 —— 他写的
// 那个值根本活不到管理端。所以这里信 X-Forwarded-Host 是安全的。
//
// 直接访问（不经代理）时退回 r.Host，与旧行为一致，没有放松。
func effectiveRequestHost(r *http.Request) string {
	if viaOwnProxy(r) {
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			return h
		}
	}
	return r.Host
}

// sameHostPort 比对两个 host:port 是否等同，缺端口时按协议默认端口补齐。
//
// 为什么要补默认端口：浏览器在 80/443 上访问时会**省略** Origin 里的端口
// （`Origin: http://example.com`），而 r.Host 也常常不带端口，但代理改写过的
// X-Forwarded-Host 是原样的 Host，可能带着 `:80`。不归一化就会出现
// 「同一个来源，有时相等有时不等」这种极难排查的抖动。
//
// 更关键的是**不能**只比 host 忽略端口：同主机不同端口 = 不同源
// （同源策略明确按 scheme+host+port 三元组判定）。把端口丢掉会让
// 「同级端口上的无关服务」也能通过校验，等于自己削掉一层防护。
// 所以这里的做法是「缺省时补上、都有时严格比」。
func sameHostPort(a, b string) bool {
	return strings.EqualFold(normalizeHostPort(a), normalizeHostPort(b))
}

// normalizeHostPort 把 host / host:port 统一成带端口的小写形式。
// 补的默认端口只能是 80：本函数没有 scheme 信息，而**只有 http 才有
// 「省略 80」这个行为** —— 恰恰是这里要修的场景（用户部署在
// http://118.190.159.207:32000/，带的是非默认端口，不会被省略）。
// https 的情况另说：443 从不会被省略，且 8080 这类端口根本不是
// https 的默认值，因此补 80 不会造成「本该不同源却判成同源」。
func normalizeHostPort(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	// 去掉可能的 userinfo（正常不会有，保守处理）
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	host, port, err := net.SplitHostPort(h)
	if err != nil {
		return strings.ToLower(h) + ":80"
	}
	if port == "" {
		port = "80"
	}
	return strings.ToLower(host) + ":" + port
}

// parseOrigin 取出 origin 里的 host:port。
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
		// 没有端口：原样返回，由 normalizeHostPort 统一补默认端口后再比。
		// （旧注释说「原样返回让调用方比 r.Host」，那是 r.Host 时代的事；
		//  现在两边都会过 normalizeHostPort，所以这里不需要做任何推断。）
		return s, nil
	}
	return s, nil
}

// loginFailureBody 是所有登录失败共用的响应体。
//
// 刻意不区分「用户名不存在」「密码错」「令牌错」「凭据为空」：
// 区分开来等于告诉攻击者哪一步猜对了 —— 尤其「用户名不存在」这一条，
// 一旦单独报出来，就能被用来枚举系统里有哪些账号。
// 细节（用了哪个用户名、是走的密码还是令牌）只进服务端日志。
//
// v0.6.0 改文案：以前是「管理令牌不正确」，但那时令牌是唯一凭据。
// 现在主路径是用户名+密码，再这么说会让用户去找一个他根本没设过的令牌。
func loginFailureBody() map[string]string {
	return map[string]string{
		"error":   "invalid_credentials",
		"message": "用户名或密码不正确",
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
