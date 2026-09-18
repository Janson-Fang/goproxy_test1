package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// maxBodyBytes 限制管理接口请求体大小。1MiB 足够放几百条路由。
const maxBodyBytes = 1 << 20

// apiError 是带 HTTP 状态码的业务错误，处理器直接映射，不用各自判断。
type apiError struct {
	status int
	code   string
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func badRequest(code, format string, a ...any) *apiError {
	return &apiError{http.StatusBadRequest, code, fmt.Sprintf(format, a...)}
}

func notFound(id string) *apiError {
	return &apiError{http.StatusNotFound, "route_not_found", fmt.Sprintf("路由 %q 不存在", id)}
}

// ---------- 登录 / 登出 / 会话状态 ----------
//
// 这三个接口的路径都**不在 adminGuard 之内**（见 main.go 的 isAuthPath）：
// 登录接口的职责就是「在还没有凭据的时候拿到凭据」，放在闸门里等于把钥匙
// 锁在屋里。放行不等于不设防 —— 各自带限流、恒定耗时、同源校验。
//
// 历史上这三条曾注册在 adminMux 上（受 Guard 保护），导致未登录请求在 Guard 里
// 就被 401 掉、永远走不到处理器。那个 bug 的症状是「所有登录测试一起变 401」，
// 看着像认证逻辑写错，实际是路由挂错了层。

// sessionLoginRequest 是登录请求体。
//
// 支持两种形态，两种都合法：
//
//	{"username":"alice","password":"..."}  ← 控制台登录页用
//	{"token":"<admin_token>"}              ← 脚本 / 不方便建账号的场景用
//
// 都不含回显字段：这两个值在任何情况下都不会出现在响应体或日志里
// （日志故意只记 ip / ua / 是否配置了凭据，不记内容）。
type sessionLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

// handleLogin 用「用户名 + 密码」或「admin_token」换取一个会话 Cookie。
//
// 防爆破的三层：
//   - 单个 IP 失败 5 次封 10 分钟
//   - 全局失败 50 次短暂封禁（挡换 IP 池）
//   - 响应时间恒定 ~400ms（抹平时序侧信道）
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// 登录接口的响应绝不能被缓存，否则可能把一个成功响应缓存给另一个用户
	w.Header().Set("Cache-Control", "no-store")

	// 这条路径在 adminGuard 之外（否则未登录根本到不了这里），
	// 所以同源校验得自己兜 —— 不能让一个第三方站点替用户登成别的账号，
	// 那会变成「登录 CSRF」。
	//
	// 用 requireCrossSiteNotClaimed 而不是 requireSameOrigin：
	// 登录请求本来就不带 Cookie，curl/脚本也不发 Origin，
	// 一律 fail-closed 会把非浏览器的登录入口直接堵死。理由详见该函数注释。
	if isStateChanging(r.Method) && !requireCrossSiteNotClaimed(r) {
		slog.Warn("拒绝来源不明的登录请求",
			"method", r.Method,
			"origin", r.Header.Get("Origin"),
			"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"))
		sleepConstant(start)
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":   "cross_origin_rejected",
			"message": "登录请求的来源与控制台不同源，已拒绝。",
		})
		return
	}

	ip := clientIP(r, a.trustedNets())
	ua := r.UserAgent()

	if blocked, wait := a.sessions.loginBlocked(ip); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(jitterSeconds(wait)))
		sleepConstant(start)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error":   "too_many_attempts",
			"message": "登录失败次数过多，请稍后再试。",
		})
		return
	}

	var req sessionLoginRequest
	// 限制体积：登录体只有几十字节，不需要 1MiB 的宽容度
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil &&
		err != io.EOF {
		sleepConstant(start)
		writeJSON(w, http.StatusBadRequest, loginFailureBody())
		return
	}

	a.mu.Lock()
	token := a.adminToken
	accounts := a.adminAccounts
	a.mu.Unlock()

	// 两条凭据路径。顺序无关紧要（两者互斥：用户名密码请求不带 token 字段），
	// 但结果要能区分「哪种凭据都没配」—— 那不是登录失败，是没配置，
	// 前端据此显示「去设置账号」而不是「密码错误」（否则用户会一直重试一个
	// 根本没设过的密码）。
	var (
		username    string
		fingerprint string
		via         authVia
	)

	switch {
	case req.Username != "" || req.Password != "":
		// 用户名密码路径。verify 内部对「用户不存在」也跑一次假哈希比对，
		// 避免用响应时间枚举用户名。
		fp, err := accounts.verify(req.Username, req.Password)
		if err == nil {
			username, fingerprint, via = req.Username, fp, viaSession
		}

	case req.Token != "":
		// 令牌路径。常量时间比对；「令牌没配」和「令牌错」走同一条失败路径 ——
		// 区分开来等于告诉攻击者服务端到底有没有配置令牌。
		if token != "" && subtle.ConstantTimeCompare([]byte(req.Token), []byte(token)) == 1 {
			fingerprint, via = tokenFingerprint(token), viaBearer
		}
	}

	if via == "" {
		// 凭据都没配置时不要记失败次数：那不是「有人在猜密码」，
		// 而是「管理员还没配」。记进去会让真正的管理员被自己锁在门外。
		if !a.hasAnyAdminCredentialLocked() {
			slog.Warn("管理端登录被拒：配置里没有任何可用的管理凭据", "ip", ip)
			sleepConstant(start)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "admin_credentials_not_set",
				"message": "服务端还没有配置任何管理凭据。请在 config.json 里设置 " +
					"admin_users（用户名 + bcrypt 密码哈希，推荐）或 admin_token，" +
					"保存后会自动热重载。",
			})
			return
		}

		a.sessions.recordLoginFailure(ip)
		slog.Warn("管理端登录失败", "ip", ip, "ua", ua,
			"username_used", req.Username,
			"token_used", req.Token != "",
			"accounts_configured", accounts.count())
		sleepConstant(start)
		writeJSON(w, http.StatusUnauthorized, loginFailureBody())
		return
	}

	handle, expires, err := a.sessions.create(username, fingerprint, ip, ua)
	if err != nil {
		slog.Error("创建会话失败", "err", err)
		sleepConstant(start)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error":   "session_unavailable",
			"message": "会话创建失败，请稍后重试。",
		})
		return
	}

	a.sessions.recordLoginSuccess(ip)
	setSessionCookie(w, r, handle, expires)
	slog.Info("管理端登录成功", "ip", ip, "username", username, "via", string(via),
		"active_sessions", a.sessions.count())

	sleepConstant(start)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"via":      string(via),
		"username": username,
		"expires":  expires.UTC().Format(time.RFC3339),
		"secure":   requestIsTLS(r),
		"idle_sec": int(sessionIdleTimeout.Seconds()),
		"abs_sec":  int(sessionAbsoluteTimeout.Seconds()),
	})
}

// handleSession 查询当前会话状态（GET）或登出（DELETE）。
//
// 放在同一个路径上是因为它们表达的是同一件事的状态迁移，
// 前端也只需要记一个地址。
//
// 这条路径在 adminGuard 之外（见 main.go 的 isAuthPath），所以它必须**自己**
// 判断凭据是否有效，不能假设「能走到这里就是已认证」。
func (a *App) handleSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	handle := sessionHandleFrom(r)
	user, via := a.identifyAdminRequest(r, handle)
	authenticated := via != viaNone

	switch r.Method {
	case http.MethodGet:
		// 未认证时明确回 401，前端据此切到登录页。
		//
		// 注意这里**不能**沿用 adminGuard 里那句 "需要登录，或带 Bearer" ——
		// 前端判断「要不要显示登录页」看的是状态码和 error 字段，
		// 给 200 + authenticated:false 会让控制台一直转圈。
		if !authenticated {
			w.Header().Set("WWW-Authenticate", `Bearer realm="goproxy admin"`)
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":   "unauthorized",
				"message": "尚未登录。",
				// 一并告诉前端「服务端到底有没有配凭据」，让它能在登录页上
				// 直接给出正确的下一步，而不是让人对着「用户名或密码错误」
				// 反复试一个从来没设过的账号。
				"credentials_configured": a.hasAnyAdminCredential(),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"via":           string(via),
			"username":      user,
			"has_session":   via == viaSession,
			"token_set":     a.adminTokenSet(),
		})

	case http.MethodDelete, http.MethodPost:
		// DELETE 是登出；POST 也接受（部分客户端不方便发 DELETE）
		if !requireSameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":   "cross_origin_rejected",
				"message": "登出请求的来源与控制台不同源，已拒绝。",
			})
			return
		}
		if via == viaSession {
			a.sessions.revoke(handle)
		}
		clearSessionCookie(w, r)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		w.Header().Set("Allow", "GET, DELETE, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// identifyAdminRequest 判断一个请求的凭据来源，返回 (用户名, 来源)。
//
// 这是唯一一处「怎么算通过鉴权」的判定逻辑，adminGuard 与 handleSession
// 都调它 —— 两处各写一遍是这类代码最容易出的错：Guard 放行的路径
// handleSession 认为没登录（或者反过来），症状是「能改路由但按钮显示未登录」。
//
// 不在这里做 CSRF 校验：写方法要不要同源检查取决于调用场景
// （会话写请求 fail-closed、登录 fail-open），由各自的调用方决定。
func (a *App) identifyAdminRequest(r *http.Request, handle string) (username string, via authVia) {
	a.mu.Lock()
	token := a.adminToken
	accounts := a.adminAccounts
	a.mu.Unlock()

	// 会话优先：浏览器只会走这条，而且它带得出「是谁」。
	if handle != "" {
		ok, user := a.sessions.lookup(handle, func(sessionUser string) string {
			if sessionUser == "" {
				// 令牌登录建立的会话没有用户名，用令牌指纹续期
				return tokenFingerprint(token)
			}
			return accounts.fingerprintFor(sessionUser)
		})
		if ok {
			return user, viaSession
		}
	}

	// Bearer 令牌：给 curl / 脚本 / Prometheus 用。
	if got, ok := bearerToken(r); ok && token != "" &&
		subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1 {
		return "", viaBearer
	}

	return "", viaNone
}

// hasAnyAdminCredential 报告当前配置里有没有可用的管理凭据。
func (a *App) hasAnyAdminCredential() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hasAnyAdminCredentialLocked()
}

// hasAnyAdminCredentialLocked 同上，但要求调用方已持有 a.mu。
func (a *App) hasAnyAdminCredentialLocked() bool {
	return a.adminAccounts.count() > 0 || strings.TrimSpace(a.adminToken) != ""
}

// adminTokenSet 报告是否配置了 admin_token。只用于展示，不用于鉴权决定。
func (a *App) adminTokenSet() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.TrimSpace(a.adminToken) != ""
}

// writeErr 把错误翻译成响应。
//
// 500 的响应体**不回显 err.Error()**：那里面常常带着绝对路径、
// 「permission denied」、甚至配置文件内容片段，等于免费给攻击者做信息收集。
// 详情只进服务端日志，客户端拿到一个短错误码 + 一句笼统说明。
// 排查时按 error id 去日志里搜（id 也回给客户端，便于对账）。
func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeJSON(w, ae.status, map[string]string{"error": ae.code, "message": ae.msg})
		return
	}
	id := newErrorID()
	slog.Error("管理接口内部错误", "error_id", id, "err", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{
		"error":   "internal",
		"message": "服务端内部错误，详情见服务端日志（错误编号 " + id + "）。",
	})
}

// newErrorID 生成一个短错误编号，用来把客户端看到的 500 和服务端日志对上。
// 只需要「短时间内可区分」，不要求全局唯一，所以取 8 字节十六进制足够。
func newErrorID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 随机源不可用时退化成固定值，不能因为这个就把请求搞挂
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

// ---------- 认证 ----------

// adminGuard 包住整个管理端 mux。三条鉴权路径，任一通过即放行：
//
//  1. 来自回环地址、且**不是经本进程代理转发**进来的请求（本机运维习惯）
//  2. Authorization: Bearer <admin_token>（curl / 脚本 / Prometheus）
//  3. 会话 Cookie（控制台登录后拿到；HttpOnly，脚本读不到）
//
// 判断来源只用 RemoteAddr，绝不用 X-Forwarded-For —— XFF 是客户端随手就能写的头，
// 拿它判断「是不是本机」等于把认证决定权交给攻击者。
//
// 关键：光看 RemoteAddr 是不够的。代理转发到管理端口时源地址就是 127.0.0.1，
// 所以「来源是回环」在**本进程自己转发**的情形下毫无保证 —— 只要存在一条
// target 指向管理端口的代理路由，外部客户端就能白拿免认证的管理权限。
// 因此这里额外要求「不带代理标记头」才认回环，见 internalViaHeader。
func (a *App) adminGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handle := sessionHandleFrom(r)
		username, via := a.identifyAdminRequest(r, handle)

		switch via {
		case viaSession:
			// 会话/Cookie 会被浏览器自动携带，所以必须防 CSRF。
			// 只对写方法强制：GET 修改不了任何东西，而 SSE 等长连接
			// 不该因为缺 Origin 就被拒。
			if isStateChanging(r.Method) && !requireSameOrigin(r) {
				slog.Warn("拒绝来源不明的管理写请求（会话鉴权）",
					"method", r.Method, "path", r.URL.Path,
					"username", username,
					"origin", r.Header.Get("Origin"),
					"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"))
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error":   "cross_origin_rejected",
					"message": "写操作的来源与控制台不同源，已拒绝。",
				})
				return
			}
			next.ServeHTTP(w, r)
			return

		case viaBearer:
			// Bearer 不随请求自动携带，本来就没有 CSRF 面，
			// 所以这里**不做**同源校验 —— 给 curl 增加负担没有收益。
			next.ServeHTTP(w, r)
			return
		}

		// 到这里说明既没有有效会话、也没有有效令牌。
		//
		// 曾经这里还有一条「回环地址免认证」的路径，v0.6.0 已移除：
		// 它让同一个配置在本机访问和外部访问下表现完全不同，是用户报
		// 「没见到登录界面」的直接原因。现在一律要凭据。
		//
		// 注意 viaOwnProxy / internalViaHeader 仍然必须保留 ——
		// 它的作用已经不是「把回环请求降级」，而是保证经本进程代理转发进来的
		// 请求一定带有这个标记。攻击者可以伪造它，但伪造的后果只是「把自己
		// 变成一个普通的未认证请求」，对攻击者毫无好处，所以无需防伪。
		if !a.hasAnyAdminCredential() {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "admin_credentials_not_set",
				"message": "该请求需要认证，但配置里既没有 admin_users 也没有 admin_token，已拒绝。" +
					"请在 config.json 里配置后重载（admin_users 用 bcrypt 的 password_hash，推荐）。",
			})
			return
		}

		// 这条是给「用脚本/curl 的人」看的：他已经会读响应体，直接告诉他
		// 两条路各怎么走。浏览器走的是 /_goproxy/session 的 401（文案不同），
		// 因为前端要看的是状态码 + credentials_configured，不是这句话。
		w.Header().Set("WWW-Authenticate", `Bearer realm="goproxy admin"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":   "unauthorized",
			"message": "需要登录：浏览器打开 /_goproxy/ui/ 用用户名密码登录，脚本请带 Authorization: Bearer <admin_token>",
		})
	})
}

// isStateChanging 判断方法是否会改动服务端状态。
func isStateChanging(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// viaOwnProxy 判断请求是不是经**本进程自己的代理**转发进来的。
//
// 标记头由本进程在转发前往请求里注入（见 internalViaHeader），外部客户端
// 理论上也能自己伪造这个头。但伪造的后果只是「把自己降级成需要认证」——
// 相当于主动放弃任何可能的信任，对攻击者毫无好处，所以这里不需要额外防伪。
//
// v0.6.0 起回环不再免认证，这个函数也就不再用于「决定要不要放行」。
// 保留它是因为 adminHandler 仍需要识别「经代理进来的请求」来做日志标注与
// 避免把控制台重定向逻辑套到代理流量上；同样的判断在 probe 脚本里也仍是
// 验证「路由指向管理端口能不能提权」的依据。
func viaOwnProxy(r *http.Request) bool {
	return r.Header.Get(internalViaHeader) != ""
}

// trustedNets 返回可信代理网段快照，登录限流用它解析真实 IP。
func (a *App) trustedNets() []*net.IPNet {
	if p := a.trusted.Load(); p != nil {
		return *p
	}
	return nil
}

func isLoopbackAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	v := r.Header.Get("Authorization")
	if len(v) <= len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(v[len(prefix):])
	return tok, tok != ""
}

// ---------- 写事务 ----------

// mutate 执行「读配置 → 改 → 校验 → 原子写回 → 热重载」，全程串行。
//
// 事务的源永远是磁盘上的文件，而不是内存里的路由表 ——
// 这样即使用户手工编辑过 config.json，界面的一次保存也不会把它悄悄覆盖掉。
//
// ifMatch 非空时要求与当前 revision 一致，用来挡住两个页签互相覆盖（lost update）。
// 返回写回后的 revision 与最终生效的配置。
func (a *App) mutate(ifMatch string, fn func(cfg *Config) error) (rev string, out *Config, err error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()

	raw, cfg, err := parseConfigFile(a.cfgPath)
	if err != nil {
		return "", nil, err
	}
	if ifMatch != "" && ifMatch != revisionOf(raw) {
		return "", nil, &apiError{http.StatusConflict, "revision_mismatch",
			"配置已被其它请求修改，请重新读取后再提交"}
	}

	// 先固化一遍路由默认值，之后按 ID 增删改才稳定
	cfg.applyRouteDefaults()

	if err := fn(cfg); err != nil {
		return "", nil, err
	}
	// fn 可能新增了路由，再补一次默认值（否则 ID / path_prefix 会空着落盘）
	cfg.applyRouteDefaults()

	if err := cfg.validateWithDefaults(); err != nil {
		return "", nil, badRequest("invalid_config", "%v", err)
	}

	_, newRev, err := saveConfig(a.cfgPath, cfg)
	if err != nil {
		return "", nil, err
	}

	// 把 watcher 的基线推到新文件上，免得 watchLoop 再触发一次重复重载
	if st, serr := os.Stat(a.cfgPath); serr == nil {
		a.mu.Lock()
		a.lastMod, a.lastSize = st.ModTime(), st.Size()
		a.mu.Unlock()
	}

	if err := a.reload(); err != nil {
		// 已经落盘了才发现在运行时加载不了 —— 立刻回滚，别留下一个坏配置
		if werr := os.WriteFile(a.cfgPath, raw, 0o644); werr != nil {
			return "", nil, fmt.Errorf("新配置无法生效（%v），且回滚文件失败：%w", err, werr)
		}
		if rerr := a.reload(); rerr != nil {
			return "", nil, fmt.Errorf("新配置无法生效（%v），回滚后旧配置也加载不了：%v", err, rerr)
		}
		return "", nil, badRequest("reload_failed", "新配置无法生效，已回滚：%v", err)
	}
	return newRev, cfg, nil
}

// ---------- 路由视图 ----------

// routeView = 可编辑的配置字段 + 实时观测值。
// 内嵌 RouteConfig 让它直接展平成普通路由 JSON，写接口收到的也就是这个结构。
type routeView struct {
	RouteConfig
	Live *routeLive `json:"live,omitempty"`
}

type routeLive struct {
	Requests    int64            `json:"requests_total"`
	ByStatus    map[string]int64 `json:"by_status,omitempty"`
	RateLimited int64            `json:"rate_limited_total"`
	Rejected    int64            `json:"rejected_total"`
	InFlight    int64            `json:"in_flight"`
	AvgMs       float64          `json:"avg_ms"`
	Circuit     *CBSnapshot      `json:"circuit_breaker,omitempty"`
}

// routeViews 给路由列表附上实时观测值。
// 观测值来自当前生效的路由表（按 ID 对齐），配置字段来自文件。
func (a *App) routeViews(routes []RouteConfig) []routeView {
	live := map[string]*routeLive{}
	if tbl := a.table.Load(); tbl != nil {
		for _, rt := range tbl.routes {
			s := a.metrics.Live(rt.ID)
			item := &routeLive{
				Requests:    s.Requests,
				ByStatus:    s.ByStatus,
				RateLimited: s.RateLimited,
				Rejected:    s.Rejected,
				InFlight:    s.InFlight,
				AvgMs:       s.AvgMs,
			}
			if rt.cb != nil {
				snap := rt.cb.Snapshot()
				item.Circuit = &snap
			}
			live[rt.ID] = item
		}
	}
	out := make([]routeView, 0, len(routes))
	for _, rc := range routes {
		out = append(out, routeView{RouteConfig: rc, Live: live[rc.ID]})
	}
	return out
}

// ---------- 路由 CRUD ----------

func (a *App) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	raw, cfg, err := readConfigFile(a.cfgPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("ETag", quoteETag(revisionOf(raw)))
	writeJSON(w, http.StatusOK, a.routeViews(cfg.Routes))
}

func (a *App) handleGetRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, cfg, err := readConfigFile(a.cfgPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	idx := indexRoute(cfg.Routes, id)
	if idx < 0 {
		writeErr(w, notFound(id))
		return
	}
	writeJSON(w, http.StatusOK, a.routeViews([]RouteConfig{cfg.Routes[idx]})[0])
}

func (a *App) handleCreateRoute(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var rc RouteConfig
	if err := json.Unmarshal(body, &rc); err != nil {
		writeErr(w, badRequest("invalid_route", "请求体不是合法的路由 JSON: %v", err))
		return
	}

	var newID string
	rev, out, err := a.mutate(ifMatchOf(r), func(cfg *Config) error {
		if rc.ID == "" {
			rc.ID = nextRouteID(cfg)
		}
		if indexRoute(cfg.Routes, rc.ID) >= 0 {
			return &apiError{http.StatusConflict, "duplicate_id",
				fmt.Sprintf("路由 id %q 已存在", rc.ID)}
		}
		newID = rc.ID
		cfg.Routes = append(cfg.Routes, rc)
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, a.mutationResult(rev, out, newID))
}

func (a *App) handleReplaceRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	body, err := readBody(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var rc RouteConfig
	if err := json.Unmarshal(body, &rc); err != nil {
		writeErr(w, badRequest("invalid_route", "请求体不是合法的路由 JSON: %v", err))
		return
	}
	// ID 以 URL 为准，body 里的 id 字段不作数
	rc.ID = id

	rev, out, err := a.mutate(ifMatchOf(r), func(cfg *Config) error {
		idx := indexRoute(cfg.Routes, id)
		if idx < 0 {
			return notFound(id)
		}
		cfg.Routes[idx] = rc
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a.mutationResult(rev, out, id))
}

// handlePatchRoute 做局部更新 —— 启停路由、只改限流值这类操作走它。
//
// 实现方式是把请求体反序列化到「现有的那条路由」上：encoding/json 只会覆盖
// 请求体里出现过的字段，天然就是合并语义。显式传 null 可以清掉
// rate_limit / circuit_breaker / auth / acl。
func (a *App) handlePatchRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	body, err := readBody(r)
	if err != nil {
		writeErr(w, err)
		return
	}

	rev, out, err := a.mutate(ifMatchOf(r), func(cfg *Config) error {
		idx := indexRoute(cfg.Routes, id)
		if idx < 0 {
			return notFound(id)
		}
		if err := json.Unmarshal(body, &cfg.Routes[idx]); err != nil {
			return badRequest("invalid_route", "请求体不是合法的路由 JSON: %v", err)
		}
		// ID 不允许通过 body 改，否则等于偷偷重命名，客户端按旧 ID 再也找不到
		cfg.Routes[idx].ID = id
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a.mutationResult(rev, out, id))
}

func (a *App) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rev, out, err := a.mutate(ifMatchOf(r), func(cfg *Config) error {
		idx := indexRoute(cfg.Routes, id)
		if idx < 0 {
			return notFound(id)
		}
		cfg.Routes = append(cfg.Routes[:idx], cfg.Routes[idx+1:]...)
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"revision": rev,
		"deleted":  id,
		"routes":   len(out.Routes),
		// 删掉某端口上最后一条路由后，那个端口会被自动关闭，这里能看到结果
		"ports": a.listeners.Ports(),
	})
}

// mutationResult 是写操作统一的返回体：新 revision + 该路由的最新状态 + 当前端口。
func (a *App) mutationResult(rev string, out *Config, id string) map[string]any {
	res := map[string]any{
		"revision": rev,
		"routes":   len(out.Routes),
		"ports":    a.listeners.Ports(),
	}
	if idx := indexRoute(out.Routes, id); idx >= 0 {
		res["route"] = a.routeViews([]RouteConfig{out.Routes[idx]})[0]
	}
	return res
}

// ---------- 全局配置 ----------

// configView 是 GET /_goproxy/config 的返回体。
//
// 刻意不回传 admin_token 明文、也不回传 admin_users 的 password_hash：
// 界面只需要知道「配了几个账号、都叫什么」，永远不需要密码材料。
// 少一处泄露面 —— 这个接口本身是能读到配置的，把凭据顺带带出去等于
// 一次认证读取就泄漏全部凭据。
type configView struct {
	DefaultPorts   []int    `json:"default_ports"`
	AdminAddr      string   `json:"admin_addr"`
	AdminEnabled   bool     `json:"admin_enabled"`
	AdminTokenSet  bool     `json:"admin_token_set"`
	AccessLog      bool     `json:"access_log"`
	TrustedProxies []string `json:"trusted_proxies"`
	RouteCount     int      `json:"route_count"`

	// AdminUsers 只给用户名，供界面展示「当前有哪些管理员」。
	// 密码哈希绝不出现。
	AdminUsers []string `json:"admin_users"`

	// CredentialsConfigured 报告是否至少有一种可用凭据。
	// 控制台据此在「什么都没配」时给出正确的引导，而不是让人猜。
	CredentialsConfigured bool `json:"credentials_configured"`
}

func (a *App) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	raw, cfg, err := readConfigFile(a.cfgPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("ETag", quoteETag(revisionOf(raw)))
	addr := cfg.AdminAddr
	if !cfg.adminEnabled() {
		addr = ""
	}
	names := make([]string, 0, len(cfg.AdminUsers))
	for _, u := range cfg.AdminUsers {
		names = append(names, u.Username)
	}
	writeJSON(w, http.StatusOK, configView{
		DefaultPorts:          cfg.DefaultPorts,
		AdminAddr:             addr,
		AdminEnabled:          cfg.adminEnabled(),
		AdminTokenSet:         cfg.AdminToken != "",
		AccessLog:             cfg.AccessLog,
		TrustedProxies:        cfg.TrustedProxies,
		RouteCount:            len(cfg.Routes),
		AdminUsers:            names,
		CredentialsConfigured: cfg.hasAdminCredentials(),
	})
}

type configPatch struct {
	DefaultPorts   *[]int    `json:"default_ports"`
	AccessLog      *bool     `json:"access_log"`
	TrustedProxies *[]string `json:"trusted_proxies"`
	AdminToken     *string   `json:"admin_token"`
}

func (a *App) handlePatchConfig(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeErr(w, err)
		return
	}

	// 先看有没有不该在这里改的键 —— 静默接受一个不生效的修改比直接拒绝更糟
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(body, &keys); err != nil {
		writeErr(w, badRequest("invalid_body", "请求体不是合法的 JSON 对象: %v", err))
		return
	}
	if _, ok := keys["admin_addr"]; ok {
		writeErr(w, badRequest("admin_addr_immutable",
			"admin_addr 属于启动期配置：监听套接字在进程启动时就绑定了，运行期改它不生效，"+
				"还可能把自己关在门外。请改配置文件后重启进程。"))
		return
	}
	if _, ok := keys["routes"]; ok {
		writeErr(w, badRequest("use_routes_api",
			"路由不要走这个接口，请用 /_goproxy/routes"))
		return
	}

	var p configPatch
	if err := json.Unmarshal(body, &p); err != nil {
		writeErr(w, badRequest("invalid_config", "%v", err))
		return
	}

	rev, _, err := a.mutate(ifMatchOf(r), func(cfg *Config) error {
		if p.DefaultPorts != nil {
			cfg.DefaultPorts = *p.DefaultPorts
		}
		if p.AccessLog != nil {
			cfg.AccessLog = *p.AccessLog
		}
		if p.TrustedProxies != nil {
			cfg.TrustedProxies = *p.TrustedProxies
		}
		if p.AdminToken != nil {
			cfg.AdminToken = *p.AdminToken
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"revision": rev,
		"ports":    a.listeners.Ports(),
	})
}

// ---------- 小工具 ----------

func readBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, badRequest("body_read_failed", "读取请求体失败: %v", err)
	}
	if len(b) > maxBodyBytes {
		return nil, &apiError{http.StatusRequestEntityTooLarge, "body_too_large", "请求体超过 1MiB"}
	}
	if len(b) == 0 {
		return nil, badRequest("empty_body", "请求体为空")
	}
	return b, nil
}

// ifMatchOf 取出 If-Match 里的 revision（去掉 HTTP 要求的引号）。
func ifMatchOf(r *http.Request) string { return strings.Trim(r.Header.Get("If-Match"), `"`) }

func quoteETag(rev string) string { return `"` + rev + `"` }

func indexRoute(routes []RouteConfig, id string) int {
	for i := range routes {
		if routes[i].ID == id {
			return i
		}
	}
	return -1
}

// nextRouteID 生成一个不会撞车的路由 ID。
func nextRouteID(cfg *Config) string {
	for i := 0; i < 100; i++ {
		id := "rt-" + randomHex(3)
		if indexRoute(cfg.Routes, id) < 0 {
			return id
		}
	}
	return fmt.Sprintf("rt-%d", time.Now().UnixNano())
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%06x", time.Now().UnixNano()&0xffffff)
	}
	return hex.EncodeToString(b)
}
