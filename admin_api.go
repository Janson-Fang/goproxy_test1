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

// loopbackNets 返回回环网段。
//
// 单独列出来是给 consoleClientIPs 用的：判断「本进程自己的代理」这一跳时，
// 回环当然可信，但用户配置的 trusted_proxies 里通常不会写 127.0.0.0/8
// （那是给外部反代准备的），所以不能指望它。
func loopbackNets() []*net.IPNet {
	_, v4, _ := net.ParseCIDR("127.0.0.0/8")
	_, v6, _ := net.ParseCIDR("::1/128")
	return []*net.IPNet{v4, v6}
}

// consoleClientIPs 列出「正在改配置的这个请求」可能对应的客户端地址。
//
// 为什么要列多个：控制台有两种到达方式，看到的来源 IP 不一样。
//
//	① 直连管理端口：RemoteAddr 就是发起者。
//	② 经自己的路由发布出去（比如把管理端口挂到公网 32000 上）：到达管理端口
//	   这一跳来自本机反向代理，RemoteAddr 是 127.0.0.1；发起者的真实地址在
//	   X-Forwarded-For 里。
//
// 情况 ② 里采信 X-Forwarded-For 是安全的：viaOwnProxy 为真说明这个头是本进程
// 的代理写上去的（proxy.go 里用 Set 无条件覆盖，外部伪造的值活不到这里，
// admin_api_test.go 有专门的用例守着这一点）。
//
// 实现上没有自己手写「取 XFF 最后一段」，而是把回环并进可信网段后重新调用
// clientIP —— 复用那套「从右往左跳过可信跳数」的逻辑，免得两处实现悄悄走样。
//
// 只要其中任何一个地址会被新规则挡掉，这次保存就可能让自己失联，所以全都查。
func (a *App) consoleClientIPs(r *http.Request) []string {
	trusted := a.trustedNets()

	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	add(clientIP(r, trusted))
	if viaOwnProxy(r) {
		// 复制一份再追加：trustedNets() 返回的是共享切片，直接 append 有
		// 写进它底层数组的风险（那时会静默改掉全局的可信网段）。
		withLoopback := append(append([]*net.IPNet(nil), trusted...), loopbackNets()...)
		add(clientIP(r, withLoopback))
	}
	return out
}

// guardSelfLockout 检查新配置会不会把「正在改配置的这个人」挡在外面。
//
// 为什么需要它：管理端口也在全局黑名单的管辖范围内（这是明确的设计选择，
// 见 config.go 的 GlobalIPDeny 注释），而控制台正是改配置的地方。于是在控制台
// 上加一条写错的网段，就能在点下保存的瞬间让自己失去控制台 —— 只能登机器
// 改文件重启。这个组合必须有人兜住。
//
// 这是**护栏，不是权限**：它挡的是无心之失，不是禁止这么配。真要封掉自己
// 所在的网段，改配置文件后重启即可 —— 那条路永远留着，也不该被这里限制。
//
// 只检查全局黑名单，不检查路由级名单：路由名单的锁定范围限于那条路由所挂的
// 端口，界面上 target 和端口都摆在同一屏，属于「看得见」的风险；而全局名单
// 会静默作用于所有入口，这才是容易误判的那个。路由级的风险交给前端的
// 命中测试工具提示。
func (a *App) guardSelfLockout(r *http.Request, next *Config) error {
	global, err := NewIPList(next.GlobalIPDeny)
	if err != nil {
		return nil // 非法配置由 validate 负责报错，不在这里抢答
	}
	if global == nil {
		return nil
	}
	ips := a.consoleClientIPs(r)
	for _, ip := range ips {
		m, ok := global.Match(net.ParseIP(ip))
		if !ok {
			continue
		}
		return &apiError{http.StatusConflict, "self_lockout", fmt.Sprintf(
			"这条规则会把你关在门外，已拒绝保存：新的 global_ip_deny 命中 %s（来自规则 %s%s），"+
				"而它同样作用于管理端口 —— 保存生效之后，你现在用的这个控制台就打不开了。\n\n"+
				"如果确实要封这个网段：改配置文件后重启进程即可，那条路不受此检查限制。",
			ip, m.Rule, noteSuffix(m.Note))}
	}
	return nil
}

// renameListRefs 把路由里的名单引用按 old→new 改写一遍。
//
// 为什么改名要由服务端改写引用、而不是让控制台自己两步走完：
// 先删旧名再加新名会让所有引用在中间态里悬空，而悬空引用是硬错误
// （validate 会拦），保存根本提交不下去 —— 用户会看到一个无法完成的操作。
// 一次请求里「改名单名 + 改引用」才是原子的。
//
// 只做一次映射、不跟随链：{"A":"B","B":"C"} 会把引用 A 变成 B（而不是 C）。
// 控制台一次改名只产生一个键值对，链式改名是手工编辑配置文件才可能出现的情况，
// 与其猜用户想要哪一种，不如保持「一次映射」这个可预测的语义。
func renameListRefs(routes []RouteConfig, renames map[string]string) {
	for i := range routes {
		acl := routes[i].ACL
		if acl == nil {
			continue
		}
		for j, ref := range acl.Lists {
			name := strings.TrimSpace(ref)
			to := strings.TrimSpace(renames[name])
			if to == "" {
				continue
			}
			acl.Lists[j] = to
		}
	}
}

// guardListInUse 拦住「删掉一份还被路由引用的名单」。
//
// 不这么做的话，删除会一路走到 validate 才被拦下，报的是「某条路由引用了
// 不存在的名单」—— 用户看到的是「引用写错了」，而真正发生的是一次删除动作，
// 两者的下一步操作完全不同（一个去改引用，一个去解除引用）。所以在这里
// 用 409 list_in_use 明确说清是删除被挡了，并把在用的路由列出来。
func guardListInUse(routes []RouteConfig, old, next []IPListDef) error {
	keep := make(map[string]bool, len(next))
	for _, d := range next {
		keep[strings.TrimSpace(d.Name)] = true
	}
	usage := listUsage(routes)

	// 按 old 的顺序检查，报错结果才稳定（map 遍历顺序是随机的，
	// 一次删两份被引用的名单时，报哪一份不该每次都变）。
	for _, d := range old {
		name := strings.TrimSpace(d.Name)
		if name == "" || keep[name] {
			continue
		}
		if ids := usage[name]; len(ids) > 0 {
			return &apiError{http.StatusConflict, "list_in_use", fmt.Sprintf(
				"名单 %q 还被这些路由引用着，不能删除：%s。\n\n"+
					"要删它，先去那些路由里取消勾选；如果只是想改个名字，直接用「改名」——"+
					"改名会把所有引用一起改写，是安全的。",
				name, strings.Join(ids, "、"))}
		}
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
//
// r 只用于自锁检查（guardSelfLockout）：判断这次改动会不会把发起者关在门外。
// 传 nil 表示跳过该检查（测试里构造配置时用）。
func (a *App) mutate(r *http.Request, ifMatch string, fn func(cfg *Config) error) (rev string, out *Config, err error) {
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

	// 落盘前的最后一道自检：这次改动会不会把发起者自己关在门外。
	//
	// 放在 mutate 里而不是各个处理器里，是为了让**所有**配置写入都必经此路 ——
	// 将来新增一个写接口时不可能忘掉它。全局黑名单是唯一能让控制台彻底不可达
	// 的配置，而控制台恰恰就是改配置的地方，这个组合必须有人兜住。
	if r != nil {
		if err := a.guardSelfLockout(r, cfg); err != nil {
			return "", nil, err
		}
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
	rev, out, err := a.mutate(r, ifMatchOf(r), func(cfg *Config) error {
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

	rev, out, err := a.mutate(r, ifMatchOf(r), func(cfg *Config) error {
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

	rev, out, err := a.mutate(r, ifMatchOf(r), func(cfg *Config) error {
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
	rev, out, err := a.mutate(r, ifMatchOf(r), func(cfg *Config) error {
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

// ---------- 命中测试 ----------

// handleACLTest 是「命中测试」：拿一个地址跑一遍三层名单，回答「它会被哪条
// 规则拦下；如果拦不下，又是因为什么」。
//
// 为什么值得单独做一个接口：三层名单有明确的先后顺序，光盯着配置列表很难在
// 脑子里模拟出结果 —— 尤其是「白名单里写了它，但全局黑名单也写了它」这种。
// 一次误判就是线上事故（要么放进了不该放的，要么把办公网整个封掉）。
// 让人在按保存之前先把待封的地址试一遍，比写十页文档管用。
//
// 只读接口：不改任何状态，也不依赖写权限。
//
// 不填 ip 即「测我自己」，见下面 self 的说明。
func (a *App) handleACLTest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP      string `json:"ip"`
		RouteID string `json:"route_id"`
	}

	// 同时支持 GET 查询串与 POST JSON：前者方便 curl 与脚本，
	// 后者是控制台用的。两条路径解析到同一个结构，不许各写一套逻辑。
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		in.IP, in.RouteID = q.Get("ip"), q.Get("route_id")
	case http.MethodPost:
		body, err := readBody(r)
		if err != nil {
			writeErr(w, err)
			return
		}
		if err := json.Unmarshal(body, &in); err != nil {
			writeErr(w, badRequest("invalid_body", "%v", err))
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		writeErr(w, &apiError{http.StatusMethodNotAllowed, "method_not_allowed", "请用 GET 或 POST"})
		return
	}

	ip := strings.TrimSpace(in.IP)
	self := false
	if ip == "" {
		// 不填 = 「测我自己」。取 consoleClientIPs 的最后一个：经自己的代理
		// 进来时它按「本机代理、真实来源」的顺序排列，后者才是使用者本人。
		ips := a.consoleClientIPs(r)
		if len(ips) == 0 {
			writeErr(w, badRequest("ip_required", "无法确定你的来源 IP，请显式填写 ip"))
			return
		}
		ip = ips[len(ips)-1]
		self = true
	}
	if net.ParseIP(ip) == nil {
		writeErr(w, badRequest("invalid_ip", "%q 不是合法的 IP 地址", ip))
		return
	}

	// 名单读的是**磁盘上的配置**，不是内存里已生效的路由表。
	// 命中测试要回答的是「保存之后会怎样」，所以必须和写路径看同一份源。
	_, cfg, err := readConfigFile(a.cfgPath)
	if err != nil {
		writeErr(w, err)
		return
	}

	// 名单库先建起来。路由的引用要拿它来展开，构建失败说明配置本身坏了，
	// 这时候报「名单库有问题」比报「某条路由有问题」更贴近事实。
	listSet, err := NewIPListSet(cfg.IPLists)
	if err != nil {
		writeErr(w, badRequest("invalid_config", "ip_lists 配置有问题：%v", err))
		return
	}

	var routeACL *ACL
	routeName := ""
	if id := strings.TrimSpace(in.RouteID); id != "" {
		i := indexRoute(cfg.Routes, id)
		if i < 0 {
			writeErr(w, notFound(id))
			return
		}
		if routeACL, err = resolveRouteACL(listSet, cfg.Routes[i]); err != nil {
			writeErr(w, badRequest("invalid_config", "路由 %s 的名单引用有问题：%v", id, err))
			return
		}
		routeName = cfg.Routes[i].Name
	}

	global, err := NewIPList(cfg.GlobalIPDeny)
	if err != nil {
		writeErr(w, badRequest("invalid_config", "global_ip_deny 配置有问题：%v", err))
		return
	}

	dec := decideIP(global, routeACL, ip, true)
	dec.RouteID = strings.TrimSpace(in.RouteID)
	writeJSON(w, http.StatusOK, map[string]any{
		"decision":   dec,
		"self":       self,
		"route_name": routeName,
	})
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

	// GlobalIPDeny 是全局黑名单的原始配置，供配置页展示与编辑。
	// 它不含任何秘密（就是把配置文件里那一栏原样回显），所以直接给出去。
	GlobalIPDeny []IPRule `json:"global_ip_deny"`

	// IPLists 是可复用的命名地址列表库，供「IP 名单」页签编辑。
	// 路由表单也要用它来列出「可以勾选哪些名单」，所以这个字段必须下发。
	//
	// 这是**原始**形态（条目可能是字符串简写），前端统一走 normalizeIPRules 收口。
	IPLists []IPListDef `json:"ip_lists"`

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
		GlobalIPDeny:          cfg.GlobalIPDeny,
		IPLists:               cfg.IPLists,
	})
}

type configPatch struct {
	DefaultPorts   *[]int    `json:"default_ports"`
	AccessLog      *bool     `json:"access_log"`
	TrustedProxies *[]string `json:"trusted_proxies"`
	AdminToken     *string   `json:"admin_token"`
	// GlobalIPDeny 用指针是为了区分「没提交这个字段」和「提交了一个空数组」：
	// 前者保持原样，后者表示清空全局黑名单。
	GlobalIPDeny *[]IPRule `json:"global_ip_deny"`

	// IPLists 同理用指针：提交空数组表示「一份名单都不要了」。
	//
	// 这份是全量替换（不是逐个合并）。控制台总是把当前所有名单一起提交，
	// 所以不需要按名字做增量 —— 那样反而要处理「改名的名单算新的还是旧的」这种
	// 无法从数据本身判断的问题。
	IPLists *[]IPListDef `json:"ip_lists"`

	// IPListRenames 声明「哪份名单改了名」：{"旧名": "新名"}。
	//
	// 有了它，改名才能和引用改写合成一次原子写。没有它的话，「先删旧名再加新名」
	// 这一步会让所有引用在中间态里悬空，而悬空引用是硬错误，保存根本提交不下去。
	//
	// 只在**改名**时需要；新增和删除都不用它。
	IPListRenames map[string]string `json:"ip_list_renames"`
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

	rev, _, err := a.mutate(r, ifMatchOf(r), func(cfg *Config) error {
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
		if p.GlobalIPDeny != nil {
			cfg.GlobalIPDeny = *p.GlobalIPDeny
		}
		// 改名先只作用于**路由引用**；名单本身的名字由下面 IPLists 的全量替换决定。
		// 顺序不能反：先把引用搬到新名字上，再换掉名单表，中间态才是自洽的。
		if len(p.IPListRenames) > 0 {
			renameListRefs(cfg.Routes, p.IPListRenames)
		}
		if p.IPLists != nil {
			if err := guardListInUse(cfg.Routes, cfg.IPLists, *p.IPLists); err != nil {
				return err
			}
			cfg.IPLists = *p.IPLists
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
