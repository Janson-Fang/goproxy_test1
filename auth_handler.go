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
	"strconv"
	"strings"
	"time"
)

// 认证与登录：登录/登出/会话状态、管理接口的鉴权闸门（adminGuard）、
// 令牌识别、自锁护栏（guardSelfLockout）与名单改名/删除护栏。
// 从 admin_api.go 拆出，纯机械移动，逻辑未动。
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
				"message": "服务端还没有配置任何管理凭据。请配置 " +
					"admin_users（用户名 + bcrypt 密码哈希，推荐）或 admin_token。" +
					"配置源是 SQLite 数据库，用命令行导入：goproxy -config-export 导出一份、" +
					"填好凭据后再 -config-import 导回并重启。",
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
			a.rememberConsoleSource(r)
			next.ServeHTTP(w, r)
			return

		case viaBearer:
			// Bearer 不随请求自动携带，本来就没有 CSRF 面，
			// 所以这里**不做**同源校验 —— 给 curl 增加负担没有收益。
			a.rememberConsoleSource(r)
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
					"请用命令行导入一份带凭据的配置：goproxy -config-export 导出、" +
					"填好 admin_users（用 bcrypt 的 password_hash，推荐）再 -config-import 导回并重启。",
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

// escapeHint 是「护栏挡住了你，但这条配置确实要这么写」时给出的退路。
//
// v0.9.0 之前这里写的是「改配置文件后重启」—— 那时配置就是一份 config.json，
// 手工编辑它是真实可走的一条路。现在配置的真源是 SQLite 库，没有可编辑的
// 文本文件了，准确的退路是命令行导出 / 导入：导出一份 JSON、改完导回去、
// 重启生效。**不只是文字问题**：让人去找一个不存在的文件夹，等于没给退路。
//
// 前端（global_ip_deny 的护栏提示）用的是同一句话，改动时要一起改。
const escapeHint = "如果确实要这么配：用 goproxy -config-export 导出一份 JSON、" +
	"改完之后再用 goproxy -config-import 导回并重启进程 —— 那条路不受此检查限制。"

// guardSelfLockout 检查新配置会不会把「正在改配置的这个人」挡在外面。
//
// 为什么需要它：管理端口也在全局黑名单的管辖范围内（这是明确的设计选择，
// 见 config.go 的 GlobalIPDeny 注释），而控制台正是改配置的地方。于是在控制台
// 上加一条写错的网段，就能在点下保存的瞬间让自己失去控制台 —— 只能登机器
// 改配置。这个组合必须有人兜住。
//
// 这是**护栏，不是权限**：它挡的是无心之失，不是禁止这么配。真要封掉自己
// 所在的网段，走命令行导入即可 —— 那条路永远留着，也不该被这里限制。
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
				"%s",
			ip, m.Rule, noteSuffix(m.Note), escapeHint)}
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
