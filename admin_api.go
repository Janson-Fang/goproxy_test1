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

// writeErr 把错误翻译成响应。
func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeJSON(w, ae.status, map[string]string{"error": ae.code, "message": ae.msg})
		return
	}
	slog.Error("管理接口内部错误", "err", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal", "message": err.Error()})
}

// ---------- 认证 ----------

// adminGuard 包住整个管理端 mux。
//
//   - 来自回环地址的请求直接放行（默认 admin_addr 就是 127.0.0.1，行为不变）
//   - 其余请求必须带 Authorization: Bearer <admin_token>
//
// 判断来源只用 RemoteAddr，绝不用 X-Forwarded-For —— XFF 是客户端随手就能写的头，
// 拿它判断「是不是本机」等于把认证决定权交给攻击者。
func (a *App) adminGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLoopbackAddr(r.RemoteAddr) {
			next.ServeHTTP(w, r)
			return
		}

		a.mu.Lock()
		token := a.adminToken
		a.mu.Unlock()

		if token == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "admin_token_not_set",
				"message": "管理端口正在监听非回环地址，但配置里没有 admin_token，" +
					"已拒绝所有外部请求。请在 config.json 里设置 admin_token 后重载，" +
					"或把 admin_addr 改回 127.0.0.1 只允许本机访问。",
			})
			return
		}

		got, ok := bearerToken(r)
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="goproxy admin"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":   "unauthorized",
				"message": "需要 Authorization: Bearer <admin_token>",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
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
// 刻意不回传 admin_token 明文：界面从来不需要它，少一处泄露面。
type configView struct {
	DefaultPorts   []int    `json:"default_ports"`
	AdminAddr      string   `json:"admin_addr"`
	AdminEnabled   bool     `json:"admin_enabled"`
	AdminTokenSet  bool     `json:"admin_token_set"`
	AccessLog      bool     `json:"access_log"`
	TrustedProxies []string `json:"trusted_proxies"`
	RouteCount     int      `json:"route_count"`
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
	writeJSON(w, http.StatusOK, configView{
		DefaultPorts:   cfg.DefaultPorts,
		AdminAddr:      addr,
		AdminEnabled:   cfg.adminEnabled(),
		AdminTokenSet:  cfg.AdminToken != "",
		AccessLog:      cfg.AccessLog,
		TrustedProxies: cfg.TrustedProxies,
		RouteCount:     len(cfg.Routes),
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
