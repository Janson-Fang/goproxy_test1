package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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

// ---------- 写事务 ----------

// mutate 执行「读配置 → 改 → 校验 → 原子写回 → 热重载」，全程串行。
//
// 事务的源永远是**库里的当前内容**，而不是内存里的路由表 ——
// 这样即使有人绕过控制台直接改过库（命令行导入），界面的一次保存也是基于
// 那份最新内容做的增量修改，而不是把它悄悄覆盖掉。
//
// ifMatch 非空时要求与当前 revision 一致，用来挡住两个页签互相覆盖（lost update）。
// 返回写回后的 revision 与最终生效的配置。
//
// r 只用于自锁检查（guardSelfLockout）：判断这次改动会不会把发起者关在门外。
// 传 nil 表示跳过该检查（测试里构造配置时用）。
func (a *App) mutate(r *http.Request, ifMatch string, fn func(cfg *Config) error) (rev string, out *Config, err error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()

	raw, cfg, err := parseConfigFile(a.configDB)
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

	_, newRev, err := saveConfig(a.configDB, cfg)
	if err != nil {
		return "", nil, err
	}

	if err := a.reload(); err != nil {
		// 已经写库了才发现在运行时加载不了 —— 立刻回滚，别留下一个坏配置。
		// 回滚写的是保存前那份内容（raw），而不是「撤销刚才那次写入」：
		// 按内容回滚是幂等的，也不必依赖「期间没有别的写入」这个假设。
		if werr := restoreConfig(a.configDB, raw); werr != nil {
			return "", nil, fmt.Errorf("新配置无法生效（%v），且回滚失败：%w", err, werr)
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
	raw, cfg, err := readConfigFile(a.configDB)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("ETag", quoteETag(revisionOf(raw)))
	writeJSON(w, http.StatusOK, a.routeViews(cfg.Routes))
}

func (a *App) handleGetRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, cfg, err := readConfigFile(a.configDB)
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
	_, cfg, err := readConfigFile(a.configDB)
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
	raw, cfg, err := readConfigFile(a.configDB)
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
				"还可能把自己关在门外。"+escapeHint))
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
