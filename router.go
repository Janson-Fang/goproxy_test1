package main

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Route 是一条可运行状态的路由。配置里的 RouteConfig 经过解析、
// 绑定后端地址与限流器之后，变成 Route 放进路由表。
type Route struct {
	ID           string
	Name         string
	ListenPort   int
	Host         string
	PathPrefix   string
	Target       string
	StripPrefix  bool
	PreserveHost bool

	targetURL *url.URL
	proxy     *httputil.ReverseProxy
	limiter   *IPLimiter
}

// RouteTable 是不可变的路由快照，用 atomic.Pointer 整体替换实现热更新。
// 请求路径只读它，全程不加锁、不查配置源。
type RouteTable struct {
	routes []*Route
	// byPort 每个监听端口一份索引。构建时已经把 listen_port=0 的
	// 全局路由合并进每个端口的 global 桶，所以这里一定能查到。
	byPort map[int]*portIndex
}

type portIndex struct {
	// specific 只匹配 listen_port 恰好等于该端口的路由（优先）
	specific *hostIndex
	// global 匹配 listen_port=0 的路由（兜底）
	global *hostIndex
}

type hostIndex struct {
	exact     map[string][]*Route
	wildcards []wildcardEntry
	any       []*Route
}

type wildcardEntry struct {
	suffix string // "*.example.com" 存为 "example.com"
	routes []*Route
}

// Match 三级匹配：端口 → host → path。
func (t *RouteTable) Match(port int, hostPort, path string) *Route {
	pi := t.byPort[port]
	if pi == nil {
		return nil
	}
	host := normalizeHost(hostPort)
	if r := pi.specific.match(host, path); r != nil {
		return r
	}
	return pi.global.match(host, path)
}

func (h *hostIndex) match(host, path string) *Route {
	if h == nil {
		return nil
	}
	if host != "" {
		if rs, ok := h.exact[host]; ok {
			if r := pick(rs, path); r != nil {
				return r
			}
		}
		for _, w := range h.wildcards {
			// *.example.com 匹配 a.example.com，但不匹配 example.com 本身
			if strings.HasSuffix(host, "."+w.suffix) {
				if r := pick(w.routes, path); r != nil {
					return r
				}
			}
		}
	}
	return pick(h.any, path)
}

// pick 在已按「前缀长度降序」排好的路由里，取第一个前缀命中的。
func pick(routes []*Route, path string) *Route {
	for _, r := range routes {
		if pathMatch(path, r.PathPrefix) {
			return r
		}
	}
	return nil
}

// pathMatch 是「按路径分段」的前缀匹配：/api 能匹配 /api 和 /api/x，
// 但不能匹配 /apixxx —— 这是常见的配置踩坑点。
func pathMatch(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	if prefix == "/" || len(path) == len(prefix) {
		return true
	}
	return path[len(prefix)] == '/'
}

// normalizeHost 去掉 Host 头里的端口，并统一小写。
func normalizeHost(h string) string {
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return strings.ToLower(h)
}

// buildTable 从配置构建新的路由表。
// old 传入是为了复用限流器实例 —— 否则每次改配置都会把限流计数清零，
// 客户端改一次配置就能绕过限流。
func buildTable(cfg *Config, old *RouteTable, base *http.Transport) (*RouteTable, error) {
	oldLimiters := make(map[string]*IPLimiter)
	if old != nil {
		for _, r := range old.routes {
			if r.limiter != nil {
				oldLimiters[r.ID] = r.limiter
			}
		}
	}

	t := &RouteTable{byPort: make(map[int]*portIndex)}
	var routes []*Route

	for _, rc := range cfg.Routes {
		if !rc.enabled() {
			continue
		}
		u, err := url.Parse(rc.Target)
		if err != nil {
			return nil, err
		}
		r := &Route{
			ID:           rc.ID,
			Name:         rc.Name,
			ListenPort:   rc.ListenPort,
			Host:         strings.ToLower(rc.Host),
			PathPrefix:   rc.PathPrefix,
			Target:       rc.Target,
			StripPrefix:  rc.StripPrefix,
			PreserveHost: rc.PreserveHost,
			targetURL:    u,
		}

		tr := base
		if rc.TimeoutMs > 0 {
			tr = base.Clone()
			tr.ResponseHeaderTimeout = time.Duration(rc.TimeoutMs) * time.Millisecond
		}
		r.proxy = newReverseProxy(r, tr)

		if rl := rc.RateLimit; rl != nil && rl.RPS > 0 {
			burst := rl.Burst
			if burst <= 0 {
				burst = rl.RPS * 2
			}
			if l, ok := oldLimiters[r.ID]; ok && l.rate == rl.RPS && l.burst == burst {
				r.limiter = l // 复用，保留已有计数
			} else {
				r.limiter = NewIPLimiter(rl.RPS, burst, rl.Scope == "global")
			}
		}

		routes = append(routes, r)
	}

	t.routes = routes

	// 先建端口索引
	ports := cfg.allListenPorts()
	for _, p := range ports {
		t.byPort[p] = &portIndex{
			specific: newHostIndex(),
			global:   newHostIndex(),
		}
	}
	// 兜底：配置里可能声明了端口但被过滤掉，确保每个路由的端口都有索引
	for _, r := range routes {
		if r.ListenPort > 0 {
			if _, ok := t.byPort[r.ListenPort]; !ok {
				t.byPort[r.ListenPort] = &portIndex{
					specific: newHostIndex(),
					global:   newHostIndex(),
				}
			}
		}
	}

	for _, r := range routes {
		if r.ListenPort > 0 {
			t.byPort[r.ListenPort].specific.add(r)
			continue
		}
		// listen_port=0：挂到所有端口的 global 桶上
		for _, pi := range t.byPort {
			pi.global.add(r)
		}
	}

	for _, pi := range t.byPort {
		pi.specific.finish()
		pi.global.finish()
	}

	return t, nil
}

func newHostIndex() *hostIndex {
	return &hostIndex{exact: make(map[string][]*Route)}
}

func (h *hostIndex) add(r *Route) {
	switch {
	case strings.HasPrefix(r.Host, "*."):
		h.wildcards = append(h.wildcards, wildcardEntry{suffix: r.Host[2:], routes: []*Route{r}})
	case r.Host == "":
		h.any = append(h.any, r)
	default:
		h.exact[r.Host] = append(h.exact[r.Host], r)
	}
}

// finish 排序并合并同 host 的通配分组，让匹配顺序确定下来。
func (h *hostIndex) finish() {
	// 合并同后缀的通配条目
	merged := make(map[string][]*Route)
	var order []string
	for _, w := range h.wildcards {
		if _, ok := merged[w.suffix]; !ok {
			order = append(order, w.suffix)
		}
		merged[w.suffix] = append(merged[w.suffix], w.routes...)
	}
	// 后缀越长越具体，优先匹配
	sort.Slice(order, func(i, j int) bool { return len(order[i]) > len(order[j]) })
	h.wildcards = h.wildcards[:0]
	for _, s := range order {
		sortRoutes(merged[s])
		h.wildcards = append(h.wildcards, wildcardEntry{suffix: s, routes: merged[s]})
	}
	for k := range h.exact {
		sortRoutes(h.exact[k])
	}
	sortRoutes(h.any)
}

// sortRoutes 按路径前缀长度降序 —— 越长的前缀越具体，越先匹配。
func sortRoutes(rs []*Route) {
	sort.SliceStable(rs, func(i, j int) bool {
		return len(rs[i].PathPrefix) > len(rs[j].PathPrefix)
	})
}

// ListenPorts 返回当前需要监听的端口列表，供 ListenerManager 做 diff。
func (t *RouteTable) ListenPorts() []int {
	ports := make([]int, 0, len(t.byPort))
	for p := range t.byPort {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}
