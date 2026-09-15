package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var durBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// seriesSize 是每秒采样保留的点数（300 点 = 最近 5 分钟）。
//
// 为什么在服务端存历史，而不是让前端每次刷新自己攒：
// 管理台一打开就该有曲线，而不是空白五分钟慢慢长出来。
// 300 个点不到 10KB，代价可以忽略。
const seriesSize = 300

type reqKey struct {
	route  string
	status int
}

// seriesPoint 是某一秒的增量，前端直接拿来画 QPS / 错误率曲线。
type seriesPoint struct {
	T        int64 `json:"t"` // Unix 秒
	Requests int64 `json:"requests"`
	Errors   int64 `json:"errors"`  // 5xx
	Blocked  int64 `json:"blocked"` // 被限流 + 被拒绝（ACL/熔断/认证）
}

// totals 是累计值的原始快照，用于算相邻两次采样之间的增量。
type totals struct {
	requests int64
	errors   int64
	blocked  int64
}

// Metrics 用一把互斥锁保护的内存计数器，按 Prometheus 文本格式导出。
type Metrics struct {
	mu       sync.Mutex
	start    time.Time
	reqs     map[reqKey]int64
	limited  map[string]int64
	inFly    map[string]int64
	sum      map[string]float64
	count    map[string]int64
	buckets  map[string][]int64
	rejected map[string]int64 // route|reason
	cbState  map[string]int
	cbOpened map[string]int64
	cbReject map[string]int64

	reloadTotal int64
	routeCount  int64

	// series 是每秒采样环，seriesAt 是下一个写入位置，seriesN 是已填充点数
	series   []seriesPoint
	seriesAt int
	seriesN  int
	last     totals
}

func NewMetrics() *Metrics {
	return &Metrics{
		start:    time.Now(),
		reqs:     make(map[reqKey]int64),
		limited:  make(map[string]int64),
		inFly:    make(map[string]int64),
		sum:      make(map[string]float64),
		count:    make(map[string]int64),
		buckets:  make(map[string][]int64),
		rejected: make(map[string]int64),
		cbState:  make(map[string]int),
		cbOpened: make(map[string]int64),
		cbReject: make(map[string]int64),
		series:   make([]seriesPoint, seriesSize),
	}
}

// StartedAt 返回进程启动（准确说是指标对象创建）时间。
func (m *Metrics) StartedAt() time.Time { return m.start }

// UptimeSeconds 返回运行时长。start 构造后不再改动，不需要加锁。
func (m *Metrics) UptimeSeconds() int64 { return int64(time.Since(m.start).Seconds()) }

// ReloadTotal 返回累计配置重载次数。
func (m *Metrics) ReloadTotal() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reloadTotal
}

// RouteCount 返回当前生效的路由数。
func (m *Metrics) RouteCount() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.routeCount
}

func (m *Metrics) IncRequest(route string, status int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reqs[reqKey{route, status}]++
}

func (m *Metrics) IncRateLimited(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.limited[route]++
}

// IncRejected 记录被 ACL / 熔断 / 认证挡掉的请求
func (m *Metrics) IncRejected(route, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rejected[rejectKey{route, reason}.encode()]++
}

type rejectKey struct {
	route  string
	reason string
}

func (k rejectKey) encode() string { return k.route + "|" + k.reason }

// SetCircuitStates 定期同步熔断器状态（0=closed 1=open 2=half_open）
func (m *Metrics) SetCircuitStates(states map[string]int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cbState = states
}

func (m *Metrics) SetCBStats(route string, opened, rejected int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cbOpened[route] = opened
	m.cbReject[route] = rejected
}

func (m *Metrics) IncInFlight(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inFly[route]++
}

func (m *Metrics) DecInFlight(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inFly[route]--
}

func (m *Metrics) Observe(route string, seconds float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sum[route] += seconds
	m.count[route]++
	b := m.buckets[route]
	if b == nil {
		b = make([]int64, len(durBuckets))
		m.buckets[route] = b
	}
	for i, ub := range durBuckets {
		if seconds <= ub {
			b[i]++
		}
	}
}

func (m *Metrics) SetRouteCount(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routeCount = int64(n)
}

func (m *Metrics) IncReload() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloadTotal++
}

// RouteLive 是单条路由的实时观测值快照。
type RouteLive struct {
	Requests    int64            `json:"requests_total"`
	ByStatus    map[string]int64 `json:"by_status,omitempty"`
	RateLimited int64            `json:"rate_limited_total"`
	Rejected    int64            `json:"rejected_total"`
	InFlight    int64            `json:"in_flight"`
	AvgMs       float64          `json:"avg_ms"`
}

// Live 汇总单条路由的观测值。route 传空串拿到的是「未匹配任何路由」的汇总。
func (m *Metrics) Live(route string) RouteLive {
	m.mu.Lock()
	defer m.mu.Unlock()

	lv := RouteLive{
		InFlight:    m.inFly[route],
		RateLimited: m.limited[route],
	}
	for k, v := range m.reqs {
		if k.route != route {
			continue
		}
		lv.Requests += v
		if lv.ByStatus == nil {
			lv.ByStatus = make(map[string]int64, 4)
		}
		lv.ByStatus[strconv.Itoa(k.status)] = v
	}
	prefix := route + "|"
	for k, v := range m.rejected {
		if strings.HasPrefix(k, prefix) {
			lv.Rejected += v
		}
	}
	if n := m.count[route]; n > 0 {
		lv.AvgMs = m.sum[route] / float64(n) * 1000
	}
	return lv
}

// Summary 是全局累计值的汇总，管理台的指标卡片直接用。
type Summary struct {
	Requests    int64            `json:"requests_total"`
	ByStatus    map[string]int64 `json:"by_status"`
	Unmatched   int64            `json:"unmatched_total"`
	InFlight    int64            `json:"in_flight"`
	RateLimited int64            `json:"rate_limited_total"`
	Rejected    int64            `json:"rejected_total"`
	AvgMs       float64          `json:"avg_ms"`
	P95Ms       float64          `json:"p95_ms"`
	ErrorRate   float64          `json:"error_rate"`
}

// Global 汇总所有路由的观测值。
//
// 单条路由的 Live() 不够用：管理台要的是「整个代理现在什么状况」，
// 而全局视图没法靠前端把几十条路由的 Live 加起来 —— 未匹配路由的请求
// （route=""）不在任何一条路由里，会被漏掉，而那恰恰是最该看到的信号。
func (m *Metrics) Global() Summary {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := Summary{ByStatus: make(map[string]int64, 8)}
	for k, v := range m.reqs {
		s.Requests += v
		s.ByStatus[strconv.Itoa(k.status)] += v
		if k.route == "" {
			s.Unmatched += v
		}
	}
	for _, v := range m.limited {
		s.RateLimited += v
	}
	for _, v := range m.rejected {
		s.Rejected += v
	}
	for _, v := range m.inFly {
		s.InFlight += v
	}

	// 直方图桶在 Observe 里是累计计数的（dur <= ub 就 +1），
	// 所以跨路由合并只需要逐位相加，不必再算前缀和。
	var merged []int64
	var sum float64
	var n int64
	for r, c := range m.count {
		sum += m.sum[r]
		n += c
		b := m.buckets[r]
		if merged == nil {
			merged = make([]int64, len(durBuckets))
		}
		for i := range merged {
			if i < len(b) {
				merged[i] += b[i]
			}
		}
	}
	if n > 0 {
		s.AvgMs = sum / float64(n) * 1000
		s.P95Ms = quantileFromBuckets(merged, n, 95)
	}
	if s.Requests > 0 {
		var errs int64
		for code, v := range s.ByStatus {
			if len(code) == 3 && code[0] == '5' {
				errs += v
			}
		}
		s.ErrorRate = float64(errs) / float64(s.Requests)
	}
	return s
}

// quantileFromBuckets 从直方图里取分位数的上界（单位毫秒）。
//
// buckets[i] 已经是累计值（「耗时 <= durBuckets[i] 的请求数」），
// 所以这里**只能直接比较，不能再累加** —— 累加一次就把两个桶的空隙
// 算成了样本，p95 会系统性偏小（实测 25ms 被算成 10ms）。
func quantileFromBuckets(buckets []int64, total int64, pct int) float64 {
	if total <= 0 || len(buckets) == 0 {
		return 0
	}
	// 向上取整，避免整除后落到前一个桶
	target := (total*int64(pct) + 99) / 100
	for i, c := range buckets {
		if c >= target {
			return durBuckets[i] * 1000
		}
	}
	// 最后一个桶都没凑够（样本统计与实际不一致），报最大桶上界即「>10s」
	return durBuckets[len(durBuckets)-1] * 1000
}

// Sample 记录一个采样点。由 sampleLoop 每秒调用一次。
func (m *Metrics) Sample(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cur := m.totalsLocked()
	m.series[m.seriesAt] = seriesPoint{
		T:        now.Unix(),
		Requests: cur.requests - m.last.requests,
		Errors:   cur.errors - m.last.errors,
		Blocked:  cur.blocked - m.last.blocked,
	}
	m.last = cur
	m.seriesAt = (m.seriesAt + 1) % len(m.series)
	if m.seriesN < len(m.series) {
		m.seriesN++
	}
}

// SeriesPoints 按时间从旧到新返回已采集的采样点。
func (m *Metrics) SeriesPoints() []seriesPoint {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]seriesPoint, 0, m.seriesN)
	start := (m.seriesAt - m.seriesN + len(m.series)) % len(m.series)
	for i := 0; i < m.seriesN; i++ {
		out = append(out, m.series[(start+i)%len(m.series)])
	}
	return out
}

// totalsLocked 汇总累计值。调用方必须已持有 m.mu。
func (m *Metrics) totalsLocked() totals {
	var t totals
	for k, v := range m.reqs {
		t.requests += v
		if k.status >= 500 {
			t.errors += v
		}
	}
	for _, v := range m.limited {
		t.blocked += v
	}
	for _, v := range m.rejected {
		t.blocked += v
	}
	return t
}

// Render 输出 Prometheus 文本格式（可被直接抓取）。
func (m *Metrics) Render() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var sb strings.Builder

	sb.WriteString("# HELP goproxy_requests_total 按路由和状态码统计的请求数\n")
	sb.WriteString("# TYPE goproxy_requests_total counter\n")
	keys := make([]reqKey, 0, len(m.reqs))
	for k := range m.reqs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].route != keys[j].route {
			return keys[i].route < keys[j].route
		}
		return keys[i].status < keys[j].status
	})
	for _, k := range keys {
		fmt.Fprintf(&sb, "goproxy_requests_total{route=%q,status=%q} %d\n",
			k.route, strconv.Itoa(k.status), m.reqs[k])
	}

	sb.WriteString("# HELP goproxy_request_duration_seconds 请求耗时分布\n")
	sb.WriteString("# TYPE goproxy_request_duration_seconds histogram\n")
	routes := sortedKeys(m.count)
	for _, r := range routes {
		b := m.buckets[r]
		for i, ub := range durBuckets {
			fmt.Fprintf(&sb, "goproxy_request_duration_seconds_bucket{route=%q,le=%q} %d\n",
				r, strconv.FormatFloat(ub, 'g', -1, 64), b[i])
		}
		fmt.Fprintf(&sb, "goproxy_request_duration_seconds_bucket{route=%q,le=\"+Inf\"} %d\n", r, m.count[r])
		fmt.Fprintf(&sb, "goproxy_request_duration_seconds_sum{route=%q} %f\n", r, m.sum[r])
		fmt.Fprintf(&sb, "goproxy_request_duration_seconds_count{route=%q} %d\n", r, m.count[r])
	}

	sb.WriteString("# HELP goproxy_rate_limited_total 被限流拒绝的请求数\n")
	sb.WriteString("# TYPE goproxy_rate_limited_total counter\n")
	for _, r := range sortedKeys(m.limited) {
		fmt.Fprintf(&sb, "goproxy_rate_limited_total{route=%q} %d\n", r, m.limited[r])
	}

	sb.WriteString("# HELP goproxy_rejected_total 被 ACL / 熔断 / 认证拒绝的请求数\n")
	sb.WriteString("# TYPE goproxy_rejected_total counter\n")
	for _, k := range sortedKeys(m.rejected) {
		route, reason, _ := strings.Cut(k, "|")
		fmt.Fprintf(&sb, "goproxy_rejected_total{route=%q,reason=%q} %d\n", route, reason, m.rejected[k])
	}

	sb.WriteString("# HELP goproxy_circuit_state 熔断器状态 0=closed 1=open 2=half_open\n")
	sb.WriteString("# TYPE goproxy_circuit_state gauge\n")
	for _, r := range sortedKeys(m.cbState) {
		fmt.Fprintf(&sb, "goproxy_circuit_state{route=%q} %d\n", r, m.cbState[r])
	}

	sb.WriteString("# HELP goproxy_circuit_opened_total 累计跳闸次数\n")
	sb.WriteString("# TYPE goproxy_circuit_opened_total counter\n")
	for _, r := range sortedKeys(m.cbOpened) {
		fmt.Fprintf(&sb, "goproxy_circuit_opened_total{route=%q} %d\n", r, m.cbOpened[r])
	}

	sb.WriteString("# HELP goproxy_circuit_rejected_total 熔断期间被快速失败的请求数\n")
	sb.WriteString("# TYPE goproxy_circuit_rejected_total counter\n")
	for _, r := range sortedKeys(m.cbReject) {
		fmt.Fprintf(&sb, "goproxy_circuit_rejected_total{route=%q} %d\n", r, m.cbReject[r])
	}

	sb.WriteString("# HELP goproxy_requests_in_flight 正在处理的请求数\n")
	sb.WriteString("# TYPE goproxy_requests_in_flight gauge\n")
	for _, r := range sortedKeys(m.inFly) {
		fmt.Fprintf(&sb, "goproxy_requests_in_flight{route=%q} %d\n", r, m.inFly[r])
	}

	sb.WriteString("# HELP goproxy_route_count 当前生效的路由数\n")
	sb.WriteString("# TYPE goproxy_route_count gauge\n")
	fmt.Fprintf(&sb, "goproxy_route_count %d\n", m.routeCount)

	sb.WriteString("# HELP goproxy_config_reload_total 配置重载次数\n")
	sb.WriteString("# TYPE goproxy_config_reload_total counter\n")
	fmt.Fprintf(&sb, "goproxy_config_reload_total %d\n", m.reloadTotal)

	sb.WriteString("# HELP goproxy_uptime_seconds 进程运行时长\n")
	sb.WriteString("# TYPE goproxy_uptime_seconds gauge\n")
	fmt.Fprintf(&sb, "goproxy_uptime_seconds %d\n", int64(time.Since(m.start).Seconds()))

	return sb.String()
}

func sortedKeys[T any](m map[string]T) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
