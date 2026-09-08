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

type reqKey struct {
	route  string
	status int
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
	}
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
