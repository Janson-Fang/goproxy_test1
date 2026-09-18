package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// noProxyClient 显式不配代理。
//
// 本机（以及不少内网环境）设了 http_proxy，而 Go 的 DefaultTransport 会
// ProxyFromEnvironment，于是连 127.0.0.1 的测试请求也会被代理截走 ——
// 症状是测试报连接失败，看起来像服务没起来，其实是客户端的问题。
func noProxyClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{}, // Proxy 为 nil = 不走代理
		Timeout:   10 * time.Second,
	}
}

// newStatsEnv 起一个带真实后端的测试环境，后端用 httptest 起，
// 这样「请求 → 转发 → 记录日志 → 出现在接口里」整条链路都是真的。
func newStatsEnv(t *testing.T) (*testEnv, []int) {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /slow 上真的睡一会儿：给「耗时被如实记录」提供一个确定性的下界。
		// 拿机器速度去断言「耗时 > 0」必然偶发失败 —— 快机器上 1ms 内就返回了。
		if strings.Contains(r.URL.Path, "slow") {
			time.Sleep(5 * time.Millisecond)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(backend.Close)

	p := nextPorts(4)
	cfg := fmt.Sprintf(`{
  "default_ports": [%d],
  "admin_addr": "127.0.0.1:%d",
  "admin_token": %q,
  "access_log": true,
  "routes": [
    {"id":"seed","name":"种子路由","listen_port":%d,"path_prefix":"/","target":%q}
  ]
}`, p[0], p[2], testToken, p[1], backend.URL)

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatalf("写测试配置失败: %v", err)
	}
	a, err := NewApp(path)
	if err != nil {
		t.Fatalf("NewApp 失败: %v", err)
	}
	if err := a.reload(); err != nil {
		t.Fatalf("reload 失败: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		a.listeners.ShutdownAll(ctx)
	})
	// token 必须带上：本文件里的用例都是「打到管理接口读指标」，
	// 而 v0.6.0 起回环不再免认证，不带给就是 401。
	return &testEnv{app: a, path: path, p: p, token: testToken}, p
}

// hit 向数据端口发一个真实请求。
func hit(t *testing.T, port int, path string) int {
	t.Helper()
	resp, err := noProxyClient().Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, path))
	if err != nil {
		t.Fatalf("请求端口 %d 失败: %v", port, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// ---------- 环形缓冲 ----------

func TestLogBufferRingWraps(t *testing.T) {
	b := newLogBuffer(4)
	for i := 1; i <= 6; i++ {
		b.Add(LogEntry{Path: fmt.Sprintf("/p%d", i)})
	}
	if b.Len() != 4 {
		t.Fatalf("容量 4 的环写了 6 条，Len 应为 4，实际 %d", b.Len())
	}
	got := b.Recent(4)
	want := []string{"/p3", "/p4", "/p5", "/p6"}
	for i, e := range got {
		if e.Path != want[i] {
			t.Fatalf("Recent 应为最新的 %v，实际 %v", want, pathsOf(got))
		}
	}
	// 序号必须单调递增，前端靠它去重
	if got[3].Seq != 6 {
		t.Errorf("最后一条的 seq 应为 6，实际 %d", got[3].Seq)
	}
	// 再读一次，顺序必须稳定（Recent 不能破坏环的写指针）
	for i, e := range b.Recent(4) {
		if e.Path != want[i] {
			t.Fatalf("Recent 连续调用结果不一致: %v", pathsOf(b.Recent(4)))
		}
	}
}

func TestLogBufferRecentBeyondSize(t *testing.T) {
	b := newLogBuffer(4)
	b.Add(LogEntry{Path: "/only"})
	got := b.Recent(100)
	if len(got) != 1 || got[0].Path != "/only" {
		t.Fatalf("只写了 1 条时 Recent(100) 应返回 1 条，实际 %v", pathsOf(got))
	}
	if got := b.Recent(0); len(got) != 1 {
		t.Fatalf("Recent(0) 应等同于「全部」，实际 %d 条", len(got))
	}
	if got := newLogBuffer(4).Recent(10); len(got) != 0 {
		t.Fatalf("空缓冲应返回空切片，实际 %d 条", len(got))
	}
}

// TestLogBufferSlowSubscriberDrops 是本文件最重要的一个用例：
// 如果广播改成阻塞发送，一个不读的订阅者就能把 Add 卡死，
// 进而卡死所有请求 —— 访问日志绝不该有这种失败模式。
func TestLogBufferSlowSubscriberDrops(t *testing.T) {
	b := newLogBuffer(8)
	ch, cancel := b.Subscribe()
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 写的量远超订阅者缓冲，且全程不读
		for i := 0; i < logSubBuffer*3; i++ {
			b.Add(LogEntry{Path: "/flood"})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("慢订阅者把 Add 阻塞住了 —— 广播必须是非阻塞发送")
	}

	if len(ch) != logSubBuffer {
		t.Errorf("订阅者缓冲应被填满到 %d，实际 %d", logSubBuffer, len(ch))
	}
	_, dropped := b.Stats()
	if want := uint64(logSubBuffer*3 - logSubBuffer); dropped != want {
		t.Errorf("丢弃计数应为 %d，实际 %d", want, dropped)
	}
}

func TestLogBufferUnsubscribeIsSafe(t *testing.T) {
	b := newLogBuffer(4)
	_, cancel := b.Subscribe()
	cancel()
	cancel() // 重复取消不能 panic

	// 取消后再写：不能 panic（send on closed channel）
	b.Add(LogEntry{Path: "/after-cancel"})

	subs, _ := b.Stats()
	if subs != 0 {
		t.Fatalf("取消后订阅者应为 0，实际 %d", subs)
	}
	if entries := b.Recent(10); len(entries) != 1 {
		t.Fatalf("记录本身不该因为取消订阅而丢失，实际 %d 条", len(entries))
	}
}

// ---------- 指标聚合 ----------

func TestMetricsSeriesDeltas(t *testing.T) {
	m := NewMetrics()
	base := time.Unix(1_700_000_000, 0)

	m.Sample(base) // 首个点：此时还没有任何请求

	m.IncRequest("a", 200)
	m.IncRequest("a", 200)
	m.IncRequest("a", 500)
	m.IncRateLimited("a")
	m.IncRejected("a", "acl")
	m.Sample(base.Add(time.Second))

	m.IncRequest("a", 200)
	m.Sample(base.Add(2 * time.Second))

	pts := m.SeriesPoints()
	if len(pts) != 3 {
		t.Fatalf("应采到 3 个点，实际 %d", len(pts))
	}
	if pts[0].T != base.Unix() || pts[2].T != base.Add(2*time.Second).Unix() {
		t.Fatalf("采样点时间戳不对: %+v", pts)
	}
	// 第 2 个点应是「增量」而不是累计值 —— 累计值画曲线毫无意义
	if pts[1].Requests != 3 || pts[1].Errors != 1 || pts[1].Blocked != 2 {
		t.Errorf("第 2 点增量应为 3/1/2，实际 %d/%d/%d",
			pts[1].Requests, pts[1].Errors, pts[1].Blocked)
	}
	if pts[2].Requests != 1 || pts[2].Errors != 0 {
		t.Errorf("第 3 点应只含新增的 1 个请求，实际 %d/%d",
			pts[2].Requests, pts[2].Errors)
	}
}

func TestMetricsSeriesWraps(t *testing.T) {
	m := NewMetrics()
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < seriesSize+50; i++ {
		m.Sample(base.Add(time.Duration(i) * time.Second))
	}
	pts := m.SeriesPoints()
	if len(pts) != seriesSize {
		t.Fatalf("环应只保留 %d 个点，实际 %d", seriesSize, len(pts))
	}
	// 保留的必须是最新的那一段
	wantFirst := base.Add(50 * time.Second).Unix()
	if pts[0].T != wantFirst {
		t.Errorf("最旧的保留点应为 t=%d，实际 %d", wantFirst, pts[0].T)
	}
	if pts[len(pts)-1].T != base.Add(time.Duration(seriesSize+49)*time.Second).Unix() {
		t.Errorf("最新点时间戳不对: %d", pts[len(pts)-1].T)
	}
}

func TestMetricsGlobalSummary(t *testing.T) {
	m := NewMetrics()
	// 90 个快请求 + 10 个慢请求，p95 应落在 (0.01, 0.025] 这个桶
	for i := 0; i < 90; i++ {
		m.Observe("a", 0.003)
	}
	for i := 0; i < 10; i++ {
		m.Observe("a", 0.02)
	}
	m.IncRequest("a", 200)
	m.IncRequest("a", 500)
	m.IncRequest("", 404) // 没匹配到路由的请求不属于任何路由，全局汇总必须算上
	m.IncRateLimited("a")
	m.IncRejected("a", "circuit_open")
	m.IncInFlight("a")

	s := m.Global()
	if s.Requests != 3 || s.Unmatched != 1 {
		t.Errorf("请求总数/未匹配应为 3/1，实际 %d/%d", s.Requests, s.Unmatched)
	}
	if s.ByStatus["200"] != 1 || s.ByStatus["500"] != 1 || s.ByStatus["404"] != 1 {
		t.Errorf("按状态码分桶不对: %v", s.ByStatus)
	}
	if s.RateLimited != 1 || s.Rejected != 1 || s.InFlight != 1 {
		t.Errorf("限流/拒绝/在途应为 1/1/1，实际 %d/%d/%d",
			s.RateLimited, s.Rejected, s.InFlight)
	}
	if abs(s.AvgMs-4.7) > 0.01 {
		t.Errorf("平均耗时应为 4.7ms，实际 %.3f", s.AvgMs)
	}
	if abs(s.P95Ms-25) > 0.01 {
		t.Errorf("p95 应取到 25ms 那个桶的上界，实际 %.3f", s.P95Ms)
	}
	if abs(s.ErrorRate-1.0/3) > 1e-9 {
		t.Errorf("错误率应为 1/3，实际 %f", s.ErrorRate)
	}
}

func TestQuantileFromBucketsEdgeCases(t *testing.T) {
	if got := quantileFromBuckets(nil, 0, 95); got != 0 {
		t.Errorf("无样本时应返回 0，实际 %f", got)
	}
	// 所有请求都超过最大桶，报最大桶上界而不是 0
	over := make([]int64, len(durBuckets))
	over[len(over)-1] = 10
	if got := quantileFromBuckets(over, 10, 95); got != durBuckets[len(durBuckets)-1]*1000 {
		t.Errorf("超出最大桶时应报最大桶上界 %.0f，实际 %f",
			durBuckets[len(durBuckets)-1]*1000, got)
	}
}

// ---------- 接口 ----------

func TestLogsEndpointAfterRealTraffic(t *testing.T) {
	e, p := newStatsEnv(t)

	if code := hit(t, p[1], "/slow"); code != 200 {
		t.Fatalf("命中路由的请求应返回 200，实际 %d", code)
	}
	if code := hit(t, p[1], "/hello"); code != 200 {
		t.Fatalf("命中路由的请求应返回 200，实际 %d", code)
	}
	if code := hit(t, p[0], "/nowhere"); code != 404 {
		t.Fatalf("未命中路由的请求应返回 404，实际 %d", code)
	}

	rr := e.do(t, "GET", "/_goproxy/logs", "")
	if rr.Code != 200 {
		t.Fatalf("logs 应返回 200，实际 %d，体: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Entries   []LogEntry `json:"entries"`
		Buffered  int        `json:"buffered"`
		Capacity  int        `json:"capacity"`
		LatestSeq uint64     `json:"latest_seq"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(out.Entries) < 2 {
		t.Fatalf("至少应有 2 条记录，实际 %d：%s", len(out.Entries), rr.Body.String())
	}
	if out.Capacity != logRingSize {
		t.Errorf("容量应为 %d，实际 %d", logRingSize, out.Capacity)
	}
	if out.LatestSeq != uint64(len(out.Entries)) {
		t.Errorf("latest_seq 应为 %d，实际 %d", len(out.Entries), out.LatestSeq)
	}

	// 最近一条是 404 那条；未命中路由的记录 route 为空
	last := out.Entries[len(out.Entries)-1]
	if last.Path != "/nowhere" || last.Status != 404 || last.Route != "" {
		t.Errorf("最后一条记录不对: %+v", last)
	}

	slow := out.Entries[0]
	if slow.Path != "/slow" || slow.Status != 200 || slow.Route != "seed" {
		t.Errorf("第一条记录不对: %+v", slow)
	}
	if slow.RouteName != "种子路由" || slow.Port != p[1] {
		t.Errorf("记录缺少端口/路由名: %+v", slow)
	}
	// 后端至少睡了 5ms，所以耗时不可能低于它 —— 用下界而不是「> 0」，
	// 后者在快机器上会偶发失败（实测 6 次里挂 1 次）
	if slow.DurMs < 5 {
		t.Errorf("耗时至少应有 5ms，实际 %.3f —— 耗时没有被记录", slow.DurMs)
	}
	if slow.ClientIP != "127.0.0.1" {
		t.Errorf("客户端 IP 应为 127.0.0.1，实际 %q", slow.ClientIP)
	}
	if slow.Time == "" || !strings.Contains(slow.Time, "T") {
		t.Errorf("时间戳格式不对: %q", slow.Time)
	}

	if hello := out.Entries[1]; hello.Path != "/hello" || hello.Route != "seed" {
		t.Errorf("第二条应为 /hello: %+v", hello)
	}
}

func TestLogsEndpointLimit(t *testing.T) {
	e, p := newStatsEnv(t)
	for i := 0; i < 5; i++ {
		hit(t, p[1], "/x")
	}

	// 正常 limit
	rr := e.do(t, "GET", "/_goproxy/logs?limit=2", "")
	var out struct {
		Entries []LogEntry `json:"entries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(out.Entries) != 2 {
		t.Fatalf("limit=2 应返回 2 条，实际 %d", len(out.Entries))
	}

	// 超上限要被夹紧，而不是原样接受（否则一次请求能把整环抽干）
	rr = e.do(t, "GET", "/_goproxy/logs?limit=999999", "")
	if rr.Code != 200 {
		t.Fatalf("超大 limit 应被夹紧而不是报错，实际 %d", rr.Code)
	}

	for _, bad := range []string{"0", "-1", "abc"} {
		rr = e.do(t, "GET", "/_goproxy/logs?limit="+bad, "")
		if rr.Code != http.StatusBadRequest {
			t.Errorf("limit=%s 应返回 400，实际 %d", bad, rr.Code)
		}
	}
}

func TestStatsEndpoint(t *testing.T) {
	e, p := newStatsEnv(t)
	hit(t, p[1], "/ok")
	hit(t, p[0], "/missing")
	hit(t, p[0], "/missing2")

	rr := e.do(t, "GET", "/_goproxy/stats", "")
	if rr.Code != 200 {
		t.Fatalf("stats 应返回 200，实际 %d，体: %s", rr.Code, rr.Body.String())
	}
	var s statsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &s); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}

	if s.RoutesConfigured != 1 || s.RoutesActive != 1 {
		t.Errorf("路由数应为 1/1，实际 %d/%d", s.RoutesConfigured, s.RoutesActive)
	}
	if !hasPort(s.Ports, p[0]) || !hasPort(s.Ports, p[1]) {
		t.Errorf("监听端口应含 %d 与 %d，实际 %v", p[0], p[1], s.Ports)
	}
	if s.ConfigRevision == "" || len(s.ConfigRevision) != 64 {
		t.Errorf("config_revision 应是文件 sha256，实际 %q", s.ConfigRevision)
	}
	if s.StartedAt == "" || s.Now == "" {
		t.Errorf("缺少时间字段: started_at=%q now=%q", s.StartedAt, s.Now)
	}
	if s.Version == "" || s.Commit == "" {
		t.Errorf("缺少版本信息: %q %q", s.Version, s.Commit)
	}
	if s.ReloadTotal != 1 {
		t.Errorf("reload 次数应为 1，实际 %d", s.ReloadTotal)
	}
	if s.Summary.Requests != 3 {
		t.Errorf("请求总数应为 3，实际 %d", s.Summary.Requests)
	}
	if s.Summary.Unmatched != 2 {
		t.Errorf("未匹配数应为 2，实际 %d", s.Summary.Unmatched)
	}
	if s.Summary.ByStatus["200"] != 1 || s.Summary.ByStatus["404"] != 2 {
		t.Errorf("按状态码分桶不对: %v", s.Summary.ByStatus)
	}
	if s.Circuit.Closed != 0 || s.Circuit.Open != 0 {
		t.Errorf("这条种子路由没配熔断，计数应全为 0，实际 %+v", s.Circuit)
	}
	if s.Logs.Buffered != 3 || s.Logs.LatestSeq != 3 {
		t.Errorf("日志缓冲应为 3 条，实际 %+v", s.Logs)
	}
	// series 在测试里还没被采样过，应当是空数组而不是 null（前端 `.map` 会炸）
	body := rr.Body.String()
	if strings.Contains(body, `"series":null`) {
		t.Error("series 不应序列化成 null")
	}
	if strings.Contains(body, "admin_token") {
		t.Error("stats 不该泄露任何 token 相关信息")
	}
}

func TestStatsEndpointReportsCircuitState(t *testing.T) {
	// 这条路由配了熔断、指向一个没人监听的端口：先打几次把错误率顶上去
	cbPort := nextPorts(1)[0]
	bePort := nextPorts(1)[0]
	e := newTestEnv(t, testToken, fmt.Sprintf(
		`{"id":"cb","listen_port":%d,"path_prefix":"/","target":"http://127.0.0.1:%d",`+
			`"circuit_breaker":{"min_calls":2,"error_rate":0.5,"window_secs":10,"open_secs":30}}`,
		cbPort, bePort))

	for i := 0; i < 4; i++ {
		hit(t, cbPort, "/boom") // 后端不可达 → 502 → 触发跳闸
	}

	// 接口报告的必须是熔断器的当前真实状态，而不是 5 秒同步一次的那份缓存 ——
	// 跳闸了却要等 5 秒才在界面上看见，排查时会以为限流/熔断没生效。
	rr := e.do(t, "GET", "/_goproxy/stats", "")
	var s statsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &s); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	var openCount int
	if tbl := e.app.table.Load(); tbl != nil {
		for _, rt := range tbl.routes {
			if rt.cb != nil && rt.cb.State() == cbOpen {
				openCount++
			}
		}
	}
	if openCount == 0 {
		t.Fatal("连打 4 次不可达后端后熔断器本该跳闸，实际仍是 closed —— 用例前提不成立")
	}
	if s.Circuit.Open != openCount {
		t.Errorf("接口报告的 open 数 %d 与实际 %d 不一致", s.Circuit.Open, openCount)
	}
	if s.Circuit.Tripped == 0 {
		t.Error("跳闸次数应被统计到")
	}
}

// ---------- SSE ----------

func TestEventsStreamsAccessLog(t *testing.T) {
	e, p := newStatsEnv(t)
	srv := httptest.NewServer(e.app.adminHandler())
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 这里手工构造请求（要走真实 HTTP，才能验 SSE 的流式响应头），
	// 所以必须自己带上令牌：v0.6.0 起 /_goproxy/events 同样在 adminGuard 后面。
	req, err := http.NewRequestWithContext(ctx, "GET", srv.URL+"/_goproxy/events", nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := noProxyClient().Do(req)
	if err != nil {
		t.Fatalf("连接 SSE 失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("SSE 应返回 200，实际 %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type 应为 text/event-stream，实际 %q", ct)
	}
	// 少了这个头，经过 nginx 时事件会被缓冲，表现为日志长时间不动
	if v := resp.Header.Get("X-Accel-Buffering"); v != "no" {
		t.Errorf("缺少 X-Accel-Buffering: no，实际 %q", v)
	}

	events := make(chan string, 8)
	go func() {
		br := bufio.NewReader(resp.Body)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "event: ") || strings.HasPrefix(line, "data: ") {
				select {
				case events <- strings.TrimRight(line, "\r\n"):
				default:
				}
			}
		}
	}()

	// 先握手
	waitLine(t, events, "event: hello", 3*time.Second)

	// 触发一条真实访问
	if code := hit(t, p[1], "/stream-me"); code != 200 {
		t.Fatalf("请求应返回 200，实际 %d", code)
	}

	// 然后应当收到对应的 access 事件
	waitLine(t, events, "event: access", 3*time.Second)
	data := waitLinePrefix(t, events, "data: ", 3*time.Second)
	var entry LogEntry
	if err := json.Unmarshal([]byte(strings.TrimPrefix(data, "data: ")), &entry); err != nil {
		t.Fatalf("事件 data 不是合法 JSON: %v（原文 %s）", err, data)
	}
	if entry.Path != "/stream-me" || entry.Route != "seed" || entry.Status != 200 {
		t.Errorf("事件内容不对: %+v", entry)
	}
	if entry.Seq == 0 {
		t.Error("事件应带上 seq，前端靠它去重")
	}

	// 断开后订阅者必须被回收，否则每次刷新页面都会泄漏一个 goroutine
	cancel()
	resp.Body.Close()
	waitSubscribers(t, e.app, 0, 3*time.Second)
}

func waitLine(t *testing.T, ch <-chan string, want string, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case got := <-ch:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("等待 %q 超时", want)
		}
	}
}

func waitLinePrefix(t *testing.T, ch <-chan string, prefix string, d time.Duration) string {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case got := <-ch:
			if strings.HasPrefix(got, prefix) {
				return got
			}
		case <-deadline:
			t.Fatalf("等待前缀 %q 的事件超时", prefix)
		}
	}
}

func waitSubscribers(t *testing.T, a *App, want int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if subs, _ := a.logs.Stats(); subs == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	subs, _ := a.logs.Stats()
	t.Fatalf("订阅者数量应回到 %d，实际 %d（断开连接后没有回收）", want, subs)
}

// ---------- 并发 ----------

// TestConcurrentReloadAndServe 专门喂给 -race 的：
// 之前 App.trusted 是「reload 持锁写、请求路径无锁读」，真跑起来就是 data race。
// 这个用例让二者并发，交给 CI 的 -race 去抓。（本机没有 gcc 跑不了 -race。）
func TestConcurrentReloadAndServe(t *testing.T) {
	e, p := newStatsEnv(t)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if err := e.app.reload(); err != nil {
					t.Errorf("并发重载失败: %v", err)
					return
				}
			}
		}
	}()

	client := noProxyClient()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 60; i++ {
			select {
			case <-stop:
				return
			default:
			}
			resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/c%d", p[1], i))
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}()

	time.Sleep(400 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func pathsOf(es []LogEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Path
	}
	return out
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
