package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// portSeq 给每个测试发一批互不重叠的端口。
// 不用「监听 :0 再关掉」那招：两次取端口之间有竞态，而且 Windows 上
// 刚关闭的监听端口会短暂无法重绑。单调递增最省心。
var portSeq int32 = 18000

func nextPorts(n int) []int {
	start := atomic.AddInt32(&portSeq, int32(n)) - int32(n) + 1
	out := make([]int, n)
	for i := range out {
		out[i] = int(start) + i
	}
	return out
}

type testEnv struct {
	app  *App
	path string
	p    []int
}

// newTestEnv 起一个真的在监听端口的管理端环境。
// 用真实端口而不是 mock，是为了顺带验证「改配置 → 端口自动开/关」这条链路。
func newTestEnv(t *testing.T, adminToken string, extraRoute string) *testEnv {
	t.Helper()
	p := nextPorts(5)

	tokenField := ""
	if adminToken != "" {
		tokenField = fmt.Sprintf("%q: %q,", "admin_token", adminToken)
	}
	routes := fmt.Sprintf(
		`{"id":"seed","listen_port":%d,"path_prefix":"/","target":"http://127.0.0.1:%d"}`,
		p[1], p[4])
	if extraRoute != "" {
		routes += "," + extraRoute
	}

	cfg := fmt.Sprintf(`{
  "default_ports": [%d],
  "admin_addr": "127.0.0.1:%d",
  %s
  "routes": [%s]
}`, p[0], p[2], tokenField, routes)

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
	return &testEnv{app: a, path: path, p: p}
}

// do 把请求喂给管理端 mux。走 mux 而不是直接调 handler，
// 是因为 {id} 这类路径参数要靠 ServeMux 填进 PathValue。
func (e *testEnv) do(t *testing.T, method, path, body string, opts ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.RemoteAddr = "127.0.0.1:34567" // 默认按回环处理，认证自动放行
	for _, o := range opts {
		o(req)
	}
	rr := httptest.NewRecorder()
	e.app.adminHandler().ServeHTTP(rr, req)
	return rr
}

func remote(addr string) func(*http.Request) {
	return func(r *http.Request) { r.RemoteAddr = addr }
}

func header(k, v string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(k, v) }
}

func decode[T any](t *testing.T, rr *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatalf("解析响应失败: %v，原文 %s", err, rr.Body.String())
	}
	return v
}

type mutationResp struct {
	Revision string     `json:"revision"`
	Routes   int        `json:"routes"`
	Ports    []int      `json:"ports"`
	Route    *routeView `json:"route"`
	Deleted  string     `json:"deleted"`
}

func hasPort(ports []int, p int) bool {
	for _, v := range ports {
		if v == p {
			return true
		}
	}
	return false
}

func dialOK(port int) error {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return err
	}
	return c.Close()
}

func readConfigFromDisk(t *testing.T, path string) ([]byte, Config) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读配置文件失败: %v", err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("配置文件已不是合法 JSON: %v\n%s", err, raw)
	}
	return raw, c
}

func TestAdminRouteCRUD(t *testing.T) {
	e := newTestEnv(t, "", "")
	np := nextPorts(2)

	// --- 列表 ---
	rr := e.do(t, "GET", "/_goproxy/routes", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("列表应 200，实际 %d: %s", rr.Code, rr.Body)
	}
	etag := rr.Header().Get("ETag")
	if !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
		t.Fatalf("ETag 格式不对: %q", etag)
	}
	if got := len(decode[[]routeView](t, rr)); got != 1 {
		t.Fatalf("初始路由数应为 1，实际 %d", got)
	}

	// --- 新建 ---
	body := fmt.Sprintf(
		`{"id":"api","name":"API","listen_port":%d,"path_prefix":"/api","target":"http://127.0.0.1:%d"}`,
		np[0], np[1])
	rr = e.do(t, "POST", "/_goproxy/routes", body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("新建应 201，实际 %d: %s", rr.Code, rr.Body)
	}
	created := decode[mutationResp](t, rr)
	if created.Revision == "" {
		t.Fatal("新建响应缺少 revision")
	}
	if created.Route == nil || created.Route.ID != "api" || created.Route.Name != "API" {
		t.Fatalf("返回的路由不对: %+v", created.Route)
	}
	if !hasPort(created.Ports, np[0]) {
		t.Fatalf("新端口 %d 未出现在监听列表 %v", np[0], created.Ports)
	}
	// 真去连一下，证明监听套接字确实起来了（而不只是配置里多了一行）
	if err := dialOK(np[0]); err != nil {
		t.Fatalf("新端口 %d 没有真正监听: %v", np[0], err)
	}

	// --- 局部更新：停用 ---
	rr = e.do(t, "PATCH", "/_goproxy/routes/api", `{"enabled":false}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH 应 200，实际 %d: %s", rr.Code, rr.Body)
	}
	if got := decode[mutationResp](t, rr).Route; got == nil || got.Enabled == nil || *got.Enabled {
		t.Fatalf("PATCH 后 enabled 应为 false: %+v", got)
	}

	// 配置文件的唯一真源是磁盘，落盘了才算数
	raw, onDisk := readConfigFromDisk(t, e.path)
	idx := indexRoute(onDisk.Routes, "api")
	if idx < 0 {
		t.Fatalf("配置文件里没有 api 路由:\n%s", raw)
	}
	if onDisk.Routes[idx].Enabled == nil || *onDisk.Routes[idx].Enabled {
		t.Fatal("配置文件里 enabled 应为 false")
	}
	if _, err := os.Stat(e.path + ".bak"); err != nil {
		t.Fatalf("写回时应生成 .bak 备份: %v", err)
	}

	// --- 全量替换 ---
	body = fmt.Sprintf(
		`{"name":"API v2","listen_port":%d,"path_prefix":"/v2","target":"http://127.0.0.1:%d"}`,
		np[0], np[1])
	rr = e.do(t, "PUT", "/_goproxy/routes/api", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT 应 200，实际 %d: %s", rr.Code, rr.Body)
	}
	if got := decode[mutationResp](t, rr).Route; got == nil || got.Name != "API v2" || got.PathPrefix != "/v2" {
		t.Fatalf("PUT 后字段不对: %+v", got)
	}
	// PUT 是全量替换：body 里没提 enabled，应回到「默认启用」
	if got := decode[routeView](t, e.do(t, "GET", "/_goproxy/routes/api", "")); !got.enabled() {
		t.Fatalf("PUT 未提到的字段应回到零值/默认值: %+v", got)
	}

	// --- 单条读取 ---
	rr = e.do(t, "GET", "/_goproxy/routes/api", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("单条读取应 200，实际 %d", rr.Code)
	}
	if got := decode[routeView](t, rr); got.Name != "API v2" {
		t.Fatalf("单条读取内容不对: %+v", got)
	}

	// --- 删除 ---
	rr = e.do(t, "DELETE", "/_goproxy/routes/api", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("删除应 200，实际 %d: %s", rr.Code, rr.Body)
	}
	del := decode[mutationResp](t, rr)
	if del.Deleted != "api" {
		t.Fatalf("删除响应里 deleted 应为 api: %+v", del)
	}
	// 该端口上最后一条路由没了，端口应该被自动关掉
	if hasPort(del.Ports, np[0]) {
		t.Fatalf("删掉端口 %d 上最后一条路由后应关闭监听，实际还在 %v", np[0], del.Ports)
	}
	// 但 default_ports 里的端口必须一直留着
	if !hasPort(del.Ports, e.p[0]) {
		t.Fatalf("default_ports 的 %d 应始终监听，实际 %v", e.p[0], del.Ports)
	}
	if rr := e.do(t, "GET", "/_goproxy/routes/api", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("删除后单条读取应 404，实际 %d", rr.Code)
	}
}

func TestRouteCreateDuplicateID(t *testing.T) {
	e := newTestEnv(t, "", "")
	body := fmt.Sprintf(`{"id":"seed","listen_port":%d,"target":"http://127.0.0.1:9000"}`, e.p[3])
	rr := e.do(t, "POST", "/_goproxy/routes", body)
	if rr.Code != http.StatusConflict {
		t.Fatalf("重复 id 应 409，实际 %d: %s", rr.Code, rr.Body)
	}
	if !strings.Contains(rr.Body.String(), "duplicate_id") {
		t.Fatalf("错误码不对: %s", rr.Body)
	}
}

func TestRouteAutoIDAndDefaults(t *testing.T) {
	e := newTestEnv(t, "", "")
	body := fmt.Sprintf(`{"listen_port":%d,"target":"http://127.0.0.1:9000"}`, e.p[3])
	rr := e.do(t, "POST", "/_goproxy/routes", body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("不带 id 新建应 201，实际 %d: %s", rr.Code, rr.Body)
	}
	got := decode[mutationResp](t, rr).Route
	if got == nil || !strings.HasPrefix(got.ID, "rt-") {
		t.Fatalf("应自动生成 rt- 前缀的 id: %+v", got)
	}
	// 兜底的 path_prefix 要真的落盘，而不是只存在于内存
	if got.PathPrefix != "/" {
		t.Fatalf("path_prefix 应兜底为 /，实际 %q", got.PathPrefix)
	}
	_, onDisk := readConfigFromDisk(t, e.path)
	idx := indexRoute(onDisk.Routes, got.ID)
	if idx < 0 || onDisk.Routes[idx].PathPrefix != "/" {
		t.Fatalf("兜底值没有落盘:\n%+v", onDisk.Routes)
	}
}

// 两个页签同时编辑时，后提交的那个必须被挡下，否则前一个人的修改会被静默吞掉。
func TestIfMatchPreventsLostUpdate(t *testing.T) {
	e := newTestEnv(t, "", "")

	rr := e.do(t, "GET", "/_goproxy/routes", "")
	revA := strings.Trim(rr.Header().Get("ETag"), `"`)
	if revA == "" {
		t.Fatal("列表响应缺少 ETag")
	}

	body := fmt.Sprintf(`{"id":"one","listen_port":%d,"target":"http://127.0.0.1:9000"}`, e.p[3])
	if rr := e.do(t, "POST", "/_goproxy/routes", body, header("If-Match", `"`+revA+`"`)); rr.Code != http.StatusCreated {
		t.Fatalf("基于当前 revision 的写应成功，实际 %d: %s", rr.Code, rr.Body)
	}

	// 拿着已经过期的 revision 再写
	body = fmt.Sprintf(`{"id":"two","listen_port":%d,"target":"http://127.0.0.1:9000"}`, e.p[3])
	rr = e.do(t, "POST", "/_goproxy/routes", body, header("If-Match", `"`+revA+`"`))
	if rr.Code != http.StatusConflict {
		t.Fatalf("过期 revision 应 409，实际 %d: %s", rr.Code, rr.Body)
	}
	raw, _ := readConfigFromDisk(t, e.path)
	if strings.Contains(string(raw), `"two"`) {
		t.Fatalf("被拒绝的写不该落盘:\n%s", raw)
	}
}

func TestInvalidRouteRejectedWithoutTouchingFile(t *testing.T) {
	e := newTestEnv(t, "", "")
	before, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct{ name, body string }{
		{"target 协议不支持", fmt.Sprintf(`{"id":"x1","listen_port":%d,"target":"ftp://127.0.0.1:9000"}`, e.p[3])},
		{"target 缺主机", fmt.Sprintf(`{"id":"x2","listen_port":%d,"target":"http://"}`, e.p[3])},
		{"path_prefix 不以 / 开头", fmt.Sprintf(`{"id":"x3","listen_port":%d,"path_prefix":"api","target":"http://127.0.0.1:9000"}`, e.p[3])},
		{"listen_port 与管理端口冲突", fmt.Sprintf(`{"id":"x4","listen_port":%d,"target":"http://127.0.0.1:9000"}`, e.p[2])},
		{"basic 认证没配账号", fmt.Sprintf(`{"id":"x5","listen_port":%d,"target":"http://127.0.0.1:9000","auth":{"mode":"basic"}}`, e.p[3])},
		{"认证模式不认识", fmt.Sprintf(`{"id":"x6","listen_port":%d,"target":"http://127.0.0.1:9000","auth":{"mode":"oauth"}}`, e.p[3])},
		{"报文不是合法 JSON", `{"id":`},
		{"报文是空对象", `{}`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := e.do(t, "POST", "/_goproxy/routes", c.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("应 400，实际 %d: %s", rr.Code, rr.Body)
			}
			after, err := os.ReadFile(e.path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("校验没过却动了配置文件:\n改动前 %s\n改动后 %s", before, after)
			}
		})
	}
}

// 局部更新必须只覆盖报文里出现过的字段。这条要是错了，
// 界面上改个名字就会把限流、熔断、认证全清掉，而且很难发现。
func TestPatchMergesAndNullClears(t *testing.T) {
	e := newTestEnv(t, "", "")
	np := nextPorts(1)

	body := fmt.Sprintf(
		`{"id":"rl","listen_port":%d,"target":"http://127.0.0.1:9000","rate_limit":{"rps":5,"burst":10}}`, np[0])
	rr := e.do(t, "POST", "/_goproxy/routes", body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("新建应 201，实际 %d: %s", rr.Code, rr.Body)
	}
	if got := decode[mutationResp](t, rr).Route; got == nil || got.RateLimit == nil {
		t.Fatalf("限流没生效: %+v", got)
	}

	rr = e.do(t, "PATCH", "/_goproxy/routes/rl", `{"name":"改个名字"}`)
	if got := decode[mutationResp](t, rr).Route; got == nil || got.Name != "改个名字" {
		t.Fatalf("改名失败: %+v", got)
	} else if got.RateLimit == nil || got.RateLimit.RPS != 5 {
		t.Fatalf("局部更新把没提到的 rate_limit 弄丢了: %+v", got.RateLimit)
	}

	rr = e.do(t, "PATCH", "/_goproxy/routes/rl", `{"rate_limit":null}`)
	if got := decode[mutationResp](t, rr).Route; got == nil || got.RateLimit != nil {
		t.Fatalf("显式传 null 应清掉限流: %+v", got)
	}

	// ID 不能通过报文偷改，否则客户端按旧 ID 就再也找不到了
	rr = e.do(t, "PATCH", "/_goproxy/routes/rl", `{"id":"偷偷改名"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH 应 200，实际 %d", rr.Code)
	}
	if got := decode[mutationResp](t, rr).Route; got == nil || got.ID != "rl" {
		t.Fatalf("id 不应被报文改掉: %+v", got)
	}
	if rr := e.do(t, "GET", "/_goproxy/routes/rl", ""); rr.Code != http.StatusOK {
		t.Fatalf("按原 id 应仍能查到，实际 %d", rr.Code)
	}
}

func TestAdminAuth(t *testing.T) {
	const external = "203.0.113.9:5555"

	t.Run("非回环且未配 token 时一律拒绝", func(t *testing.T) {
		e := newTestEnv(t, "", "")
		rr := e.do(t, "GET", "/_goproxy/routes", "", remote(external))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("应 403，实际 %d: %s", rr.Code, rr.Body)
		}
		if !strings.Contains(rr.Body.String(), "admin_token_not_set") {
			t.Fatalf("错误码不对: %s", rr.Body)
		}
		if rr := e.do(t, "GET", "/_goproxy/routes", ""); rr.Code != http.StatusOK {
			t.Fatalf("回环地址应放行，实际 %d", rr.Code)
		}
	})

	t.Run("配了 token 后校验 Bearer", func(t *testing.T) {
		e := newTestEnv(t, "s3cret-token", "")

		if rr := e.do(t, "GET", "/_goproxy/routes", "", remote(external)); rr.Code != http.StatusUnauthorized {
			t.Fatalf("不带 token 应 401，实际 %d", rr.Code)
		}
		if rr := e.do(t, "GET", "/_goproxy/routes", "", remote(external),
			header("Authorization", "Bearer 猜的")); rr.Code != http.StatusUnauthorized {
			t.Fatalf("错误 token 应 401，实际 %d", rr.Code)
		}
		if rr := e.do(t, "GET", "/_goproxy/routes", "", remote(external),
			header("Authorization", "Bearer s3cret-token")); rr.Code != http.StatusOK {
			t.Fatalf("正确 token 应 200，实际 %d: %s", rr.Code, rr.Body)
		}
		// 这是最关键的一条：X-Forwarded-For 是客户端随手可写的，
		// 伪造它说「我是本机」绝不能被当成回环访问放行。
		if rr := e.do(t, "GET", "/_goproxy/routes", "", remote(external),
			header("X-Forwarded-For", "127.0.0.1"),
			header("X-Real-IP", "127.0.0.1")); rr.Code != http.StatusUnauthorized {
			t.Fatalf("伪造 XFF 不该绕过认证，实际 %d", rr.Code)
		}
	})
}

func TestAdminConfigEndpoint(t *testing.T) {
	e := newTestEnv(t, "", "")

	rr := e.do(t, "GET", "/_goproxy/config", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET config 应 200，实际 %d", rr.Code)
	}
	if rr.Header().Get("ETag") == "" {
		t.Fatal("GET config 应带 ETag")
	}

	// admin_addr 是启动期配置，运行期改它不生效。必须明确拒绝，
	// 而不是返回 200 让人以为改成了。
	rr = e.do(t, "PATCH", "/_goproxy/config", `{"admin_addr":"0.0.0.0:9080"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("改 admin_addr 应 400，实际 %d: %s", rr.Code, rr.Body)
	}
	if !strings.Contains(rr.Body.String(), "admin_addr_immutable") {
		t.Fatalf("错误码不对: %s", rr.Body)
	}

	// 路由不许从这个口子改
	if rr := e.do(t, "PATCH", "/_goproxy/config", `{"routes":[]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("从 config 改 routes 应 400，实际 %d", rr.Code)
	}

	// 合法字段应该能改并且落盘
	if rr := e.do(t, "PATCH", "/_goproxy/config", `{"access_log":true}`); rr.Code != http.StatusOK {
		t.Fatalf("改 access_log 应 200，实际 %d: %s", rr.Code, rr.Body)
	}
	_, onDisk := readConfigFromDisk(t, e.path)
	if !onDisk.AccessLog {
		t.Fatal("access_log 没有落盘")
	}

	// token 明文不能在响应里出现
	e2 := newTestEnv(t, "super-secret-value", "")
	body := e2.do(t, "GET", "/_goproxy/config", "").Body.String()
	if strings.Contains(body, "super-secret-value") {
		t.Fatalf("GET config 不该回传 admin_token 明文: %s", body)
	}
	if !strings.Contains(body, `"admin_token_set":true`) {
		t.Fatalf("应报告 admin_token 是否已设置: %s", body)
	}
}

// 写回配置时不能把「留空」的顶层字段固化成默认值 ——
// 否则一次界面保存就会把原本关闭的管理端口悄悄打开。
func TestMutationPreservesOmittedTopLevelFields(t *testing.T) {
	p := nextPorts(2)
	path := filepath.Join(t.TempDir(), "config.json")
	orig := fmt.Sprintf(
		`{"default_ports":[%d],"routes":[{"id":"seed","listen_port":%d,"target":"http://127.0.0.1:9000"}]}`,
		p[0], p[1])
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}

	a, err := NewApp(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.reload(); err != nil {
		t.Fatalf("reload 失败: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		a.listeners.ShutdownAll(ctx)
	})

	// 内存里应该回落到默认管理地址
	a.mu.Lock()
	got := a.adminAddr
	a.mu.Unlock()
	if got != defaultAdminAddr {
		t.Fatalf("内存里管理地址应为默认值，实际 %q", got)
	}

	if _, _, err := a.mutate("", func(cfg *Config) error {
		cfg.Routes = append(cfg.Routes, RouteConfig{
			ID: "added", PathPrefix: "/x", Target: "http://127.0.0.1:9000",
		})
		return nil
	}); err != nil {
		t.Fatalf("mutate 失败: %v", err)
	}

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), defaultAdminAddr) {
		t.Fatalf("写回不该把留空的 admin_addr 固化成默认值:\n%s", raw)
	}
	var back Config
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("写回的文件不是合法 JSON: %v", err)
	}
	if back.AdminAddr != "" {
		t.Fatalf("admin_addr 应保持「未指定」，实际 %q", back.AdminAddr)
	}
	if !strings.Contains(string(raw), `"added"`) {
		t.Fatalf("新增路由没落盘:\n%s", raw)
	}
}

func TestAdminAddrOffSentinel(t *testing.T) {
	var c Config
	c.applyTopDefaults()
	if c.AdminAddr != defaultAdminAddr {
		t.Fatalf("admin_addr 留空应回落默认值，实际 %q", c.AdminAddr)
	}

	c = Config{AdminAddr: "off"}
	c.applyTopDefaults()
	if c.adminEnabled() {
		t.Fatalf("admin_addr=off 应彻底关闭管理端口，实际 %q", c.AdminAddr)
	}
}
