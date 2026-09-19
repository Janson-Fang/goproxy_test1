package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

// testToken 是绝大多数用例里配的 admin_token。
//
// 为什么要有这么一个共享常量：v0.6.0 起回环不再免认证，凡是「要调管理接口
// 才能测的东西」都必须先过鉴权。绝大多数用例真正想验的是路由/配置/指标，
// 认证只是它们路上的一道必经关卡 —— 与其在几十个 newTestEnv 里各写一遍
// 字面量（改起来容易漏），不如统一从这个常量取。
//
// 真正在测认证本身的用例（TestAdminAuth、TestLoopbackNoLongerBypassesAuth、
// TestNoCredentialsConfiguredRejectsEverything 等）继续用各自的字面量或
// 空字符串，不受这里影响。
const testToken = "s3cret-admin-token"

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

	// token 是这份测试配置里的 admin_token。do() 默认带上它 ——
	// v0.6.0 起回环不再免认证，如果还依赖「来自 127.0.0.1 就放行」，
	// 那么每个既有用例都会变成 401，而这些用例真正要测的并不是认证。
	// 需要测「未认证会怎样」的用例自己用 noAuth() 去掉这个头。
	token string
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
  "ip_lists": [
    {"name": "允许来源", "kind": "allow", "rules": ["10.0.0.0/8", "203.0.113.66"]},
    {"name": "内网例外", "kind": "deny",  "rules": ["10.0.0.66"]}
  ],
  "routes": [%s]
}`, p[0], p[2], tokenField, routes)

	// 先把配置库建好再起 App：NewApp 会检查这个路径是不是数据库，库为空还会
	// 尝试用旁边的 config.json 做一次性导入 —— 这里两条都不适用。
	path := filepath.Join(t.TempDir(), "goproxy.db")
	seedRawConfig(t, path, []byte(cfg))
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
	return &testEnv{app: a, path: path, p: p, token: adminToken}
}

// do 把请求喂给管理端 mux。走 mux 而不是直接调 handler，
// 是因为 {id} 这类路径参数要靠 ServeMux 填进 PathValue。
//
// 默认带上 Bearer 令牌（回环不再免认证，不带就是 401）。
// RemoteAddr 仍然设成回环：这既是「真实本机调用」的模拟，
// 也顺带保证「回环不再自动放行」这件事被每个用例持续验证着。
func (e *testEnv) do(t *testing.T, method, path, body string, opts ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.RemoteAddr = "127.0.0.1:34567"
	if e.token != "" {
		req.Header.Set("Authorization", "Bearer "+e.token)
	}
	for _, o := range opts {
		o(req)
	}
	rr := httptest.NewRecorder()
	e.app.adminHandler().ServeHTTP(rr, req)
	return rr
}

// noAuth 清掉默认带上的 Bearer 令牌，用来测「未认证」的分支。
func noAuth() func(*http.Request) {
	return func(r *http.Request) { r.Header.Del("Authorization") }
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

// readConfigFromDisk 读回落盘的配置（规范化 JSON + 未补默认值的结构）。
//
// 配置源换成 SQLite 之后，「落盘」= 已提交进库，所以这里走存储层读而不是读文件。
// 用 parseConfigFile 而不是 readConfigFile：后者会补默认值，而「兜底值到底
// 有没有真的写进库里」正是本文件好几条用例要验的事 —— 走补默认值的那条路，
// 即使什么都没存下来也照样能读到 "/"，用例就白写了。
func readConfigFromDisk(t *testing.T, path string) ([]byte, Config) {
	t.Helper()
	raw, c, err := parseConfigFile(path)
	if err != nil {
		t.Fatalf("读回配置失败: %v", err)
	}
	return raw, *c
}

func TestAdminRouteCRUD(t *testing.T) {
	e := newTestEnv(t, testToken, "")
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

	// 配置的唯一真源是数据库，落库了才算数
	raw, onDisk := readConfigFromDisk(t, e.path)
	idx := indexRoute(onDisk.Routes, "api")
	if idx < 0 {
		t.Fatalf("库里没有 api 路由:\n%s", raw)
	}
	if onDisk.Routes[idx].Enabled == nil || *onDisk.Routes[idx].Enabled {
		t.Fatal("库里 enabled 应为 false")
	}
	// 每次写入前留一版历史（替代了原来的 config.json.bak）。
	// 没了这条，改错两次就再也回不去了。
	st, err := storeFor(e.path)
	if err != nil {
		t.Fatalf("打开配置库失败: %v", err)
	}
	if n, err := st.historyCount(); err != nil {
		t.Fatalf("读配置历史失败: %v", err)
	} else if n == 0 {
		t.Fatal("写回时应留下配置历史")
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
	e := newTestEnv(t, testToken, "")
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
	e := newTestEnv(t, testToken, "")
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
	e := newTestEnv(t, testToken, "")

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

func TestInvalidRouteRejectedWithoutTouchingConfig(t *testing.T) {
	e := newTestEnv(t, testToken, "")
	before, _ := readConfigFromDisk(t, e.path)

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
			// 校验没过就绝不能落库：库里的内容必须和请求前逐字节一致。
			after, _ := readConfigFromDisk(t, e.path)
			if string(after) != string(before) {
				t.Fatalf("校验没过却动了配置:\n改动前 %s\n改动后 %s", before, after)
			}
		})
	}
}

// 局部更新必须只覆盖报文里出现过的字段。这条要是错了，
// 界面上改个名字就会把限流、熔断、认证全清掉，而且很难发现。
func TestPatchMergesAndNullClears(t *testing.T) {
	e := newTestEnv(t, testToken, "")
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

	t.Run("一个凭据都没配时一律 403", func(t *testing.T) {
		e := newTestEnv(t, "", "")
		rr := e.do(t, "GET", "/_goproxy/routes", "", remote(external))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("应 403，实际 %d: %s", rr.Code, rr.Body)
		}
		if !strings.Contains(rr.Body.String(), "admin_credentials_not_set") {
			t.Fatalf("错误码不对: %s", rr.Body)
		}
		// v0.6.0 起回环不再免认证：本机访问同样 403。
		// 旧版本这里断言的是 200（「回环地址应放行」），那正是
		// 「同一个配置在本机和别处表现不同」的根源，已经删掉了。
		if rr := e.do(t, "GET", "/_goproxy/routes", "", noAuth()); rr.Code != http.StatusForbidden {
			t.Fatalf("未配凭据时回环也应 403，实际 %d", rr.Code)
		}
	})

	t.Run("配了 token 后校验 Bearer", func(t *testing.T) {
		e := newTestEnv(t, "s3cret-token", "")

		if rr := e.do(t, "GET", "/_goproxy/routes", "", remote(external), noAuth()); rr.Code != http.StatusUnauthorized {
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
		// v0.6.0 起回环本身就不放行了，但这条断言仍然有价值：
		// 它保证没有人偷偷把「看 XFF 判断来源」这种写法加回来。
		if rr := e.do(t, "GET", "/_goproxy/routes", "", remote(external),
			noAuth(),
			header("X-Forwarded-For", "127.0.0.1"),
			header("X-Real-IP", "127.0.0.1")); rr.Code != http.StatusUnauthorized {
			t.Fatalf("伪造 XFF 不该绕过认证，实际 %d", rr.Code)
		}
	})
}

// TestAdminGuardRejectsProxiedLoopbackRequest 守住「经代理转发不能白拿权限」。
//
// 历史背景（v0.5.0）：管理端当时对来自回环的请求免认证，而代理转发正是从
// 127.0.0.1 发出的。于是「把一条路由的 target 指向管理端口」就能让外部客户端
// 白拿免认证的管理权限。实测确认过：这样读 /_goproxy/config、
// 写 POST /_goproxy/reload 全部 200。
//
// v0.6.0 起回环不再免认证，这个洞从根上没了 —— 但本测试**保留**，
// 因为它现在守的是另一件同样重要的事：标记头不能反过来成为放行理由。
// 只要有人日后写出「见到标记头就跳过认证」这种反向逻辑，这里立刻红。
func TestAdminGuardRejectsProxiedLoopbackRequest(t *testing.T) {
	t.Run("带代理标记的回环请求必须认证", func(t *testing.T) {
		e := newTestEnv(t, testToken, "")

		// 不带凭据 → 必须被拒。未修时这里是 200，也就是越权成立。
		rr := e.do(t, "GET", "/_goproxy/config", "", noAuth(), header(internalViaHeader, "1"))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("经代理转发且无凭据应 401，实际 %d: %s", rr.Code, rr.Body)
		}

		// 带正确令牌 → 正常放行：加了标记不能把合法访问也一起挡死，
		// 否则「用 TLS 路由把管理面板发布出去」这种正当用法就没法用了。
		if rr := e.do(t, "GET", "/_goproxy/config", "",
			header(internalViaHeader, "1")); rr.Code != http.StatusOK {
			t.Fatalf("带正确令牌应 200，实际 %d: %s", rr.Code, rr.Body)
		}
	})

	t.Run("不带标记的回环请求同样要认证", func(t *testing.T) {
		e := newTestEnv(t, testToken, "")
		// v0.5.0 这里断言的是 200（「本机直连免认证」）。
		// 那条豁免正是「控制台在别的机器上打开却没有登录入口」的根因，已删除。
		if rr := e.do(t, "GET", "/_goproxy/config", "", noAuth()); rr.Code != http.StatusUnauthorized {
			t.Fatalf("本机直连不带凭据也应 401，实际 %d: %s", rr.Code, rr.Body)
		}
	})

	t.Run("伪造任意标记值同样要认证", func(t *testing.T) {
		e := newTestEnv(t, testToken, "")
		// 判断只认「有没有」这个头，不认值 —— 这样就不存在「猜中密钥就绕过」的说法。
		if rr := e.do(t, "GET", "/_goproxy/config", "",
			noAuth(),
			header(internalViaHeader, "随便编一个")); rr.Code != http.StatusUnauthorized {
			t.Fatalf("带标记头一律要认证，应 401，实际 %d", rr.Code)
		}
	})
}

// TestLoopbackNoLongerBypassesAuth 是 v0.6.0 的行为变更守卫。
//
// v0.5.0 及以前：来自 127.0.0.1 的请求免认证。这条规则让同一个配置在
// 「本机打开控制台」和「从别的机器打开控制台」下表现完全不同 ——
// 前者直接进、后者可能看到登录页也可能看到被拒页，用户反馈过
// 「没见到登录界面」，根因就在这里。
//
// 现在一律要凭据。这个用例把「回环也不行」钉死：万一以后有人觉得
// 「本机调用加个豁免比较方便」又把它加回来，这里会立刻红。
func TestLoopbackNoLongerBypassesAuth(t *testing.T) {
	e := newTestEnv(t, "s3cret-token", "")

	// 来自回环、不带任何凭据 —— 必须 401，而不是 200
	for _, path := range []string{
		"/_goproxy/config", "/_goproxy/routes", "/_goproxy/stats",
		"/metrics", "/healthz", "/readyz",
	} {
		rr := e.do(t, "GET", path, "", noAuth())
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s：回环地址不带凭据应 401，实际 %d", path, rr.Code)
		}
	}

	// 写操作同样拦住，不能靠回环直连改配置
	if rr := e.do(t, "POST", "/_goproxy/reload", "", noAuth()); rr.Code != http.StatusUnauthorized {
		t.Errorf("回环地址不带凭据写操作应 401，实际 %d", rr.Code)
	}

	// 带上令牌就正常（证明上面拦的是「缺凭据」，不是把接口整个弄坏了）
	if rr := e.do(t, "GET", "/_goproxy/config", ""); rr.Code != http.StatusOK {
		t.Errorf("带令牌应 200，实际 %d: %s", rr.Code, rr.Body)
	}
}

// TestNoCredentialsConfiguredRejectsEverything 覆盖「一个凭据都没配」的状态。
//
// 这种状态下管理端必须彻底关门，并且回一个**能被前端识别的**错误码
// （admin_credentials_not_set），而不是笼统的 401 ——
// 否则用户会以为是自己密码打错了，对着一个从没设过的密码反复试。
func TestNoCredentialsConfiguredRejectsEverything(t *testing.T) {
	e := newTestEnv(t, "", "") // 既没有 admin_token，也没有 admin_users

	rr := e.do(t, "GET", "/_goproxy/config", "", noAuth())
	if rr.Code != http.StatusForbidden {
		t.Fatalf("无任何凭据时应 403，实际 %d", rr.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是 JSON: %v", err)
	}
	if body["error"] != "admin_credentials_not_set" {
		t.Fatalf("错误码应是 admin_credentials_not_set，实际 %q", body["error"])
	}

	// 即便带了（根本不存在的）令牌也要拒绝
	if rr := e.do(t, "GET", "/_goproxy/config", "",
		header("Authorization", "Bearer whatever")); rr.Code != http.StatusForbidden {
		t.Fatalf("凭据未配置时带任何令牌都应 403，实际 %d", rr.Code)
	}

	// 会话状态接口要如实告诉前端「服务端没配凭据」，
	// 前端的登录页据此给出正确引导而不是「密码错误」
	sess := e.do(t, "GET", "/_goproxy/session", "", noAuth())
	if sess.Code != http.StatusUnauthorized {
		t.Fatalf("/session 未登录应 401，实际 %d", sess.Code)
	}
	var sv map[string]any
	if err := json.Unmarshal(sess.Body.Bytes(), &sv); err != nil {
		t.Fatalf("/session 响应不是 JSON: %v", err)
	}
	if cfg, ok := sv["credentials_configured"].(bool); !ok || cfg {
		t.Fatalf("/session 应报告 credentials_configured=false，实际 %v", sv["credentials_configured"])
	}
}

// TestReverseProxyMarksInternalVia 验证代理侧确实写了标记头，
// 并且会**覆盖**客户端自带的同名头 —— 否则外部请求就能靠伪造它来干扰判断。
func TestReverseProxyMarksInternalVia(t *testing.T) {
	cfg := &Config{
		DefaultPorts: []int{1},
		AdminAddr:    "off",
		Routes: []RouteConfig{{
			ID: "r", ListenPort: 1, PathPrefix: "/", Target: "http://127.0.0.1:9",
		}},
	}
	cfg.applyDefaults()

	tbl, err := buildTable(cfg, nil, newTransport())
	if err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	if len(tbl.routes) != 1 {
		t.Fatalf("应有 1 条路由，实际 %d", len(tbl.routes))
	}

	req := httptest.NewRequest("GET", "http://example.com/x", nil)
	req.Header.Set(internalViaHeader, "客户端瞎写的")
	tbl.routes[0].proxy.Director(req)

	if got := req.Header.Get(internalViaHeader); got != "1" {
		t.Fatalf("代理必须把标记头覆写成 1，实际 %q —— 客户端自带的值没被盖掉", got)
	}
}

func TestAdminConfigEndpoint(t *testing.T) {
	e := newTestEnv(t, testToken, "")

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
	path := filepath.Join(t.TempDir(), "goproxy.db")
	orig := fmt.Sprintf(
		`{"default_ports":[%d],"routes":[{"id":"seed","listen_port":%d,"target":"http://127.0.0.1:9000"}]}`,
		p[0], p[1])
	seedRawConfig(t, path, []byte(orig))

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

	if _, _, err := a.mutate(nil, "", func(cfg *Config) error {
		cfg.Routes = append(cfg.Routes, RouteConfig{
			ID: "added", PathPrefix: "/x", Target: "http://127.0.0.1:9000",
		})
		return nil
	}); err != nil {
		t.Fatalf("mutate 失败: %v", err)
	}

	// 读回的是「库里真正存下的内容」，不是内存里的路由表 ——
	// 这条用例验的正是落库那一刻有没有把留空字段固化。
	raw, _, err := readConfigFile(path)
	if err != nil {
		t.Fatalf("读回配置失败: %v", err)
	}
	if strings.Contains(string(raw), defaultAdminAddr) {
		t.Fatalf("写回不该把留空的 admin_addr 固化成默认值:\n%s", raw)
	}
	var back Config
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("写回的配置不是合法 JSON: %v", err)
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

// ---------- 全局黑名单：自锁护栏 / 管理端口 / 命中测试 ----------

// patchGlobalDeny 用当前 revision 提交一份全局黑名单，返回响应。
func patchGlobalDeny(t *testing.T, e *testEnv, body string, opts ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	rr := e.do(t, "GET", "/_goproxy/config", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("读配置失败: %d %s", rr.Code, rr.Body.String())
	}
	rev := strings.Trim(rr.Header().Get("ETag"), `"`)
	return e.do(t, "PATCH", "/_goproxy/config", body, append([]func(*http.Request){
		header("If-Match", `"`+rev+`"`),
	}, opts...)...)
}

// TestSelfLockoutGuard 守住「别在控制台里把自己关在门外」这道护栏。
//
// 管理端口也在全局黑名单的管辖范围内（这是明确的设计选择），所以在控制台上
// 加一条覆盖自己来源的规则，保存生效后这个控制台就再也打不开了 ——
// 只能登机器改文件重启。写路径必须在落盘之前把它拦下来。
//
// 同时要守住边界：护栏只拦「会锁死自己」的那一条，封别人的地址必须照常能存。
func TestSelfLockoutGuard(t *testing.T) {
	e := newTestEnv(t, testToken, "")

	// 用例里客户端来源固定是 127.0.0.1（见 testEnv.do），所以封回环 = 锁死自己
	rr := patchGlobalDeny(t, e, `{"global_ip_deny": ["127.0.0.0/8"]}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("会锁死自己的规则应当被拒绝（409），实际 %d :: %s", rr.Code, rr.Body.String())
	}
	var bad map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &bad); err != nil {
		t.Fatal(err)
	}
	if bad["error"] != "self_lockout" {
		t.Errorf("错误码应当是 self_lockout，实际 %q", bad["error"])
	}
	// 提示里必须给出退路，否则用户只会觉得「工具不让我干活」。
	// 退路是命令行的导出 / 导入 —— 配置的真源是数据库，没有可手改的文本文件了。
	if !strings.Contains(bad["message"], "-config-import") {
		t.Errorf("提示里应当给出「导出改完再导入」的退路，实际：%s", bad["message"])
	}

	// 关键：护栏必须在落库之前生效。落了库再报错等于已经写坏了。
	raw, _ := readConfigFromDisk(t, e.path)
	if strings.Contains(string(raw), "127.0.0.0/8") {
		t.Error("被拒绝的配置不应落库")
	}

	// 封一个跟客户端无关的地址是合法操作，不能被护栏误伤
	rr = patchGlobalDeny(t, e, `{"global_ip_deny": ["203.0.113.0/24"]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("封别人的地址应当能保存，实际 %d :: %s", rr.Code, rr.Body.String())
	}
}

// TestGlobalDenyAppliesToAdminPort 验证「全局黑名单也作用于管理端口」。
//
// 这是用户明确选定的行为：管理端口不是法外之地。
func TestGlobalDenyAppliesToAdminPort(t *testing.T) {
	e := newTestEnv(t, testToken, "")
	if rr := patchGlobalDeny(t, e, `{"global_ip_deny": ["203.0.113.0/24"]}`); rr.Code != http.StatusOK {
		t.Fatalf("配置全局黑名单失败: %d %s", rr.Code, rr.Body.String())
	}

	// 被封的地址：连管理接口都进不去，连凭据都不必看
	rr := e.do(t, "GET", "/_goproxy/config", "", remote("203.0.113.9:40000"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("全局黑名单必须作用于管理端口，期望 403，实际 %d :: %s", rr.Code, rr.Body.String())
	}
	// 响应体不该回显命中的具体规则：那等于告诉扫描器「你踩到哪条线了」
	if strings.Contains(rr.Body.String(), "203.0.113.0/24") {
		t.Errorf("403 响应不应泄露命中的规则，实际：%s", rr.Body.String())
	}

	// 未被封的地址照常访问
	if rr := e.do(t, "GET", "/_goproxy/config", "", remote("198.51.100.9:40000")); rr.Code != http.StatusOK {
		t.Fatalf("未被封的地址应当正常访问，实际 %d :: %s", rr.Code, rr.Body.String())
	}

	// 静态控制台页面同样在管辖范围内 —— 「作用于管理端口」不能只管接口
	if rr := e.do(t, "GET", "/_goproxy/ui/", "", remote("203.0.113.9:40000")); rr.Code != http.StatusForbidden {
		t.Errorf("控制台静态资源也应被全局黑名单拦住，实际 %d", rr.Code)
	}
}

// TestGlobalDenyBeatsAllRoutes 验证全局黑名单在**业务端口**上的位置：
// 它排在路由匹配之前，所以连匹配不到路由的请求也会被拦。
//
// 这正是「全局」二字的关键：扫描器挨个端口扫过来时压根不会命中任何路由，
// 如果排查放在路由匹配之后，这类流量永远碰不到这份名单 ——
// 而那恰恰是最需要拦下的。
func TestGlobalDenyBeatsAllRoutes(t *testing.T) {
	e := newTestEnv(t, testToken, "")
	if rr := patchGlobalDeny(t, e, `{"global_ip_deny": ["203.0.113.0/24"]}`); rr != nil && rr.Code != 200 {
		t.Fatalf("配置全局黑名单失败: %d %s", rr.Code, rr.Body.String())
	}

	tbl := e.app.table.Load()
	if tbl == nil {
		t.Fatal("路由表未就绪")
	}
	if tbl.globalDeny == nil {
		t.Fatal("全局黑名单没有进入路由表快照")
	}
	// 用业务端口的 handler 打一个**匹配不到路由**的端口/路径组合
	req := httptest.NewRequest("GET", "/whatever", nil)
	req.RemoteAddr = "203.0.113.9:40000"
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyPort{}, 65535))
	rr := httptest.NewRecorder()
	e.app.handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("未匹配路由的请求也应被全局黑名单拦下，期望 403，实际 %d :: %s",
			rr.Code, rr.Body.String())
	}
	// 确认拦它的是全局黑名单而不是 404 分支
	if !strings.Contains(rr.Body.String(), reasonACLGlobalDeny) {
		t.Errorf("拦截原因应当是 %s，实际：%s", reasonACLGlobalDeny, rr.Body.String())
	}
}

// TestACLTestEndpoint 覆盖命中测试接口：GET / POST 两种形式、三层判定结果、
// 以及「不填 ip 就测我自己」。
func TestACLTestEndpoint(t *testing.T) {
	e := newTestEnv(t, testToken,
		`{"id":"guarded","listen_port":0,"path_prefix":"/g","target":"http://127.0.0.1:1",
		  "acl":{"lists":["允许来源","内网例外"]}}`)

	// 先配一条全局黑名单（封的地址与客户端无关，不会被自锁护栏挡下）
	rr := patchGlobalDeny(t, e,
		`{"global_ip_deny":[{"cidr":"203.0.113.0/24","note":"已知扫描源"}]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("配置全局黑名单失败: %d %s", rr.Code, rr.Body.String())
	}

	cases := []struct {
		ip      string
		allowed bool
		layer   string
		rule    string
		note    string
	}{
		{"10.1.2.3", true, "", "", ""},
		{"10.0.0.66", false, layerDeny, "10.0.0.66", ""},
		{"203.0.113.66", false, layerGlobalDeny, "203.0.113.0/24", "已知扫描源"},
		{"192.168.1.9", false, layerAllow, "", ""},
	}
	for _, c := range cases {
		rr := e.do(t, "GET", "/_goproxy/acl/test?ip="+c.ip+"&route_id=guarded", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("ip=%s 命中测试失败: %d %s", c.ip, rr.Code, rr.Body.String())
		}
		var got struct {
			Decision ACLDecision `json:"decision"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		d := got.Decision
		if d.Allowed != c.allowed || d.Layer != c.layer || d.Rule != c.rule {
			t.Errorf("ip=%s：期望 allowed=%v layer=%q rule=%q，实际 allowed=%v layer=%q rule=%q",
				c.ip, c.allowed, c.layer, c.rule, d.Allowed, d.Layer, d.Rule)
		}
		if c.note != "" && d.Note != c.note {
			t.Errorf("ip=%s：备注应当回显以便排查，期望 %q，实际 %q", c.ip, c.note, d.Note)
		}
		if d.RouteID != "guarded" {
			t.Errorf("ip=%s：应当回显套用的路由，实际 %q", c.ip, d.RouteID)
		}
		// 命中测试的价值在于「说清楚为什么」，所以必须带判定过程
		if len(d.Steps) == 0 {
			t.Errorf("ip=%s：命中测试应当带上判定过程", c.ip)
		}
		if d.Message == "" {
			t.Errorf("ip=%s：应当给出给人看的一句话", c.ip)
		}
	}

	// 不填 ip = 测我自己。客户端是 127.0.0.1，三层名单都不拦它。
	rr = e.do(t, "GET", "/_goproxy/acl/test?route_id=guarded", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("测自己失败: %d %s", rr.Code, rr.Body.String())
	}
	var self struct {
		Self     bool        `json:"self"`
		Decision ACLDecision `json:"decision"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &self); err != nil {
		t.Fatal(err)
	}
	if !self.Self {
		t.Error("不填 ip 时应当标记 self=true，界面据此提示「这是你自己」")
	}
	if self.Decision.IP != "127.0.0.1" {
		t.Errorf("测自己应当用请求来源 IP，实际 %q", self.Decision.IP)
	}

	// POST 与 GET 必须等价 —— 两条路径解析到同一个结构，不许各写一套逻辑
	rr = e.do(t, "POST", "/_goproxy/acl/test", `{"ip":"10.0.0.66","route_id":"guarded"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST 形式失败: %d %s", rr.Code, rr.Body.String())
	}
	var viaPost struct {
		Decision ACLDecision `json:"decision"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &viaPost); err != nil {
		t.Fatal(err)
	}
	if viaPost.Decision.Reason != reasonACLRouteDeny ||
		viaPost.Decision.Layer != layerDeny {
		t.Errorf("POST 结果应与 GET 一致，实际 %+v", viaPost.Decision)
	}

	// 不存在的路由要明确 404，不能悄悄按「只测全局」给出一个看似正确的结果
	if rr := e.do(t, "GET", "/_goproxy/acl/test?ip=10.0.0.1&route_id=nope", ""); rr.Code != http.StatusNotFound {
		t.Errorf("不存在的路由应当 404，实际 %d", rr.Code)
	}
	// 非法 IP 要明确 400
	if rr := e.do(t, "GET", "/_goproxy/acl/test?ip=not-an-ip", ""); rr.Code != http.StatusBadRequest {
		t.Errorf("非法 IP 应当 400，实际 %d", rr.Code)
	}
	// 不指定路由 = 只测全局黑名单，这是合法的用法
	rr = e.do(t, "GET", "/_goproxy/acl/test?ip=203.0.113.7", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("只测全局失败: %d %s", rr.Code, rr.Body.String())
	}
	var onlyGlobal struct {
		Decision ACLDecision `json:"decision"`
	}
	json.Unmarshal(rr.Body.Bytes(), &onlyGlobal)
	if onlyGlobal.Decision.Allowed || onlyGlobal.Decision.Layer != layerGlobalDeny {
		t.Errorf("只测全局时也应被全局黑名单拦下，实际 %+v", onlyGlobal.Decision)
	}
	// 而只测全局时，一个白名单外的地址应当是放行的 —— 因为没有套路由名单
	rr = e.do(t, "GET", "/_goproxy/acl/test?ip=192.168.1.9", "")
	json.Unmarshal(rr.Body.Bytes(), &onlyGlobal)
	if !onlyGlobal.Decision.Allowed {
		t.Errorf("不指定路由时不应套用任何路由名单，实际 %+v", onlyGlobal.Decision)
	}
}

// TestLegacyACLBlocksStartup 从「启动」这一层确认旧写法会被拦下。
//
// 上面 TestLegacyACLRejected 直接调了 rejectLegacyACL，这里走完整链路：
// 把旧格式留在 config.json 里，让 NewApp 的一次性导入去读它。
// 这条路径值得单独守住 —— 它是老部署升级时唯一会碰到旧配置的地方。
func TestLegacyACLBlocksStartup(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // 报错里必须出现的迁移线索
	}{
		{"v0.6.x 的 mode+cidrs", `"acl": {"mode": "allow", "cidrs": ["10.0.0.0/8"]}`, "acl.lists"},
		{"v0.7.x 的内联 allow", `"acl": {"allow": ["10.0.0.0/8"]}`, "ip_lists"},
		{"v0.7.x 的内联 deny", `"acl": {"deny": ["10.0.0.0/8"]}`, "ip_lists"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "goproxy.db")
			t.Cleanup(func() { _ = closeStore(dbPath) })

			legacy := `{
  "admin_addr": "127.0.0.1:19099",
  "routes": [{
    "id": "old", "path_prefix": "/", "target": "http://127.0.0.1:9000",
    ` + c.body + `
  }]
}`
			seedLegacyConfigFile(t, dir, []byte(legacy))

			_, err := NewApp(dbPath)
			if err == nil {
				t.Fatal("旧写法必须让加载失败，否则那份名单会静默失效")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("报错应当给出迁移映射（含 %q），实际：%v", c.want, err)
			}
		})
	}
}

// readCfg 直接从配置库里读回配置。
//
// 断言写路径时读库而不是看接口返回值：接口返回的 revision 只能证明
// 「有东西被写下去了」，证明不了写下去的内容是什么。
func readCfg(t *testing.T, e *testEnv) *Config {
	t.Helper()
	_, cfg, err := readConfigFile(e.path)
	if err != nil {
		t.Fatalf("读回配置失败: %v", err)
	}
	return cfg
}

// TestIPListLibraryWritePath 覆盖名单库的完整写路径：
// 新建 → 被路由引用 → 改名（引用要跟着走）→ 删除被引用（必须被拒）→ 解除引用后删除。
//
// 改名那一段是重点。名单名就是引用键，改名如果不同时改写引用，所有引用会在
// 中间态里悬空，而悬空引用过不了 validate —— 保存根本提交不下去，
// 用户看到的是一个「怎么都做不完」的操作。
func TestIPListLibraryWritePath(t *testing.T) {
	e := newTestEnv(t, testToken, "")

	rr := e.do(t, "PATCH", "/_goproxy/config",
		`{"ip_lists":[{"name":"办公网","kind":"allow","rules":["10.0.0.0/8"]},
		              {"name":"扫描源","kind":"deny","rules":["10.0.0.66"]}]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("保存名单库失败: %d %s", rr.Code, rr.Body.String())
	}

	// 列表要能被读回来 —— 路由表单正是靠它列出「可以勾选哪些名单」
	rr = e.do(t, "GET", "/_goproxy/config", "")
	var view struct {
		IPLists []IPListDef `json:"ip_lists"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.IPLists) != 2 || view.IPLists[0].Name != "办公网" || view.IPLists[0].Kind != IPListKindAllow {
		t.Fatalf("GET /_goproxy/config 应当回传名单库，实际 %+v", view.IPLists)
	}

	rr = e.do(t, "PATCH", "/_goproxy/routes/seed", `{"acl":{"lists":["办公网","扫描源"]}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("给路由挂名单失败: %d %s", rr.Code, rr.Body.String())
	}

	// 被引用的名单不能删。这里必须是 409 list_in_use 并点名路由，
	// 而不是让它一路走到 validate 报「引用了不存在的名单」——
	// 后者会让用户以为是引用写错了，而真正发生的是一个删除动作，
	// 两者的下一步操作完全不同。
	rr = e.do(t, "PATCH", "/_goproxy/config",
		`{"ip_lists":[{"name":"办公网","kind":"allow","rules":["10.0.0.0/8"]}]}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("删除被引用的名单应当 409，实际 %d %s", rr.Code, rr.Body.String())
	}
	var conflict struct{ Error, Message string }
	json.Unmarshal(rr.Body.Bytes(), &conflict)
	if conflict.Error != "list_in_use" {
		t.Errorf("错误码应当是 list_in_use，实际 %q", conflict.Error)
	}
	if !strings.Contains(conflict.Message, "扫描源") || !strings.Contains(conflict.Message, "seed") {
		t.Errorf("报错应当点名是哪份名单、被哪条路由用着，实际：%s", conflict.Message)
	}
	// 被拒之后磁盘上一个字都不能动
	if cfg := readCfg(t, e); len(cfg.IPLists) != 2 {
		t.Errorf("保存被拒后磁盘不应变化，实际 ip_lists=%+v", cfg.IPLists)
	}

	// 改名：提交新的名字表 + 声明 rename，服务端要把路由的引用一起改写
	rr = e.do(t, "PATCH", "/_goproxy/config",
		`{"ip_lists":[{"name":"办公网","kind":"allow","rules":["10.0.0.0/8"]},
		              {"name":"爬虫","kind":"deny","rules":["10.0.0.66"]}],
		  "ip_list_renames":{"扫描源":"爬虫"}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("改名失败: %d %s", rr.Code, rr.Body.String())
	}

	cfg := readCfg(t, e)
	if got := cfg.Routes[0].ACL.Lists; len(got) != 2 || got[1] != "爬虫" {
		t.Fatalf("改名应当同步改写路由引用，实际 %v", got)
	}
	// 光看引用还不够：判定必须照旧生效，而且报出来的是新名字
	rr = e.do(t, "GET", "/_goproxy/acl/test?ip=10.0.0.66&route_id=seed", "")
	var hit struct {
		Decision ACLDecision `json:"decision"`
	}
	json.Unmarshal(rr.Body.Bytes(), &hit)
	if hit.Decision.Allowed || hit.Decision.List != "爬虫" {
		t.Errorf("改名后黑名单仍应生效、并报出新名单名，实际 %+v", hit.Decision)
	}

	// 解除引用之后就能删了
	rr = e.do(t, "PATCH", "/_goproxy/routes/seed", `{"acl":{"lists":["办公网"]}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("改引用失败: %d %s", rr.Code, rr.Body.String())
	}
	rr = e.do(t, "PATCH", "/_goproxy/config",
		`{"ip_lists":[{"name":"办公网","kind":"allow","rules":["10.0.0.0/8"]}]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("解除引用后应当能删除，实际 %d %s", rr.Code, rr.Body.String())
	}
	if cfg := readCfg(t, e); len(cfg.IPLists) != 1 {
		t.Errorf("删除后应当只剩一份名单，实际 %+v", cfg.IPLists)
	}
}

// TestIPListDeleteWithoutReferenceIsAllowed 单独钉住「没被引用就能删」。
//
// 与上一条相反的方向：如果删除被一律拒绝，用户就再也没法清理名单库了。
// 拒绝的依据必须**只是**「还在被引用」，不能是「你提交的比原来少」。
func TestIPListDeleteWithoutReferenceIsAllowed(t *testing.T) {
	e := newTestEnv(t, testToken, "")
	if rr := e.do(t, "PATCH", "/_goproxy/config",
		`{"ip_lists":[{"name":"没人用的","kind":"deny","rules":["203.0.113.66"]}]}`); rr.Code != http.StatusOK {
		t.Fatalf("新建失败: %d %s", rr.Code, rr.Body.String())
	}
	if rr := e.do(t, "PATCH", "/_goproxy/config", `{"ip_lists":[]}`); rr.Code != http.StatusOK {
		t.Fatalf("删除没被引用的名单应当允许，实际 %d %s", rr.Code, rr.Body.String())
	}
	if cfg := readCfg(t, e); len(cfg.IPLists) != 0 {
		t.Errorf("名单应当已清空，实际 %+v", cfg.IPLists)
	}
}
