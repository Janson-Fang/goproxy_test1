package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
)

// doAdmin 直接打管理端的 handler（不起真实端口），并允许伪造 RemoteAddr。
//
// RemoteAddr 必须显式指定：httptest.NewRequest 默认给的是 192.0.2.1:1234，
// 那是个公网测试网段，adminGuard 会把它当外部访问，于是没配令牌的环境
// 一律 403 —— 用它来测「本机免鉴权」会得到完全对不上的结果。
func doAdmin(t *testing.T, env *testEnv, method, target, accept, remoteAddr, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if remoteAddr == "" {
		remoteAddr = "127.0.0.1:34567" // 默认模拟从本机访问
	}
	req.RemoteAddr = remoteAddr
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	env.app.adminHandler().ServeHTTP(rec, req)
	return rec
}

// findAsset 从内嵌的 dist 里挑一个 assets/ 下的真实文件。
// 写死文件名不行 —— Vite 的文件名带内容 hash，每次构建都会变。
func findAsset(t *testing.T) string {
	t.Helper()
	sub, ok := uiFS()
	if !ok {
		t.Fatal("web/dist 未内嵌：前端资源缺失，go:embed 没能取到 index.html")
	}
	var found string
	err := fs.WalkDir(sub, "assets", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || found != "" {
			return nil
		}
		found = path.Join("assets", strings.TrimPrefix(p, "assets/"))
		return nil
	})
	if err != nil || found == "" {
		t.Fatalf("web/dist/assets 下没有文件，前端构建产物不完整: %v", err)
	}
	return found
}

func TestUIConsoleIsEmbeddedAndServed(t *testing.T) {
	env := newTestEnv(t, "", "")

	rec := doAdmin(t, env, http.MethodGet, uiPrefix, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s 期望 200，实际 %d", uiPrefix, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type 应为 text/html，实际 %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `id="root"`) {
		t.Error("返回的不是控制台页面（找不到 #root 挂载点）")
	}
	// 资源引用必须是带 base 的绝对路径，否则上线后 404
	if !strings.Contains(body, uiPrefix+"assets/") {
		t.Errorf("index.html 引用的资源没带 %s 前缀，上线后会 404", uiPrefix)
	}
}

func TestUIAssetsHaveContentHashCacheHeaders(t *testing.T) {
	env := newTestEnv(t, "", "")
	asset := findAsset(t)

	rec := doAdmin(t, env, http.MethodGet, uiPrefix+asset, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s 期望 200，实际 %d", asset, rec.Code)
	}
	cc := rec.Header().Get("Cache-Control")
	if !strings.Contains(cc, "immutable") {
		t.Errorf("带内容 hash 的资源应可长缓存，实际 Cache-Control=%q", cc)
	}

	// index.html 相反：必须每次校验，否则发版后用户还在用旧的资源清单
	rec = doAdmin(t, env, http.MethodGet, uiPrefix+"index.html", "", "", "")
	if cc := rec.Header().Get("Cache-Control"); strings.Contains(cc, "immutable") {
		t.Errorf("index.html 不应长缓存，实际 Cache-Control=%q", cc)
	}
}

// 刷新页面时停在 /_goproxy/ui/routes 这种路径是很正常的操作，
// 不能因为磁盘上没有同名文件就 404。
func TestUISpaFallback(t *testing.T) {
	env := newTestEnv(t, "", "")

	rec := doAdmin(t, env, http.MethodGet, uiPrefix+"routes", "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("未知路径应回落到 index.html，实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Error("回落内容不是控制台入口页")
	}
}

// 浏览器打管理端口根路径要看到界面，curl 要看到接口清单。
func TestRootServesRedirectForBrowserAndTextForCurl(t *testing.T) {
	env := newTestEnv(t, "", "")

	rec := doAdmin(t, env, http.MethodGet, "/", "text/html,application/xhtml+xml", "", "")
	if rec.Code != http.StatusFound {
		t.Fatalf("浏览器访问 / 期望 302，实际 %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != uiPrefix {
		t.Errorf("应重定向到 %s，实际 %q", uiPrefix, loc)
	}

	rec = doAdmin(t, env, http.MethodGet, "/", "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("curl 访问 / 期望 200，实际 %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("curl 拿到的应是纯文本清单，实际 Content-Type=%q", ct)
	}
	if !strings.Contains(rec.Body.String(), "/_goproxy/routes") {
		t.Error("纯文本清单里应列出接口")
	}
}

// 这是控制台鉴权设计的核心约束，必须钉住：
// 静态壳不鉴权（否则浏览器打不开页面就永远没法输入令牌），
// 但所有管理接口仍然必须鉴权。
func TestUIStaticShellIsOpenButAPIsStayGuarded(t *testing.T) {
	const token = "s3cret-admin-token"
	env := newTestEnv(t, token, "")
	const remote = "203.0.113.9:45678" // 非回环 = 外部访问

	// 页面壳：外部可访问
	rec := doAdmin(t, env, http.MethodGet, uiPrefix, "text/html", remote, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("控制台静态页面应在无令牌时也能加载，实际 %d（%s）", rec.Code, rec.Body.String())
	}

	// 资产：外部可访问
	rec = doAdmin(t, env, http.MethodGet, uiPrefix+findAsset(t), "", remote, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("控制台静态资源应在无令牌时也能加载，实际 %d", rec.Code)
	}

	// 管理接口：必须带令牌
	for _, p := range []string{"/_goproxy/routes", "/_goproxy/config", "/_goproxy/stats", "/_goproxy/logs", "/metrics"} {
		rec = doAdmin(t, env, http.MethodGet, p, "", remote, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s 无令牌时应返回 401，实际 %d", p, rec.Code)
		}
		rec = doAdmin(t, env, http.MethodGet, p, "", remote, token)
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Errorf("%s 带正确令牌时不应被拒，实际 %d", p, rec.Code)
		}
	}

	// 伪造 X-Forwarded-For 不能骗过鉴权：认证只看 RemoteAddr
	req := httptest.NewRequest(http.MethodGet, "/_goproxy/routes", nil)
	req.RemoteAddr = remote
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec2 := httptest.NewRecorder()
	env.app.adminHandler().ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("伪造 X-Forwarded-For 冒充本机必须失败，实际 %d", rec2.Code)
	}
}

func TestAdminTokenNotSetRejectsExternal(t *testing.T) {
	env := newTestEnv(t, "", "") // 非回环 + 没配令牌

	rec := doAdmin(t, env, http.MethodGet, "/_goproxy/routes", "", "203.0.113.9:45678", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("未配令牌时外部请求应被拒（403），实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "admin_token_not_set") {
		t.Errorf("应返回可识别的错误码，实际 %s", rec.Body.String())
	}
}

func TestRootPlainTextListsUIPath(t *testing.T) {
	env := newTestEnv(t, "", "")
	rec := doAdmin(t, env, http.MethodGet, "/", "", "", "")
	if !strings.Contains(rec.Body.String(), uiPrefix) {
		t.Errorf("接口清单里应提示控制台地址 %s", uiPrefix)
	}
}

// 管理端上任何「人在找控制台」的地址都要进控制台，而不只是根路径。
//
// 这里每一条都是真实踩过的：/_goproxy/ 是最容易手写的猜测，
// /index.html 和 /dashboard 是顺手敲的，以前全部落进纯文本接口清单，
// 表现就是「控制台明明做好了，直接访问却没有」。
func TestAdminPrefixPathsSendBrowserToConsole(t *testing.T) {
	env := newTestEnv(t, "", "")
	const html = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

	for _, p := range []string{"/_goproxy/", "/_goproxy", "/index.html", "/dashboard", "/anything"} {
		rec := doAdmin(t, env, http.MethodGet, p, html, "", "")
		if rec.Code != http.StatusFound {
			t.Errorf("浏览器访问 %s 期望 302 到控制台，实际 %d", p, rec.Code)
			continue
		}
		if loc := rec.Header().Get("Location"); loc != uiPrefix {
			t.Errorf("浏览器访问 %s 应重定向到 %s，实际 %q", p, uiPrefix, loc)
		}
	}

	// 落地页：curl（不带 text/html）要拿到纯文本清单，
	// 这样运维不用翻文档也知道接口长什么样、真正的控制台在哪个地址。
	for _, p := range []string{"/", "/_goproxy", "/_goproxy/"} {
		rec := doAdmin(t, env, http.MethodGet, p, "*/*", "", "")
		if rec.Code != http.StatusOK {
			t.Errorf("curl 访问 %s 期望 200 纯文本清单，实际 %d", p, rec.Code)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
			t.Errorf("curl 访问 %s 应拿到纯文本，实际 Content-Type=%q", p, ct)
		}
		if !strings.Contains(rec.Body.String(), uiPrefix) {
			t.Errorf("curl 访问 %s 的清单里应写出控制台地址 %s", p, uiPrefix)
		}
	}

	// 其余非落地页的地址对 curl 就是 404，不再伪装成「成功」。
	for _, p := range []string{"/index.html", "/dashboard", "/anything"} {
		rec := doAdmin(t, env, http.MethodGet, p, "*/*", "", "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("curl 访问非落地页 %s 期望 404，实际 %d", p, rec.Code)
		}
	}
}

// 反过来钉住：接口路径**不能**因为带 text/html 就被重定向。
// 浏览器直接打开 /_goproxy/routes 就是要看到 JSON。
func TestAdminAPIsAreNotRedirectedForBrowserAccept(t *testing.T) {
	env := newTestEnv(t, "", "")
	const html = "text/html,application/xhtml+xml"

	for _, p := range []string{"/_goproxy/routes", "/_goproxy/ports", "/_goproxy/stats", "/_goproxy/config", "/healthz", "/readyz", "/metrics"} {
		rec := doAdmin(t, env, http.MethodGet, p, html, "", "")
		if rec.Code == http.StatusFound && rec.Header().Get("Location") == uiPrefix {
			t.Errorf("接口 %s 被重定向到控制台了，浏览器将拿不到数据", p)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("接口 %s 期望 200，实际 %d", p, rec.Code)
		}
	}
}

// 拼错的接口地址必须响亮地 404。兜底的 "/" 曾经让所有未知路径回 200 + 清单，
// 于是 `curl -f /_goproxy/statss` 看着像成功。
func TestUnknownAdminPathIsNotFoundForNonHTML(t *testing.T) {
	env := newTestEnv(t, "", "")

	rec := doAdmin(t, env, http.MethodGet, "/_goproxy/statss", "*/*", "", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("写错的接口路径对 curl 应返回 404，实际 %d（%s）", rec.Code, rec.Body.String())
	}

	// 位置参数写法漏掉后半个括号 / 多带了斜杠也一样
	rec = doAdmin(t, env, http.MethodGet, "/_goproxy/routes/", "*/*", "", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("/_goproxy/routes/ 应返回 404（精确匹配）, 实际 %d", rec.Code)
	}

	// 但 /healthz 这类前缀相同的合法接口不能被误伤
	rec = doAdmin(t, env, http.MethodGet, "/healthz", "*/*", "", "")
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz 应正常返回 200，实际 %d", rec.Code)
	}
}

// 保证 fs.FS 的路径清洗没被绕过：embed FS 本身拒绝含 .. 的路径，
// 这里再确认一次请求不会穿透到别的目录。
func TestUIPathTraversalIsContained(t *testing.T) {
	env := newTestEnv(t, "", "")
	for _, p := range []string{uiPrefix + "../../config.go", uiPrefix + "..%2f..%2fconfig.go"} {
		rec := doAdmin(t, env, http.MethodGet, p, "", "", "")
		if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "package main") {
			t.Fatalf("%s 泄漏了源码", p)
		}
	}
}
