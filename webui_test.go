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
