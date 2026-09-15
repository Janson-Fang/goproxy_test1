package main

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

// 管理控制台的静态资源。产物由 web/ 目录（React + Vite）构建而来：
//
//	cd web && npm install && npm run build
//
// 构建结果 web/dist 是**提交进仓库**的：go:embed 要求目录必须存在，
// 不提交的话别人 clone 下来直接 go build 会编译失败。
// CI 在打包前会重新构建一遍，保证产物和源码一致。
//
//go:embed all:web/dist
var webDistFS embed.FS

// uiPrefix 是控制台在管理端口上的挂载路径。
// 必须和 web/vite.config.ts 里的 base 保持一致 —— 不一致的话
// index.html 里引用的 /_goproxy/ui/assets/xxx.js 会 404，页面白屏。
const uiPrefix = "/_goproxy/ui/"

var (
	uiOnce    sync.Once
	uiAssets  fs.FS
	uiPresent bool
)

// uiFS 返回 web/dist 的只读视图，第二个返回值表示前端是否已构建。
//
// 前端缺失时不能直接 500：不跑 npm build 只跑 go build 是很常见的用法，
// 这时候该给一页能看懂的指引，而不是一个空白错误。
func uiFS() (fs.FS, bool) {
	uiOnce.Do(func() {
		sub, err := fs.Sub(webDistFS, "web/dist")
		if err != nil {
			return
		}
		if _, err := fs.Stat(sub, "index.html"); err != nil {
			return
		}
		uiAssets = sub
		uiPresent = true
	})
	return uiAssets, uiPresent
}

// uiHandler 托管控制台静态资源，并做 SPA 回落。
//
// 关于鉴权：这个 handler **刻意不经过 adminGuard**。
//
//	控制台页面本身只是一堆公开的前端代码，不含任何机密；而它必须能先加载出来，
//	用户才有机会输入 admin_token。如果连壳都要鉴权，页面会直接 401，
//	形成一个「要令牌才能打开页面、要页面才能填令牌」的死循环。
//	所有真正敏感的东西都在 /_goproxy/* 接口上，那些仍然全部受 adminGuard 保护。
func (a *App) uiHandler() http.Handler {
	sub, ok := uiFS()
	if !ok {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, uiMissingPage, version, commit, uiPrefix)
		})
	}

	// StripPrefix 会把 /_goproxy/ui/assets/x.css 变成 assets/x.css 再交进来，
	// 这样才是相对 embed FS 根目录的路径。
	return http.StripPrefix(uiPrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		name := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if name == "." || name == "" || name == "/" {
			name = "index.html"
		}

		if st, err := fs.Stat(sub, name); err == nil && !st.IsDir() {
			setUICacheHeader(w, name)
			serveUIFile(w, r, sub, name)
			return
		}

		// 既不是文件也不是我们认识的资源 → 交回 index.html，由前端自己决定显示什么。
		// 直接 404 会让「刷新页面后停在 /_goproxy/ui/xxx」这种正常操作变得莫名其妙。
		setUICacheHeader(w, "index.html")
		serveUIFile(w, r, sub, "index.html")
	}))
}

// serveUIFile 从内嵌 FS 里吐一个文件。
//
// 刻意不用 http.FileServer：它对任何以 index.html 结尾的请求都会
// localRedirect("./") 返回 301（为了让 /dir/index.html 规范化成 /dir/）。
// 我们这里的 /_goproxy/ui/index.html 是正常入口，被 301 一下纯属噪音，
// 而且 SPA 回落指向的就是 index.html，会直接变成一次多余的跳转。
func serveUIFile(w http.ResponseWriter, r *http.Request, sub fs.FS, name string) {
	f, err := sub.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	// embed 的文件支持随机访问，交给 ServeContent 就能顺带拿到
	// Range 请求、If-Modified-Since 等标准行为。
	if rs, ok := f.(io.ReadSeeker); ok {
		// 零值 modtime = 不发 Last-Modified。内嵌资源的 mtime 是编译时间，
		// 发出去只会让缓存判断变得难以理解；缓存策略已经由 Cache-Control 决定了。
		http.ServeContent(w, r, name, time.Time{}, rs)
		return
	}

	// 兜底：拿不到 ReadSeeker 就整个读出来
	b, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, "读取静态资源失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeByName(name))
	_, _ = w.Write(b)
}

// contentTypeByName 给兜底分支用。ServeContent 会按扩展名自己推断，
// 这里只需要覆盖 Go 的 mime 表里可能缺失的几种。
func contentTypeByName(name string) string {
	switch path.Ext(name) {
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".html":
		return "text/html; charset=utf-8"
	case ".json":
		return "application/json; charset=utf-8"
	case ".woff2":
		return "font/woff2"
	}
	return "application/octet-stream"
}

// setUICacheHeader 按文件类型给缓存策略。
//
// Vite 产出的 assets 文件名里带内容 hash，内容变了名字就变，
// 所以可以放心 immutable 长缓存；index.html / favicon 必须每次校验，
// 否则发了新版本用户还在用旧的资源清单，表现是「更新了但界面没变」。
func setUICacheHeader(w http.ResponseWriter, name string) {
	if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
}

// wantsHTML 判断这是不是一个「想看网页」的请求。
// 浏览器会带 Accept: text/html；curl、Prometheus、健康检查探针不会。
func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// uiMissingPage 是前端未构建时的提示页。%s 会被替换成 version / commit。
const uiMissingPage = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>goproxy 控制台未构建</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:#0d1117;color:#e6edf3;font:14px/1.7 system-ui,"Microsoft YaHei",sans-serif;padding:24px}
  .box{max-width:660px;background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px 26px}
  h1{margin:0 0 6px;font-size:17px}
  .sub{color:#8b949e;font-size:12.5px;margin-bottom:18px}
  code,pre{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
  pre{background:#010409;border:1px solid #30363d;border-radius:6px;padding:11px 13px;overflow-x:auto}
  ol{padding-left:20px;margin:14px 0}
  li{margin:5px 0}
  a{color:#2f81f7}
  .tip{color:#8b949e;font-size:12.5px;margin-top:16px}
</style></head>
<body><div class="box">
  <h1>管理控制台尚未构建</h1>
  <div class="sub">goproxy %s (commit %s) · 管理接口本身工作正常</div>
  <p>当前二进制里没有打包前端资源，所以这个页面没有界面可用。后端接口不受影响，
     可以继续直接用：<code>/healthz</code>、<code>/metrics</code>、<code>/_goproxy/routes</code> 等。</p>
  <ol>
    <li>在仓库根目录执行前端构建：
      <pre>cd web
npm install
npm run build</pre>
    </li>
    <li>重新编译二进制（<code>go:embed</code> 在编译期读取 <code>web/dist</code>，所以必须先构建前端）：
      <pre>go build -o goproxy .</pre>
    </li>
    <li>重启进程后访问 <code>%s</code>。</li>
  </ol>
  <div class="tip">开发前端时不必每次重新编译 Go：<code>cd web &amp;&amp; npm run dev</code>
    会把管理接口代理到 <code>127.0.0.1:8080</code>，改完立即热更新。</div>
</div></body></html>
`
