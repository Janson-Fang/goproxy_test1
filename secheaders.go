package main

// 管理端的安全响应头。
//
// 在此之前管理端**一个安全响应头都没有**（实测确认）。对一个「能改路由、
// 能看全部访问日志」的管理面来说，缺 nosniff / frame-ancestors 是实打实的风险：
//
//   - 没有 nosniff：浏览器可能把上传的或代理回来的内容当脚本执行
//   - 没有 frame-ancestors：控制台可以被嵌进任意站点的 iframe，
//     配合透明的点击劫持就能骗管理员点「删除路由」
//   - 没有 noindex：这个内网地址可能被搜索引擎收录
//
// 这些头集中在一处加，而不是让每个 handler 自己记得加 —— 后者迟早会漏。

import (
	"net/http"
	"strings"
)

// uiCSP 是控制台页面（含静态资源）的内容安全策略。
//
// script-src 收得很紧（'self'，没有 'unsafe-inline'）：这是 CSP 的价值所在，
// 挡住 XSS 最直接的武器 —— 注入一段内联 <script>。为此把 index.html 里
// 原有的一段内联主题脚本抽成了 public/theme.js。
//
// style-src 保留了 'unsafe-inline'，这是个**有意的取舍**：项目里大量使用
// React 的 style={{...}}（例如 App.tsx 用 display:none 切页签），
// 这些是内联 style 属性，会被 style-src 挡掉，页面直接错乱。
// 内联样式能造成的危害远小于内联脚本，所以先保功能。
// 想彻底严格，就把那几处内联样式改写成 class 或 hidden 属性。
//
// connect-src 'self'：控制台的 fetch 和 SSE 都打同一个源（同端口），够了。
// img-src 允许 data: 是为了 favicon 和少量内联图标。
const uiCSP = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'; " +
	"object-src 'none'"

// apiCSP 用于纯 JSON 接口。这些响应本来就不该被当成文档渲染，
// 锁死一切可以让「被诱导直接打开某个接口 URL」也安全。
const apiCSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"

// securityHeaders 给管理端的响应统一加安全头。
//
// 用 Unwrap 无关的方式包在 adminHandler 最外层：无论请求最终落到
// 控制台静态资源、管理接口还是纯文本清单，都会带上这些头。
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// 不让浏览器猜 Content-Type —— 猜错类型是 XSS 的常见入口
		h.Set("X-Content-Type-Options", "nosniff")

		// 管理面不该被任何页面嵌入。这里同时给 X-Frame-Options（老浏览器）
		// 和 CSP 的 frame-ancestors（新浏览器），两条都留。
		h.Set("X-Frame-Options", "DENY")

		// 这是一个内网运维地址，没理由被搜索引擎收录
		h.Set("X-Robots-Tag", "noindex, nofollow")

		// 控制台带 hash 路由（/#/routes），Referer 泄露出去也没用，
		// 但管理地址本身不宜作为来源信息外流
		h.Set("Referrer-Policy", "no-referrer")

		// 管理端不需要任何设备能力
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		// CSP 按「响应类型」分两套。判断依据只能是路径：
		// 到这一步还不知道 handler 会写什么 Content-Type。
		if isAdminAPIPath(r.URL.Path) || isAdminLandingPath(r.URL.Path) {
			h.Set("Content-Security-Policy", apiCSP)
		} else {
			h.Set("Content-Security-Policy", uiCSP)
		}

		next.ServeHTTP(w, r)
	})
}

// wantsPlainText 判断调用方想要纯文本（curl / 监控探针）而不是网页。
// 保留在这里是因为安全头的判断和它无关，但内容协商经常要一起看。
func wantsPlainText(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return accept != "" && !strings.Contains(accept, "text/html")
}
