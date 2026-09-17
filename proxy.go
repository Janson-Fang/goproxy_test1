package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

// internalViaHeader 由本进程的代理在转发请求时**无条件写入**，
// 用来标记「这个请求是经我自己代理进来的」。
//
// 为什么需要它：管理端对来自回环地址的请求免认证（保留本机 curl / 脚本的运维习惯），
// 而代理转发恰恰是从 127.0.0.1 发出的 —— 于是「把一条路由的 target 指向管理端口」
// 就等于让外部客户端白拿一份免认证的管理权限：改路由、读全部访问日志、改配置。
//
// 管理端只要看到这个头，就必须按「外部请求」处理，绝不因为来源是回环就放行。
//
// 这个头**不需要保密**，也不该靠保密来生效：
//   - 伪造它只会让判断更严格，对攻击者不利；
//   - 省略它也躲不开 —— 经代理进来的请求，Director 一定会写进去。
//
// 值只是个占位；判断只认「有没有」。
const internalViaHeader = "X-Goproxy-Internal-Via"

// newTransport 返回一个调优过的连接池。所有路由共享同一个 Transport，
// 这样后端连接才能复用；只有配了 route 级超时才 Clone 一份独立的。
func newTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          2000,
		MaxIdleConnsPerHost:   512,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ForceAttemptHTTP2:     true,
	}
}

func newReverseProxy(r *Route, tr *http.Transport) *httputil.ReverseProxy {
	target := r.targetURL

	return &httputil.ReverseProxy{
		Transport: tr,

		// -1 = 收到后端数据立刻 flush 给客户端。
		// 这是 SSE / 流式响应能正常工作的关键（默认 0 会一直缓冲）。
		FlushInterval: -1,

		Director: func(req *http.Request) {
			originalHost := req.Host
			originalPath := req.URL.Path

			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host

			p := originalPath
			if r.StripPrefix && r.PathPrefix != "/" {
				p = strings.TrimPrefix(p, r.PathPrefix)
				if !strings.HasPrefix(p, "/") {
					p = "/" + p
				}
			}
			req.URL.Path = singleJoin(target.Path, p)
			// RawQuery 原样保留

			if !r.PreserveHost {
				req.Host = target.Host
			}

			// X-Forwarded-For 由 ReverseProxy 自动追加，这里补其余三个头
			if originalHost != "" {
				req.Header.Set("X-Forwarded-Host", originalHost)
			}
			if req.TLS != nil {
				req.Header.Set("X-Forwarded-Proto", "https")
			} else {
				req.Header.Set("X-Forwarded-Proto", "http")
			}
			if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				req.Header.Set("X-Real-IP", host)
			}

			// 标记「这是本进程代理转发的」。Set 会覆盖客户端自带的同名头，
			// 所以外部请求无法靠伪造这个头来改变管理端的判断（见 internalViaHeader）。
			// 必须在所有 header 覆盖完成之后写，避免被后续操作覆盖掉。
			req.Header.Set(internalViaHeader, "1")
		},

		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			slog.Error("后端请求失败",
				"route", r.ID, "target", target.String(),
				"path", req.URL.Path, "err", err)
			writeJSON(rw, http.StatusBadGateway, map[string]any{
				"error":  "bad_gateway",
				"route":  r.ID,
				"detail": err.Error(),
			})
		},
	}
}

// singleJoin 拼接 target 的 base path 与请求路径，避免出现 // 或漏掉 /。
func singleJoin(base, p string) string {
	if base == "" {
		return p
	}
	aslash := strings.HasSuffix(base, "/")
	bslash := strings.HasPrefix(p, "/")
	switch {
	case aslash && bslash:
		return base + p[1:]
	case !aslash && !bslash:
		return base + "/" + p
	}
	return base + p
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// clientIP 解析客户端真实 IP。
// 只有当直连者（RemoteAddr）在 trusted 列表里时，才信任 X-Forwarded-For；
// 否则直接伪造 XFF 就能绕过限流和 IP 黑名单。
func clientIP(r *http.Request, trusted []*net.IPNet) string {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	ip := net.ParseIP(remote)
	if ip == nil || !ipInNets(ip, trusted) {
		return remote
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remote
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		if p := net.ParseIP(candidate); p != nil && !ipInNets(p, trusted) {
			return candidate
		}
	}
	return remote
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// statusRecorder 包装 ResponseWriter 记录状态码。
// 必须实现 Hijacker 和 Flusher，否则 WebSocket 升级会失败
// （ReverseProxy 内部会对 ResponseWriter 做类型断言）。
type statusRecorder struct {
	http.ResponseWriter
	code    int
	written bool
}

func newStatusRecorder(w http.ResponseWriter) *statusRecorder {
	return &statusRecorder{ResponseWriter: w, code: http.StatusOK}
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.written {
		s.code = code
		s.written = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.written = true
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("当前 ResponseWriter 不支持 hijack")
}
