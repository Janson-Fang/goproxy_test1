package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

type ctxKeyPort struct{}

// ctxKeyTLS 标记「这个请求是从 TLS 连接进来的」。
//
// 重定向逻辑必须知道这一点：从明文端口进来的请求要跳到 HTTPS，
// 从 TLS 端口进来的不能再跳，否则就是无限重定向。
type ctxKeyTLS struct{}

// tlsListenerInfo 描述一个端口是否跑 TLS、以及跑什么 TLS 配置。
//
// 一个端口要么全明文要么全 TLS。**不能**在同端口上「客户端说什么就干什么」：
// 那是 TLS 剥离（stripping）的经典入口，也让 ALPN / HSTS 的语义变得不可预测。
type tlsListenerInfo struct {
	enabled bool
	config  *tls.Config
}

// portSpec 是一个端口完整的监听描述：端口号 + 是否 TLS。
type portSpec struct {
	port int
	tls  tlsListenerInfo
}

// ListenerManager 管理多个监听端口，按路由表的变化自动增删。
// 这是「同一 IP 不同端口 → 不同后端」的核心：加一条 listen_port=8081
// 的路由，8081 就自动开起来，不需要改启动参数、不需要重启。
type ListenerManager struct {
	mu      sync.Mutex
	servers map[int]*portServer
}

type portServer struct {
	port int
	ln   net.Listener
	srv  *http.Server
	// tls 表示这个端口是否跑 TLS，以及用的配置。
	tls tlsListenerInfo
}

func NewListenerManager() *ListenerManager {
	return &ListenerManager{servers: make(map[int]*portServer)}
}

// Sync 让实际监听的端口集合与 wanted 一致：多退少补。
//
// specs 里每个端口带了「是否 TLS」的信息。端口集合或 TLS 属性发生变化时
// 都要重建 listener —— 只比对端口号是不够的：把一个端口从明文改成 TLS，
// 端口号没变但必须重新监听，否则改了配置却毫无效果。
func (m *ListenerManager) Sync(specs []portSpec, h http.Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	keep := make(map[int]portSpec, len(specs))
	for _, s := range specs {
		keep[s.port] = s
	}

	// 关掉不再需要的端口，以及 TLS 属性变了的端口
	for p, s := range m.servers {
		want, ok := keep[p]
		if ok && want.tls.enabled == s.tls.enabled {
			continue
		}
		delete(m.servers, p)
		if ok {
			slog.Info("端口的 TLS 属性变化，重新监听", "port", p, "tls", want.tls.enabled)
		} else {
			slog.Info("关闭监听端口", "port", p)
		}
		go func(s *portServer) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = s.srv.Shutdown(ctx)
		}(s)
	}

	// 开新端口
	var firstErr error
	for _, spec := range specs {
		if _, ok := m.servers[spec.port]; ok {
			continue
		}
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", spec.port))
		if err != nil {
			// 端口被占用不应该让整个程序挂掉，记录后继续处理其余端口
			slog.Error("监听端口失败", "port", spec.port, "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("监听端口 %d 失败: %w", spec.port, err)
			}
			continue
		}

		port := spec.port
		serveLn := ln
		if spec.tls.enabled {
			if spec.tls.config == nil {
				// 配了 TLS 却没有配置，说明调用方漏传了。宁可关掉这个端口，
				// 也不能拿明文去接本以为会加密的流量。
				slog.Error("端口标记为 TLS 但缺少 TLS 配置，跳过", "port", port)
				_ = ln.Close()
				if firstErr == nil {
					firstErr = fmt.Errorf("端口 %d 标记为 TLS 但缺少配置", port)
				}
				continue
			}
			serveLn = tls.NewListener(ln, spec.tls.config)
		}

		srv := &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			// 故意不设 WriteTimeout：它会掐断 WebSocket 和大文件下载
			IdleTimeout:    120 * time.Second,
			MaxHeaderBytes: 1 << 20,
			// 把监听端口注入 context，请求处理时才知道该用哪个端口去匹配路由
			BaseContext: func(net.Listener) context.Context {
				ctx := context.WithValue(context.Background(), ctxKeyPort{}, port)
				return context.WithValue(ctx, ctxKeyTLS{}, spec.tls.enabled)
			},
		}
		ps := &portServer{port: port, ln: serveLn, srv: srv, tls: spec.tls}
		m.servers[port] = ps
		go func(ps *portServer) {
			slog.Info("开始监听", "port", ps.port, "tls", ps.tls.enabled)
			if err := ps.srv.Serve(ps.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("监听异常退出", "port", ps.port, "err", err)
			}
		}(ps)
	}

	return firstErr
}

// ShutdownAll 优雅停机：停止接收新连接，等待在途请求处理完（最多等 ctx 到期）。
func (m *ListenerManager) ShutdownAll(ctx context.Context) {
	m.mu.Lock()
	servers := make([]*portServer, 0, len(m.servers))
	for _, s := range m.servers {
		servers = append(servers, s)
	}
	m.servers = make(map[int]*portServer)
	m.mu.Unlock()

	if len(servers) == 0 {
		return
	}
	ports := make([]int, 0, len(servers))
	var wg sync.WaitGroup
	for _, s := range servers {
		ports = append(ports, s.port)
		wg.Add(1)
		go func(s *portServer) {
			defer wg.Done()
			if err := s.srv.Shutdown(ctx); err != nil {
				slog.Warn("关闭端口超时，强制退出", "port", s.port, "err", err)
			}
		}(s)
	}
	wg.Wait()
	sort.Ints(ports)
	slog.Info("所有监听端口已关闭", "ports", ports)
}

func (m *ListenerManager) Ports() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	ports := make([]int, 0, len(m.servers))
	for p := range m.servers {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// PortInfos 返回每个端口的 TLS 属性，供管理接口展示。
func (m *ListenerManager) PortInfos() []PortInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PortInfo, 0, len(m.servers))
	for _, s := range m.servers {
		out = append(out, PortInfo{Port: s.port, TLS: s.tls.enabled})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// PortInfo 是端口状态的管理接口表示。
type PortInfo struct {
	Port int  `json:"port"`
	TLS  bool `json:"tls"`
}

// requestIsTLS 报告请求是否来自 TLS 连接。
func requestIsTLS(r *http.Request) bool {
	if v, ok := r.Context().Value(ctxKeyTLS{}).(bool); ok && v {
		return true
	}
	return r.TLS != nil
}
