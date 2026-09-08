package main

import (
	"context"
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
}

func NewListenerManager() *ListenerManager {
	return &ListenerManager{servers: make(map[int]*portServer)}
}

// Sync 让实际监听的端口集合与 wanted 一致：多退少补。
func (m *ListenerManager) Sync(wanted []int, h http.Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	keep := make(map[int]struct{}, len(wanted))
	for _, p := range wanted {
		keep[p] = struct{}{}
	}

	// 关掉不再需要的端口
	for p, s := range m.servers {
		if _, ok := keep[p]; ok {
			continue
		}
		delete(m.servers, p)
		slog.Info("关闭监听端口", "port", p)
		go func(s *portServer) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = s.srv.Shutdown(ctx)
		}(s)
	}

	// 开新端口
	var firstErr error
	for _, p := range wanted {
		if _, ok := m.servers[p]; ok {
			continue
		}
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			// 端口被占用不应该让整个程序挂掉，记录后继续处理其余端口
			slog.Error("监听端口失败", "port", p, "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("监听端口 %d 失败: %w", p, err)
			}
			continue
		}

		port := p
		srv := &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			// 故意不设 WriteTimeout：它会掐断 WebSocket 和大文件下载
			IdleTimeout:    120 * time.Second,
			MaxHeaderBytes: 1 << 20,
			// 把监听端口注入 context，请求处理时才知道该用哪个端口去匹配路由
			BaseContext: func(net.Listener) context.Context {
				return context.WithValue(context.Background(), ctxKeyPort{}, port)
			},
		}
		ps := &portServer{port: port, ln: ln, srv: srv}
		m.servers[port] = ps
		go func(ps *portServer) {
			slog.Info("开始监听", "port", ps.port)
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
