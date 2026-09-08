package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type App struct {
	cfgPath   string
	transport *http.Transport
	listeners *ListenerManager
	metrics   *Metrics
	table     atomic.Pointer[RouteTable]

	mu        sync.Mutex
	trusted   []*net.IPNet
	adminAddr string
	lastMod   time.Time
	lastSize  int64

	accessLog atomic.Bool
}

func NewApp(cfgPath string) (*App, error) {
	st, err := os.Stat(cfgPath)
	if err != nil {
		return nil, err
	}
	return &App{
		cfgPath:   cfgPath,
		transport: newTransport(),
		listeners: NewListenerManager(),
		metrics:   NewMetrics(),
		lastMod:   st.ModTime(),
		lastSize:  st.Size(),
	}, nil
}

// reload 重新加载配置并原子替换路由表。
// 整个过程不停机：旧请求继续用旧表跑完，新请求用新表。
func (a *App) reload() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	cfg, err := loadConfig(a.cfgPath)
	if err != nil {
		return err
	}
	nets, err := cfg.trustedNets()
	if err != nil {
		return err
	}

	old := a.table.Load()
	tbl, err := buildTable(cfg, old, a.transport)
	if err != nil {
		return err
	}

	// 释放已经不存在的路由上的限流器（它们各自跑着清理 goroutine）
	if old != nil {
		live := make(map[string]struct{}, len(tbl.routes))
		for _, r := range tbl.routes {
			live[r.ID] = struct{}{}
		}
		for _, r := range old.routes {
			if _, ok := live[r.ID]; !ok && r.limiter != nil {
				r.limiter.Close()
			}
		}
	}

	a.trusted = nets
	a.adminAddr = cfg.AdminAddr
	a.accessLog.Store(cfg.AccessLog)
	a.table.Store(tbl)

	if err := a.listeners.Sync(tbl.ListenPorts(), a.handler()); err != nil {
		// 单个端口失败不影响其它端口，只告警
		slog.Warn("部分端口监听失败", "err", err)
	}
	a.metrics.SetRouteCount(len(tbl.routes))
	a.metrics.IncReload()
	slog.Info("配置已生效",
		"routes", len(tbl.routes),
		"ports", tbl.ListenPorts(),
		"admin", cfg.AdminAddr)
	return nil
}

// handler 是所有监听端口共用的入口。端口从 context 里取。
func (a *App) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		port := 0
		if v, ok := r.Context().Value(ctxKeyPort{}).(int); ok {
			port = v
		}

		tbl := a.table.Load()
		if tbl == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "路由表尚未就绪"})
			return
		}

		rt := tbl.Match(port, r.Host, r.URL.Path)
		if rt == nil {
			a.metrics.IncRequest("", http.StatusNotFound)
			writeJSON(w, http.StatusNotFound, map[string]any{
				"error": "no_route_matched",
				"port":  port,
				"host":  r.Host,
				"path":  r.URL.Path,
			})
			slog.Debug("未匹配到路由", "port", port, "host", r.Host, "path", r.URL.Path)
			return
		}

		ip := clientIP(r, a.trusted)
		if rt.limiter != nil && !rt.limiter.Allow(ip) {
			a.metrics.IncRateLimited(rt.ID)
			a.metrics.IncRequest(rt.ID, http.StatusTooManyRequests)
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": "rate_limited",
				"route": rt.ID,
			})
			return
		}

		a.metrics.IncInFlight(rt.ID)
		rec := newStatusRecorder(w)
		rt.proxy.ServeHTTP(rec, r)
		a.metrics.DecInFlight(rt.ID)

		dur := time.Since(start).Seconds()
		a.metrics.Observe(rt.ID, dur)
		a.metrics.IncRequest(rt.ID, rec.code)

		if a.accessLog.Load() {
			slog.Info("access",
				"route", rt.ID,
				"port", port,
				"host", r.Host,
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.code,
				"dur_ms", int(dur*1000),
				"client_ip", ip,
				"ua", r.UserAgent(),
			)
		}
	})
}

// adminHandler 管理端口：健康检查、指标、路由查看、手动重载。
func (a *App) adminHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if a.table.Load() == nil {
			http.Error(w, "route table not ready", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		io.WriteString(w, a.metrics.Render())
	})
	mux.HandleFunc("/_goproxy/routes", func(w http.ResponseWriter, r *http.Request) {
		tbl := a.table.Load()
		type item struct {
			ID         string  `json:"id"`
			Name       string  `json:"name"`
			ListenPort int     `json:"listen_port"`
			Host       string  `json:"host"`
			PathPrefix string  `json:"path_prefix"`
			Target     string  `json:"target"`
			RateRPS    float64 `json:"rate_rps,omitempty"`
		}
		out := []item{}
		if tbl != nil {
			for _, rt := range tbl.routes {
				it := item{
					ID:         rt.ID,
					Name:       rt.Name,
					ListenPort: rt.ListenPort,
					Host:       rt.Host,
					PathPrefix: rt.PathPrefix,
					Target:     rt.Target,
				}
				if rt.limiter != nil {
					it.RateRPS = rt.limiter.rate
				}
				out = append(out, it)
			}
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("/_goproxy/ports", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.listeners.Ports())
	})
	mux.HandleFunc("/_goproxy/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		if err := a.reload(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ports": a.listeners.Ports()})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "goproxy admin\n  /healthz  /readyz  /metrics\n"+
			"  /_goproxy/routes  当前路由表\n"+
			"  /_goproxy/ports   当前监听端口\n"+
			"  /_goproxy/reload  POST 手动重载配置\n")
	})
	return mux
}

// watchLoop 轮询配置文件 mtime，变了就热重载。
// 用轮询而不是 fsnotify / SIGHUP，是为了让 demo 在 Linux 和 Windows 上行为一致。
func (a *App) watchLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st, err := os.Stat(a.cfgPath)
			if err != nil {
				continue
			}
			a.mu.Lock()
			changed := st.ModTime().After(a.lastMod) || st.Size() != a.lastSize
			if changed {
				a.lastMod = st.ModTime()
				a.lastSize = st.Size()
			}
			a.mu.Unlock()
			if changed {
				slog.Info("检测到配置变化，开始热重载")
				if err := a.reload(); err != nil {
					slog.Error("热重载失败", "err", err)
				}
			}
		}
	}
}

func (a *App) Run(ctx context.Context) error {
	if err := a.reload(); err != nil {
		return err
	}

	a.mu.Lock()
	adminAddr := a.adminAddr
	a.mu.Unlock()

	var adminSrv *http.Server
	if adminAddr != "" {
		adminSrv = &http.Server{
			Addr:              adminAddr,
			Handler:           a.adminHandler(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		ln, err := net.Listen("tcp", adminAddr)
		if err != nil {
			return err
		}
		go func() {
			slog.Info("管理端口已启动", "addr", adminAddr)
			if err := adminSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				slog.Error("管理端口异常退出", "err", err)
			}
		}()
	}

	go a.watchLoop(ctx)

	<-ctx.Done()
	slog.Info("收到退出信号，开始优雅停机")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a.listeners.ShutdownAll(shutdownCtx)
	if adminSrv != nil {
		_ = adminSrv.Shutdown(shutdownCtx)
	}
	slog.Info("已停机")
	return nil
}

func main() {
	cfgPath := flag.String("c", "config.json", "配置文件路径")
	logLevel := flag.String("log-level", "info", "日志级别: debug|info|warn|error")
	textLog := flag.Bool("text-log", false, "输出人类可读日志（默认 JSON）")
	flag.Parse()

	var lvl slog.Level
	switch *logLevel {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if *textLog {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(h))

	app, err := NewApp(*cfgPath)
	if err != nil {
		slog.Error("初始化失败", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx); err != nil {
		slog.Error("运行失败", "err", err)
		os.Exit(1)
	}
}
