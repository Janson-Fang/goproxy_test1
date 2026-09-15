package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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

	// logs 是访问记录的内存环形缓冲，管理台的实时日志与 SSE 都读它。
	logs *logBuffer

	mu        sync.Mutex
	adminAddr string
	lastMod   time.Time
	lastSize  int64

	// adminToken 管理接口令牌。只从回环访问时不需要，非回环必须带。
	adminToken string

	// writeMu 串行化「读配置 → 改 → 写回 → 热重载」这一个事务，
	// 防止两个并发写各自读到旧文件、互相覆盖（经典 lost update）。
	// 单独一把锁而不复用 mu：写事务会先拿 writeMu，再在 reload() 里拿 mu,
	// 加锁顺序固定单向，不会成环。
	writeMu sync.Mutex

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
		logs:      newLogBuffer(logRingSize),
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
	// 可信代理网段挂进快照。这里还没 Store，没有并发读者，不需要额外同步。
	tbl.trusted = nets

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

	// 显式关掉管理端口时存空串，Run() 里判空即可，不用再判断一次哨兵
	if cfg.adminEnabled() {
		a.adminAddr = cfg.AdminAddr
	} else {
		a.adminAddr = ""
	}
	a.adminToken = cfg.AdminToken
	a.accessLog.Store(cfg.AccessLog)
	a.table.Store(tbl)

	if err := a.listeners.Sync(tbl.ListenPorts(), a.handler()); err != nil {
		// 单个端口失败不影响其它端口，只告警
		slog.Warn("部分端口监听失败", "err", err)
	}
	a.metrics.SetRouteCount(len(tbl.routes))
	a.metrics.IncReload()
	adminShown := a.adminAddr
	if adminShown == "" {
		adminShown = "(已关闭)"
	}
	slog.Info("配置已生效",
		"routes", len(tbl.routes),
		"ports", tbl.ListenPorts(),
		"admin", adminShown)
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

		// 状态码在这一层统一记录：转发分支之外的 ACL / 限流 / 熔断 / 认证
		// 也会提前返回，只有包住整个 handler 才能把它们的状态码一起拿到。
		rec := newStatusRecorder(w)

		tbl := a.table.Load()
		var trusted []*net.IPNet
		if tbl != nil {
			trusted = tbl.trusted
		}
		ip := clientIP(r, trusted)

		// 每次请求只记一条访问日志，所以收口在 defer 里，
		// 而不是在下面 5 个 return 分支各写一遍（漏一处就少一类日志）。
		var (
			rt      *Route
			blocked string
		)
		defer func() {
			a.logAccess(r, port, rt, blocked, ip, rec.code, start)
		}()

		if tbl == nil {
			writeJSON(rec, http.StatusServiceUnavailable, map[string]string{"error": "路由表尚未就绪"})
			return
		}

		rt = tbl.Match(port, r.Host, r.URL.Path)
		if rt == nil {
			a.metrics.IncRequest("", http.StatusNotFound)
			writeJSON(rec, http.StatusNotFound, map[string]any{
				"error": "no_route_matched",
				"port":  port,
				"host":  r.Host,
				"path":  r.URL.Path,
			})
			slog.Debug("未匹配到路由", "port", port, "host", r.Host, "path", r.URL.Path)
			return
		}

		// 1) IP 黑白名单
		if rt.acl != nil && !rt.acl.Allowed(ip) {
			blocked = "acl"
			a.metrics.IncRejected(rt.ID, "acl")
			a.metrics.IncRequest(rt.ID, http.StatusForbidden)
			writeJSON(rec, http.StatusForbidden, map[string]any{
				"error":  "forbidden",
				"route":  rt.ID,
				"reason": "ip_not_allowed",
			})
			return
		}

		// 2) 限流
		if rt.limiter != nil && !rt.limiter.Allow(ip) {
			blocked = "rate_limited"
			a.metrics.IncRateLimited(rt.ID)
			a.metrics.IncRequest(rt.ID, http.StatusTooManyRequests)
			rec.Header().Set("Retry-After", "1")
			writeJSON(rec, http.StatusTooManyRequests, map[string]any{
				"error": "rate_limited",
				"route": rt.ID,
			})
			return
		}

		// 3) 熔断：后端已经不行了就别再打了，直接快速失败
		if rt.cb != nil && !rt.cb.Allow() {
			blocked = "circuit_open"
			a.metrics.IncRejected(rt.ID, "circuit_open")
			a.metrics.IncRequest(rt.ID, http.StatusServiceUnavailable)
			retryAfter := rt.cb.cfg.OpenSecs
			if retryAfter < 1 {
				retryAfter = 1
			}
			rec.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeJSON(rec, http.StatusServiceUnavailable, map[string]any{
				"error":       "circuit_open",
				"route":       rt.ID,
				"retry_after": retryAfter,
			})
			return
		}

		// 4) 认证
		if rt.auth != nil {
			claims, ok, reason := rt.auth.Authenticate(r)
			if !ok {
				blocked = "auth_" + reason
				rt.auth.WriteChallenge(rec)
				a.metrics.IncRejected(rt.ID, "auth_"+reason)
				a.metrics.IncRequest(rt.ID, http.StatusUnauthorized)
				writeJSON(rec, http.StatusUnauthorized, map[string]any{
					"error":  "unauthorized",
					"route":  rt.ID,
					"reason": reason,
				})
				return
			}
			rt.auth.OnSuccess(r, claims)
		}

		// 5) 转发
		a.metrics.IncInFlight(rt.ID)
		rt.proxy.ServeHTTP(rec, r)
		a.metrics.DecInFlight(rt.ID)

		if rt.cb != nil {
			rt.cb.Record(isBackendFailure(rec.code))
		}

		a.metrics.Observe(rt.ID, time.Since(start).Seconds())
		a.metrics.IncRequest(rt.ID, rec.code)
	})
}

// logAccess 把一条访问记录同时送进内存环形缓冲和结构化日志。
//
// 两者的开关是分开的，这是有意的：
//   - 环形缓冲始终记录（定长 500 条、只占内存、不落盘），管理台的实时日志靠它，
//     关掉的话界面直接空掉；
//   - access_log 控制的是标准输出那条日志，量大了或者要接日志系统时由它决定。
func (a *App) logAccess(r *http.Request, port int, rt *Route, blocked, ip string, status int, start time.Time) {
	e := LogEntry{
		Time:     formatLogTime(start),
		Port:     port,
		Host:     r.Host,
		Method:   r.Method,
		Path:     r.URL.Path,
		Query:    r.URL.RawQuery,
		Status:   status,
		DurMs:    float64(time.Since(start).Microseconds()) / 1000,
		ClientIP: ip,
		UA:       r.UserAgent(),
		Blocked:  blocked,
	}
	if rt != nil {
		e.Route = rt.ID
		e.RouteName = rt.Name
	}
	a.logs.Add(e)

	if !a.accessLog.Load() {
		return
	}
	slog.Info("access",
		"route", e.Route,
		"port", port,
		"host", r.Host,
		"method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"dur_ms", int(e.DurMs),
		"client_ip", ip,
		"blocked", blocked,
		"ua", r.UserAgent(),
	)
}

// adminHandler 管理端口的总入口。
//
// 分成两层是有意为之：
//
//	/_goproxy/ui/  控制台静态资源，不鉴权（理由见 webui.go 的 uiHandler）
//	其余全部       健康检查、指标、管理接口，一律走 adminGuard
//
// 顶层的 "/" 只做一件事：浏览器访问管理端口根路径时 302 到控制台。
// curl / 监控探针不带 Accept: text/html，拿到的仍是原来的纯文本接口清单。
func (a *App) adminHandler() http.Handler {
	guarded := a.adminGuard(a.adminMux())

	root := http.NewServeMux()
	root.Handle(uiPrefix, a.uiHandler())
	root.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && wantsHTML(r) {
			if _, ok := uiFS(); ok {
				http.Redirect(w, r, uiPrefix, http.StatusFound)
				return
			}
		}
		guarded.ServeHTTP(w, r)
	})
	return root
}

// adminMux 是真正的管理接口集合，整体由 adminGuard 保护。
func (a *App) adminMux() *http.ServeMux {
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
	// 路由与全局配置的读写接口（实现见 admin_api.go）
	mux.HandleFunc("GET /_goproxy/routes", a.handleListRoutes)
	mux.HandleFunc("POST /_goproxy/routes", a.handleCreateRoute)
	mux.HandleFunc("GET /_goproxy/routes/{id}", a.handleGetRoute)
	mux.HandleFunc("PUT /_goproxy/routes/{id}", a.handleReplaceRoute)
	mux.HandleFunc("PATCH /_goproxy/routes/{id}", a.handlePatchRoute)
	mux.HandleFunc("DELETE /_goproxy/routes/{id}", a.handleDeleteRoute)
	mux.HandleFunc("GET /_goproxy/config", a.handleGetConfig)
	mux.HandleFunc("PATCH /_goproxy/config", a.handlePatchConfig)
	// 管理台的数据源（实现见 stats.go）
	mux.HandleFunc("GET /_goproxy/stats", a.handleStats)
	mux.HandleFunc("GET /_goproxy/logs", a.handleLogs)
	mux.HandleFunc("GET /_goproxy/events", a.handleEvents)
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
		io.WriteString(w, "goproxy admin\n"+
			"  浏览器访问 /            → 管理控制台（"+uiPrefix+"）\n"+
			"  /healthz  /readyz  /metrics\n"+
			"  /_goproxy/routes          GET 列出路由  POST 新建\n"+
			"  /_goproxy/routes/{id}     GET / PUT / PATCH(局部改) / DELETE\n"+
			"  /_goproxy/config          GET / PATCH 全局配置\n"+
			"  /_goproxy/ports           当前监听端口\n"+
			"  /_goproxy/stats           聚合状态（指标 + 采样曲线 + 熔断计数）\n"+
			"  /_goproxy/logs            最近访问记录  ?limit=N\n"+
			"  /_goproxy/events          实时访问日志（SSE）\n"+
			"  /_goproxy/reload          POST 手动重载配置\n")
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

// statsLoop 定期把熔断器状态同步到指标。
// 熔断状态是「当前值」而不是累加值，只能采样，不能靠请求触发。
func (a *App) statsLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tbl := a.table.Load()
			if tbl == nil {
				continue
			}
			states := make(map[string]int, len(tbl.routes))
			for _, r := range tbl.routes {
				if r.cb == nil {
					continue
				}
				states[r.ID] = int(r.cb.State())
				a.metrics.SetCBStats(r.ID, r.cb.openedTotal.Load(), r.cb.rejectedTotal.Load())
			}
			a.metrics.SetCircuitStates(states)
		}
	}
}

// sampleLoop 每秒采一个点，保留最近 5 分钟的 QPS / 错误率曲线。
//
// 采样放在服务端而不是让前端攒：界面一打开就该有历史曲线，
// 否则刷新一次页面曲线就从头开始长，没法判断「刚才那波错误还在不在」。
func (a *App) sampleLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.metrics.Sample(now)
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
	go a.statsLoop(ctx)
	go a.sampleLoop(ctx)

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

// 编译时通过 -ldflags "-X main.version=... -X main.commit=..." 注入
var (
	version = "dev"
	commit  = "none"
)

func main() {
	cfgPath := flag.String("c", "config.json", "配置文件路径")
	logLevel := flag.String("log-level", "info", "日志级别: debug|info|warn|error")
	textLog := flag.Bool("text-log", false, "输出人类可读日志（默认 JSON）")
	showVer := flag.Bool("version", false, "打印版本信息并退出")
	flag.Parse()

	if *showVer {
		fmt.Printf("goproxy %s (commit %s)\n", version, commit)
		return
	}

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
