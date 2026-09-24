package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

const (
	logsDefaultLimit = 200
	logsMaxLimit     = 1000

	// sseHeartbeat 是 SSE 的空闲心跳间隔。
	// 不心跳的话，中间的反向代理 / 负载均衡会认为连接闲置而把它掐掉，
	// 表现是日志页每隔一两分钟莫名其妙断一次。
	sseHeartbeat = 20 * time.Second
)

// cbCounts 是熔断器状态统计。
type cbCounts struct {
	Closed   int   `json:"closed"`
	Open     int   `json:"open"`
	HalfOpen int   `json:"half_open"`
	Tripped  int64 `json:"tripped_total"`
	Rejected int64 `json:"rejected_total"`
}

type logStats struct {
	Buffered    int    `json:"buffered"`
	Capacity    int    `json:"capacity"`
	Subscribers int    `json:"subscribers"`
	Dropped     uint64 `json:"dropped"`
	LatestSeq   uint64 `json:"latest_seq"`
}

// statsResponse 是 GET /_goproxy/stats 的返回体。
//
// 一次请求把所有看板要的数字都给全：管理台刷新频率不低，
// 拆成好几个接口只会让前端做并发编排，还容易拿到互相矛盾的时刻快照。
type statsResponse struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	Now        string `json:"now"`
	StartedAt  string `json:"started_at"`
	UptimeSecs int64  `json:"uptime_seconds"`

	ConfigPath       string `json:"config_path"`
	ConfigRevision   string `json:"config_revision,omitempty"`
	RoutesConfigured int    `json:"routes_configured"`
	RoutesActive     int    `json:"routes_active"`
	Ports            []int  `json:"ports"`
	ReloadTotal      int64  `json:"reload_total"`

	Summary Summary       `json:"summary"`
	Circuit cbCounts      `json:"circuit"`
	Series  []seriesPoint `json:"series"`
	Logs    logStats      `json:"logs"`
}

func (a *App) handleStats(w http.ResponseWriter, r *http.Request) {
	subs, dropped := a.logs.Stats()
	resp := statsResponse{
		Version:     version,
		Commit:      commit,
		Now:         formatLogTime(time.Now()),
		StartedAt:   formatLogTime(a.metrics.StartedAt()),
		UptimeSecs:  a.metrics.UptimeSeconds(),
		ConfigPath:  a.configDB,
		Ports:       a.listeners.Ports(),
		ReloadTotal: a.metrics.ReloadTotal(),
		Summary:     a.metrics.Global(),
		Series:      a.metrics.SeriesPoints(),
		Logs: logStats{
			Buffered:    a.logs.Len(),
			Capacity:    logRingSize,
			Subscribers: subs,
			Dropped:     dropped,
			LatestSeq:   a.logs.Seq(),
		},
	}

	// 配置的统计读不到就留空，不要因此让整个状态接口失败 ——
	// 恰恰是配置出问题的时候最需要看到运行状态。
	if raw, cfg, err := readConfigFile(a.configDB); err == nil {
		resp.ConfigRevision = revisionOf(raw)
		resp.RoutesConfigured = len(cfg.Routes)
	} else {
		slog.Warn("状态接口读取配置失败", "err", err)
	}

	// 熔断状态取自当前生效的路由表，而不是 statsLoop 每 5 秒同步一次的那份指标：
	// 跳闸了却要等 5 秒才在界面上看见，排查时会以为接口没生效。
	if tbl := a.table.Load(); tbl != nil {
		resp.RoutesActive = len(tbl.routes)
		for _, rt := range tbl.routes {
			if rt.cb == nil {
				continue
			}
			switch rt.cb.State() {
			case cbOpen:
				resp.Circuit.Open++
			case cbHalfOpen:
				resp.Circuit.HalfOpen++
			default:
				resp.Circuit.Closed++
			}
			resp.Circuit.Tripped += rt.cb.openedTotal.Load()
			resp.Circuit.Rejected += rt.cb.rejectedTotal.Load()
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleLogs 返回最近 N 条访问记录。
// 前端先调它拿历史，再连 SSE 接增量，两者按 seq 去重。
func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := logsDefaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeErr(w, badRequest("invalid_limit", "limit 必须是正整数，当前 %q", v))
			return
		}
		if n > logsMaxLimit {
			n = logsMaxLimit
		}
		limit = n
	}
	subs, dropped := a.logs.Stats()
	// 地域在**出站时**补：环形缓冲里那份不带地域（见 LogEntry.IPGeo 的说明）。
	// Recent 返回的是副本，直接改不会影响缓冲。
	entries := a.logs.Recent(limit)
	a.enrichGeo(entries)
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":     entries,
		"buffered":    a.logs.Len(),
		"capacity":    logRingSize,
		"latest_seq":  a.logs.Seq(),
		"subscribers": subs,
		"dropped":     dropped,
		// 地域库的自述：来源、版本时间、命中统计。界面据此在日志页上说明
		// 「地域是哪来的、什么时候更新的」—— 这类信息不摆出来，
		// 用户只能猜数据新不新。
		"geo": a.geoMeta(),
	})
}

// handleEvents 用 SSE 推送实时访问日志。
//
// 选 SSE 而不是 WebSocket：日志是纯单向广播，SSE 是普通 HTTP，
// 能穿过所有代理、自动重连也由浏览器负责，没必要上一个双向协议。
func (a *App) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, &apiError{http.StatusInternalServerError, "stream_unsupported",
			"当前 ResponseWriter 不支持流式输出"})
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache, no-transform")
	h.Set("Connection", "keep-alive")
	// nginx 默认会缓冲上游响应，不显式关掉的话事件要攒满一整个缓冲才吐出来，
	// 表现是「日志延迟几十秒甚至完全不动」。这个头是 SSE 走 nginx 的必备项。
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch, cancel := a.logs.Subscribe()
	defer cancel()

	// 先握手。带上当前最新序号，前端拿去和 /_goproxy/logs 的历史做去重；
	// 前端也能靠它区分「连上了但没流量」和「根本没连上」。
	fmt.Fprintf(w, "event: hello\ndata: {\"latest_seq\":%d,\"buffered\":%d}\n\n",
		a.logs.Seq(), a.logs.Len())
	flusher.Flush()

	hb := time.NewTicker(sseHeartbeat)
	defer hb.Stop()

	for {
		select {
		case <-r.Context().Done():
			// 客户端断开（关标签页 / 刷新）。订阅者由 defer cancel 回收，
			// 忘了这步会随刷新次数线性泄漏 goroutine 和通道。
			return
		case <-hb.C:
			// 注释行，SSE 规范里客户端会忽略；纯粹拿来保活连接
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case e, open := <-ch:
			if !open {
				return
			}
			// 与 /logs 一样在出站时补地域，让实时推送与首次加载的显示一致。
			// e 是从通道取出的副本，改它不影响环形缓冲。
			a.enrichGeoOne(&e)
			b, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "id: %d\nevent: access\ndata: %s\n\n", e.Seq, b)
			flusher.Flush()
		}
	}
}
