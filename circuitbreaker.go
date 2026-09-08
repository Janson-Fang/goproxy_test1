package main

import (
	"sync/atomic"
	"time"
)

type cbState int32

const (
	cbClosed cbState = iota
	cbOpen
	cbHalfOpen
)

func (s cbState) String() string {
	switch s {
	case cbClosed:
		return "closed"
	case cbOpen:
		return "open"
	case cbHalfOpen:
		return "half_open"
	}
	return "unknown"
}

// CBConfig 熔断配置。零值会在 normalize 里填默认值。
type CBConfig struct {
	// ErrorRate 窗口内错误率阈值，达到就跳闸
	ErrorRate float64 `json:"error_rate"`
	// MinCalls 窗口内最少调用数，避免刚启动就被两三个请求打跳闸
	MinCalls int64 `json:"min_calls"`
	// OpenSecs 跳闸后保持 open 的秒数，之后进入 half-open
	OpenSecs int `json:"open_secs"`
	// HalfOpenCalls half-open 阶段放行的探测请求数
	HalfOpenCalls int64 `json:"half_open_calls"`
	// WindowSecs 滑动窗口长度（秒）
	WindowSecs int `json:"window_secs"`
}

func (c CBConfig) normalize() CBConfig {
	if c.ErrorRate <= 0 || c.ErrorRate > 1 {
		c.ErrorRate = 0.5
	}
	if c.MinCalls <= 0 {
		c.MinCalls = 20
	}
	if c.OpenSecs <= 0 {
		c.OpenSecs = 30
	}
	if c.HalfOpenCalls <= 0 {
		c.HalfOpenCalls = 5
	}
	if c.WindowSecs < 2 {
		c.WindowSecs = 10
	}
	if c.WindowSecs > 300 {
		c.WindowSecs = 300
	}
	return c
}

type cbBucket struct {
	period atomic.Int64 // 该桶当前代表的时间（秒）
	calls  atomic.Int64
	fails  atomic.Int64
}

// CircuitBreaker 按路由的滑动窗口熔断器。
// 单后端场景下无法切流，所以熔断的价值是「快速失败」——
// 后端已经挂了的时候，与其让每个请求都等到超时，不如立刻返回 503。
type CircuitBreaker struct {
	cfg     CBConfig
	buckets []cbBucket

	state    atomic.Int32
	openedAt atomic.Int64 // unix nano
	halfUsed atomic.Int64
	halfOK   atomic.Int64

	openedTotal   atomic.Int64
	rejectedTotal atomic.Int64
}

func NewCircuitBreaker(cfg CBConfig) *CircuitBreaker {
	cfg = cfg.normalize()
	return &CircuitBreaker{
		cfg:     cfg,
		buckets: make([]cbBucket, cfg.WindowSecs),
	}
}

// Allow 判断当前请求是否应该放行。
func (cb *CircuitBreaker) Allow() bool {
	switch cbState(cb.state.Load()) {
	case cbClosed:
		return true

	case cbOpen:
		opened := time.Unix(0, cb.openedAt.Load())
		if time.Since(opened) < time.Duration(cb.cfg.OpenSecs)*time.Second {
			cb.rejectedTotal.Add(1)
			return false
		}
		// 冷却结束，转入 half-open 放行少量探测请求
		if cb.state.CompareAndSwap(int32(cbOpen), int32(cbHalfOpen)) {
			cb.halfUsed.Store(0)
			cb.halfOK.Store(0)
		}
		return true

	default: // half-open
		if cb.halfUsed.Add(1) <= cb.cfg.HalfOpenCalls {
			return true
		}
		cb.rejectedTotal.Add(1)
		return false
	}
}

// Record 记录一次调用结果。failed 为 true 表示后端错误（5xx 或连不上）。
func (cb *CircuitBreaker) Record(failed bool) {
	now := time.Now()
	nowSec := now.Unix()

	b := cb.bucket(nowSec)
	b.calls.Add(1)
	if failed {
		b.fails.Add(1)
	}

	switch cbState(cb.state.Load()) {
	case cbHalfOpen:
		if failed {
			cb.toOpen(now)
			return
		}
		if cb.halfOK.Add(1) >= cb.cfg.HalfOpenCalls {
			if cb.state.CompareAndSwap(int32(cbHalfOpen), int32(cbClosed)) {
				cb.resetWindow()
			}
		}
		return

	case cbClosed:
		calls, fails := cb.windowStats(nowSec)
		if calls >= cb.cfg.MinCalls && float64(fails)/float64(calls) >= cb.cfg.ErrorRate {
			cb.toOpen(now)
		}
	}
}

func (cb *CircuitBreaker) toOpen(now time.Time) {
	for {
		cur := cb.state.Load()
		if cur == int32(cbOpen) {
			return
		}
		if cb.state.CompareAndSwap(cur, int32(cbOpen)) {
			cb.openedAt.Store(now.UnixNano())
			cb.openedTotal.Add(1)
			return
		}
	}
}

// bucket 取当前秒对应的桶，跨秒时懒重置（无锁 CAS）。
func (cb *CircuitBreaker) bucket(nowSec int64) *cbBucket {
	idx := nowSec % int64(len(cb.buckets))
	b := &cb.buckets[idx]
	for {
		p := b.period.Load()
		if p == nowSec {
			return b
		}
		if b.period.CompareAndSwap(p, nowSec) {
			b.calls.Store(0)
			b.fails.Store(0)
			return b
		}
	}
}

func (cb *CircuitBreaker) windowStats(nowSec int64) (calls, fails int64) {
	n := int64(len(cb.buckets))
	for i := range cb.buckets {
		b := &cb.buckets[i]
		p := b.period.Load()
		if p <= 0 || p > nowSec || nowSec-p >= n {
			continue // 桶是空的或已滑出窗口
		}
		calls += b.calls.Load()
		fails += b.fails.Load()
	}
	return
}

func (cb *CircuitBreaker) resetWindow() {
	for i := range cb.buckets {
		cb.buckets[i].calls.Store(0)
		cb.buckets[i].fails.Store(0)
	}
}

func (cb *CircuitBreaker) State() cbState { return cbState(cb.state.Load()) }

// Snapshot 供管理接口和指标使用
type CBSnapshot struct {
	State       string  `json:"state"`
	Calls       int64   `json:"calls"`
	Fails       int64   `json:"fails"`
	ErrorRate   float64 `json:"error_rate"`
	OpenedTotal int64   `json:"opened_total"`
	Rejected    int64   `json:"rejected_total"`
}

func (cb *CircuitBreaker) Snapshot() CBSnapshot {
	calls, fails := cb.windowStats(time.Now().Unix())
	rate := 0.0
	if calls > 0 {
		rate = float64(fails) / float64(calls)
	}
	return CBSnapshot{
		State:       cb.State().String(),
		Calls:       calls,
		Fails:       fails,
		ErrorRate:   rate,
		OpenedTotal: cb.openedTotal.Load(),
		Rejected:    cb.rejectedTotal.Load(),
	}
}

// isBackendFailure 判定什么算「后端错误」。
// 5xx 和连接失败算；4xx 是客户端的问题，不该让后端背锅；
// 限流返回的 429 也不算，否则限流会误触发熔断。
func isBackendFailure(code int) bool {
	return code >= 500 || code == 0
}
