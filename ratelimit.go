package main

import (
	"sync"
	"time"
)

// IPLimiter 是按 key 分桶的令牌桶限流器。
// demo 阶段放进程内内存（多实例部署时计数不共享）；
// 正式版把 Allow 换成 Redis 实现即可，调用方无需改动。
type IPLimiter struct {
	rate   float64
	burst  float64
	global bool // true 时忽略 key，整条路由共用一个桶

	mu      sync.Mutex
	buckets map[string]*bucket

	stopOnce sync.Once
	stop     chan struct{}
}

type bucket struct {
	tokens     float64
	lastRefill time.Time
	lastSeen   time.Time
}

func NewIPLimiter(rate, burst float64, global bool) *IPLimiter {
	if burst < 1 {
		burst = 1
	}
	l := &IPLimiter{
		rate:    rate,
		burst:   burst,
		global:  global,
		buckets: make(map[string]*bucket),
		stop:    make(chan struct{}),
	}
	go l.cleanupLoop()
	return l
}

func (l *IPLimiter) Allow(key string) bool {
	if l.global {
		key = ""
	}
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, lastRefill: now}
		l.buckets[key] = b
	}
	b.lastSeen = now

	// 按时间匀速补充令牌，但不超过桶容量
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastRefill = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// cleanupLoop 防止长期运行的进程因 IP 基数增长而内存泄漏。
// 每 5 分钟清一次 10 分钟没出现过的桶。
func (l *IPLimiter) cleanupLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.sweep(10 * time.Minute)
		}
	}
}

func (l *IPLimiter) sweep(maxIdle time.Duration) {
	cutoff := time.Now().Add(-maxIdle)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

func (l *IPLimiter) Close() {
	l.stopOnce.Do(func() { close(l.stop) })
}
