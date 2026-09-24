package main

import (
	"sync"
	"time"
)

// logRingSize 是内存里保留的访问记录条数。
//
// 刻意做成定长环而不是「写文件再读回来」：管理台的实时日志要的是
// 「刚才发生了什么」，不是完整历史。完整历史属于 access_log 输出的文件，
// 由外部工具（lumberjack / logrotate）去管。500 条记录不到 100KB，
// 换来的是打开页面立刻有内容，且不会因为日志量大而拖慢进程。
const logRingSize = 500

// logSubBuffer 是每个 SSE 订阅者的缓冲深度。
// 慢客户端（浏览器切到后台、网络卡住）不应该拖累别人，所以满了直接丢。
const logSubBuffer = 256

// LogEntry 是一条访问记录。
//
// 存结构化字段而不是格式化好的文本行：管理台直接渲染表格，
// 不必再解析字符串 —— 解析日志文本既慢又脆（路径里带空格就会错位）。
type LogEntry struct {
	Seq       uint64  `json:"seq"`
	Time      string  `json:"time"`
	Route     string  `json:"route,omitempty"`
	RouteName string  `json:"route_name,omitempty"`
	Port      int     `json:"port"`
	Host      string  `json:"host,omitempty"`
	Method    string  `json:"method"`
	Path      string  `json:"path"`
	Query     string  `json:"query,omitempty"`
	Status    int     `json:"status"`
	DurMs     float64 `json:"dur_ms"`
	ClientIP  string  `json:"client_ip,omitempty"`
	UA        string  `json:"ua,omitempty"`
	// Blocked 非空表示这条请求没被转发出去，值是拦截原因：
	// acl / rate_limited / circuit_open / auth_no_credentials 等。
	// 管理台用它把「被拦掉的请求」单独标色 —— 排查限流误伤时全靠它。
	Blocked string `json:"blocked,omitempty"`

	// IPGeo 是客户端 IP 的地域（国家/省/市）。
	//
	// 它**只在出站时补上**（见 App.enrichGeo），环形缓冲里那份始终是 nil：
	// 写日志是每个请求都要走、且持着缓冲锁的路径，不宜在里面读地域库；
	// 而地域只有人打开日志页时才需要。
	//
	// 放在 LogEntry 里而不是让前端另发一次查询，是为了「地域与它对应的 IP
	// 天然对齐」—— 两者在同一个对象里，不存在按行号配错的可能。
	IPGeo *GeoInfo `json:"ip_geo,omitempty"`
}

// logBuffer 是访问记录的定长环形缓冲，同时充当 SSE 的广播源。
type logBuffer struct {
	mu   sync.RWMutex
	buf  []LogEntry
	head int // 下一个写入位置
	size int // 已写入条数，最多 len(buf)
	seq  uint64

	subs    map[chan LogEntry]struct{}
	dropped uint64
}

func newLogBuffer(size int) *logBuffer {
	if size <= 0 {
		size = logRingSize
	}
	return &logBuffer{
		buf:  make([]LogEntry, size),
		subs: make(map[chan LogEntry]struct{}),
	}
}

// Add 写入一条记录并广播给所有订阅者。
//
// 广播用的是非阻塞发送：订阅者通道满就丢弃并计数。
// 改成阻塞发送的话，一个卡住的浏览器标签页就能把整个代理拖死 ——
// 这是访问日志这种「顺手做的事」绝对不能出现的失败模式。
func (b *logBuffer) Add(e LogEntry) LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.seq++
	e.Seq = b.seq
	b.buf[b.head] = e
	b.head = (b.head + 1) % len(b.buf)
	if b.size < len(b.buf) {
		b.size++
	}

	for ch := range b.subs {
		select {
		case ch <- e:
		default:
			b.dropped++
		}
	}
	return e
}

// Recent 返回最近 n 条，按时间从旧到新排列，方便前端直接 append 渲染。
func (b *logBuffer) Recent(n int) []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if n <= 0 || n > b.size {
		n = b.size
	}
	out := make([]LogEntry, 0, n)
	start := (b.head - n + len(b.buf)) % len(b.buf)
	for i := 0; i < n; i++ {
		out = append(out, b.buf[(start+i)%len(b.buf)])
	}
	return out
}

// Len 返回当前缓冲里的条数。
func (b *logBuffer) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.size
}

// Seq 返回最新一条记录的序号（没有任何记录时为 0）。
func (b *logBuffer) Seq() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.seq
}

// Stats 返回订阅者数量与累计丢弃条数。
func (b *logBuffer) Stats() (subs int, dropped uint64) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs), b.dropped
}

// Subscribe 返回一个只读通道与取消函数。
//
// 取消必须在同一把锁里删除并关闭通道：否则 Add 正在遍历订阅者时
// 通道被关掉，就会 panic（send on closed channel）。这是这类
// 「广播 + 动态订阅」结构的经典坑。
func (b *logBuffer) Subscribe() (<-chan LogEntry, func()) {
	ch := make(chan LogEntry, logSubBuffer)

	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, ch)
			close(ch)
			b.mu.Unlock()
		})
	}
	return ch, cancel
}

// formatLogTime 用毫秒精度的 RFC3339。
// 默认的 RFC3339 只到秒，同一秒内的多条记录在界面上会分不出先后。
func formatLogTime(t time.Time) string {
	return t.Format("2006-01-02T15:04:05.000Z07:00")
}
