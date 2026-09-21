package main

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

/*
自动封禁（运行态）

与「人工黑名单」（配置里的 global_ip_deny / ip_lists）的关系：
两者都会拒绝请求，但性质相反。

	人工黑名单是**声明式配置**：我确定这个网段不该来。写进配置，进 revision，
	  进 config_history，进 -config-export，永久生效。
	自动封禁是**运行态**：某个行为触发了它，默认一小时后自己消失。

所以这一层的数据**刻意不放进 Config**，理由很具体：revision 是整份配置的哈希
（configstore.go 的 revisionOf），每封一个 IP 都会 bump 一次 ——
正在控制台上编辑的人下一次保存必然撞 409 revision_mismatch，
config_history 只有 20 版的窗口会被自动事件挤满，
-config-export 导出的备份里会混进一堆时间性极强的脏数据。

于是它有自己的表（ban_entries），而且**只有这一张**：
行 = 历史与状态（含阶梯层级），生效快照 = 其中还没过期的那部分。
过期行不立刻删，是为了记住「这个 IP 最近被封过几次」，下次时长跳一级；
过了 banRowKeep 还回来的，按第一次处理。

热路径怎么读：不可变快照 + atomic.Pointer，与 router.go 的 RouteTable 同一个
模式。请求路径只做一次 map 查，没有锁 —— 不给 Metrics.mu 那类争用点再加一个。
*/

const (
	banSourceHoneypot = "honeypot"
	banSourceManual   = "manual"

	// banSweepInterval 清扫频率：过期条目从快照里摘掉、陈旧行从表里删掉。
	banSweepInterval = time.Minute

	// banResyncInterval 从库里重读的频率。
	// 它换来两个能力：命令行解封立刻算数（最多等一轮），
	// 以及「另一个进程封了人」也能被这个进程看见。
	banResyncInterval = time.Minute

	// banRowKeep 过期条目在内存与表里再留这么久，只为了记住阶梯层级。
	banRowKeep = 7 * 24 * time.Hour

	// banSampleKeep 每条封禁最多留几条命中样本 —— 控制台的「为什么封它」靠它，
	// 但它同时也是攻击者可影响的内容（源 IP 我们改不了，路径是它给的），
	// 所以有上限、且展示时要按文本处理。
	banSampleKeep = 5

	// banMaxRows 表与内存里最多保留多少条。超出时淘汰最久没活动的，
	// 免得一次全网扫描把库撑大（封禁表本身不该成为被攻击面）。
	banMaxRows = 20000

	// 突发熔断：自动封禁在 banBurstWindow 内新增超过 banBurstLimit 个**不同 IP**
	// 就暂停自动写入 banBurstPause，并告警。
	//
	// 为什么需要它：真正被扫的时候，来的是一整片「连一次就走」的地址。
	// 把它们全写进表里，收益接近零（它们不会回来），代价是把库和日志撑爆，
	// 还会让快照重建的 O(n) 成本变成瓶颈。人工封禁不受这个限制。
	banBurstWindow = time.Minute
	banBurstLimit  = 200
	banBurstPause  = 5 * time.Minute
)

// banLadderRatios 是阶梯倍数：第 1 级用配置里的基准时长，之后逐级放大。
// 基准 1 小时时对应 1 小时 / 6 小时 / 24 小时 / 7 天（封顶）。
//
// 为什么有上限、且不做永久自动封禁：自动判据是会过期的。一个地址今天是
// 扫描器，几个月后可能已经重新分配给了正常用户。永久封禁必须由人来做
// （写进配置的名单），自动这一层只做临时处置。
var banLadderRatios = []float64{1, 6, 24, 168}

func banDuration(base time.Duration, level int) time.Duration {
	if base <= 0 {
		base = time.Hour
	}
	if level < 1 {
		level = 1
	}
	if level > len(banLadderRatios) {
		level = len(banLadderRatios)
	}
	return time.Duration(float64(base) * banLadderRatios[level-1])
}

// banEntry 是一条封禁记录。它同时是内存里的值和表里的一行。
type banEntry struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
	// Source 是 honeypot | manual。人工封禁不参与突发熔断，也不看豁免 ——
	// 那是人明确做出的决定（同 guardSelfLockout 的取舍：护栏挡的是无心之失，
	// 不是禁止这么配）。
	Source    string    `json:"source"`
	Level     int       `json:"level"`
	Hits      int       `json:"hits"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	LastAt    time.Time `json:"last_at"`
	Samples   []string  `json:"samples"`

	// persisted 表示这一版内容已经成功写进库了。
	//
	// 它只为一件事存在：让「库里没了」能区分两种截然不同的原因 ——
	//   已落盘 + 库里没有  = 有人从外面删了它（命令行 -unban / 直接改库）→ 该摘掉
	//   没落盘 + 库里没有  = 自己刚封的还没写下去 → 必须留着
	// 少了这个标记，周期性重读就只能二选一：要么丢掉刚封的，要么永远不认外部解封。
	persisted bool
}

func (e banEntry) active(now time.Time) bool { return now.Before(e.ExpiresAt) }

func (e banEntry) clone() banEntry {
	c := e
	if len(e.Samples) > 0 {
		c.Samples = append([]string(nil), e.Samples...)
	}
	return c
}

func appendSample(samples []string, s string) []string {
	s = normalizeSample(s)
	if s == "" {
		return samples
	}
	for _, old := range samples {
		if old == s {
			return samples
		}
	}
	samples = append(samples, s)
	if len(samples) > banSampleKeep {
		samples = samples[len(samples)-banSampleKeep:]
	}
	return samples
}

// normalizeSample 把一条样本压成单行短文本。
//
// 它来自网络（蜜罐端口收到的字节），要进内存、进库、最后进浏览器，
// 所以在这里就把控制字符、超长、换行一次性掐掉 —— 后面几处就不用各自提防了。
func normalizeSample(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	const max = 120
	if len(s) > max {
		s = s[:max]
	}
	return strings.TrimSpace(s)
}

// banSet 是生效集合的不可变快照。热路径只读它，所以它没有锁。
type banSet struct{ m map[string]banEntry }

func (s *banSet) lookup(ip string) (banEntry, bool) {
	if s == nil {
		return banEntry{}, false
	}
	e, ok := s.m[ip]
	return e, ok
}

var emptyBanSet = &banSet{m: map[string]banEntry{}}

type banOp struct {
	del bool
	ent banEntry
}

type banList struct {
	cur atomic.Pointer[banSet]

	// now 可注入，测试里把时间往前拨（同 sessionStore 的做法）。
	now func() time.Time

	mu sync.Mutex
	// all 是权威状态：包含**已过期但还在记忆窗口内**的行，快照只装其中生效的。
	all     map[string]banEntry
	pending []banOp
	rewrite bool

	store *configStore

	// base 是第 1 级封禁时长，来自配置。
	base time.Duration

	// exempt 是封禁前的豁免判定。做成注入而不是内联，是因为「谁不该被封」
	// 的知识属于 App（私网、可信代理、白名单、控制台来源），不属于这里。
	exempt func(ip net.IP) (bool, string)

	wake     chan struct{}
	stop     chan struct{}
	stopOnce sync.Once

	// burst 是最近一批自动封禁的时刻，用来做突发熔断。
	burst      []time.Time
	pausedTill time.Time

	blocked  atomic.Int64 // 被这一层拒掉的请求数
	exempted atomic.Int64 // 因为命中豁免而没封的次数
}

func newBanList(store *configStore, now func() time.Time) *banList {
	if now == nil {
		now = time.Now
	}
	b := &banList{
		now:   now,
		all:   map[string]banEntry{},
		store: store,
		base:  time.Hour,
		wake:  make(chan struct{}, 1),
		stop:  make(chan struct{}),
	}
	b.cur.Store(emptyBanSet)
	return b
}

// SetBase 更新第 1 级封禁时长（配置热重载时调用）。已存在的条目不追改。
func (b *banList) SetBase(d time.Duration) {
	if b == nil {
		return
	}
	if d <= 0 {
		d = time.Hour
	}
	b.mu.Lock()
	b.base = d
	b.mu.Unlock()
}

func (b *banList) SetExempt(fn func(ip net.IP) (bool, string)) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.exempt = fn
	b.mu.Unlock()
}

// lookup 是热路径：无锁，一次 map 查。
//
// 空接收者直接放行。这不是多余的防御：请求管线上有它，而 nil 接在这里
// 就是整个反代 panic（测试里用裸 &App{} 构造的实例正是这种情况）。
// 一个指针判空的代价换「热路径永不 panic」，很划算。
func (b *banList) lookup(ip string) (banEntry, bool) {
	if b == nil {
		return banEntry{}, false
	}
	e, ok := b.cur.Load().lookup(ip)
	if !ok {
		return banEntry{}, false
	}
	// 有效期必须在这里再判一次。
	//
	// 快照是「写的时候重建」的，而到期不是一次写 —— 没有这一句，
	// 一条已到期的封禁会一直生效到下一次重建（后台清扫，最多一分钟）。
	// 「封一小时」变成「封一小时零几十秒」不是灾难，但一次时间比较就
	// 能换来精确的到期语义，没有理由不做。
	if !e.active(b.now()) {
		return banEntry{}, false
	}
	b.blocked.Add(1)
	return e, true
}

// add 写入一条封禁。返回实际生效的条目与「是否真的封了」。
//
// 豁免在这里**再判一次**：调用方（蜜罐）已经判过一次，但这里是唯一的写入口，
// 防线放在最后一道才不会漏。
func (b *banList) add(ipStr, reason, source, sample string) (banEntry, bool) {
	if b == nil {
		return banEntry{}, false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return banEntry{}, false
	}

	manual := source == banSourceManual
	if !manual {
		b.mu.Lock()
		fn := b.exempt
		b.mu.Unlock()
		if fn != nil {
			if yes, why := fn(ip); yes {
				b.exempted.Add(1)
				slog.Info("自动封禁：命中豁免，不封禁",
					"ip", ipStr, "reason", reason, "exempt", why)
				return banEntry{}, false
			}
		}
	}

	now := b.now()

	b.mu.Lock()
	defer b.mu.Unlock()

	if !manual && now.Before(b.pausedTill) {
		return banEntry{}, false
	}

	// 已经在生效期内 → 只累计，不升级、不续期。
	//
	// 不续期是有意的：否则一个持续扫描的地址会让自己的封禁无限延长，
	// 等于变成永久封禁 —— 而永久封禁是人工的事（见 banLadderRatios 的说明）。
	// 升级走「这一轮封完、到期后又来」这条路。
	if prev, ok := b.all[ipStr]; ok && prev.active(now) {
		prev.Hits++
		prev.LastAt = now
		prev.Samples = appendSample(prev.Samples, sample)
		return b.putLocked(prev), true
	}

	// 记忆窗口内来过 → 升一级。过了窗口就当第一次。
	level := 1
	if prev, ok := b.all[ipStr]; ok && prev.Level > 0 && now.Sub(prev.LastAt) <= banRowKeep {
		level = prev.Level + 1
	}

	if !manual {
		if !b.burstAllowLocked(now) {
			return banEntry{}, false
		}
	}

	entry := banEntry{
		IP:        ipStr,
		Reason:    reason,
		Source:    source,
		Level:     level,
		Hits:      1,
		CreatedAt: now,
		ExpiresAt: now.Add(banDuration(b.base, level)),
		LastAt:    now,
		Samples:   appendSample(nil, sample),
	}
	return b.putLocked(entry), true
}

// addManual 是人工封禁：不看豁免、不参与突发熔断、时长由调用方给定。
//
// 豁免对人工封禁**不生效**，这是刻意的，和 guardSelfLockout 的取舍一致：
// 那类护栏挡的是无心之失，不是禁止某人做他已经明确决定要做的事。
// 真要封自己的网段，走这里或者直接写配置文件都可以。
func (b *banList) addManual(ipStr, reason string, d time.Duration) (banEntry, bool) {
	if b == nil {
		return banEntry{}, false
	}
	if net.ParseIP(ipStr) == nil {
		return banEntry{}, false
	}
	if d <= 0 {
		d = 24 * time.Hour
	}
	now := b.now()

	level := 0
	b.mu.Lock()
	defer b.mu.Unlock()
	if prev, ok := b.all[ipStr]; ok && prev.Level > 0 && now.Sub(prev.LastAt) <= banRowKeep {
		level = prev.Level + 1
	}
	entry := banEntry{
		IP:        ipStr,
		Reason:    reason,
		Source:    banSourceManual,
		Level:     level,
		Hits:      1,
		CreatedAt: now,
		ExpiresAt: now.Add(d),
		LastAt:    now,
		Samples:   appendSample(nil, "manual"),
	}
	return b.putLocked(entry), true
}

// putLocked 写入一条条目：更新权威状态、重建快照、排上落盘。必须在持锁时调用。
func (b *banList) putLocked(e banEntry) banEntry {
	e.persisted = false
	b.all[e.IP] = e
	b.trimLocked()
	b.rebuildLocked(b.now())
	b.queueLocked(banOp{ent: e.clone()})
	return e
}

// burstAllowLocked 突发熔断：自动封禁的写入速率闸门。必须在持锁时调用。
func (b *banList) burstAllowLocked(now time.Time) bool {
	cut := now.Add(-banBurstWindow)
	keep := b.burst[:0]
	for _, t := range b.burst {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	b.burst = append(keep, now)

	if len(b.burst) <= banBurstLimit {
		return true
	}
	if now.After(b.pausedTill) {
		b.pausedTill = now.Add(banBurstPause)
		slog.Warn("自动封禁：短时间内来源 IP 过多，已暂停自动封禁（改为只记录）",
			"window", banBurstWindow.String(),
			"limit", banBurstLimit,
			"pause", banBurstPause.String(),
			"hint", "这更像一次全网扫描；这类地址连一次就走，封禁收益很低，不值得把库撑爆")
	}
	return false
}

// trimLocked 控制条目总数，淘汰最久没活动的。必须在持锁时调用。
func (b *banList) trimLocked() {
	if len(b.all) <= banMaxRows {
		return
	}
	type aged struct {
		ip string
		at time.Time
	}
	list := make([]aged, 0, len(b.all))
	for ip, e := range b.all {
		list = append(list, aged{ip, e.LastAt})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].at.Before(list[j].at) })
	drop := len(b.all) - banMaxRows
	for i := 0; i < drop; i++ {
		delete(b.all, list[i].ip)
		b.queueLocked(banOp{del: true, ent: banEntry{IP: list[i].ip}})
	}
}

// rebuildLocked 用当前生效条目造一份新快照并原子换掉。必须在持锁时调用。
//
// 每次写入都重建整份 map（O(n)）。这是刻意的取舍：写动作由突发熔断限速，
// 而读是每个请求都走的热路径 —— 把成本放在罕见的写侧，换读侧零锁。
func (b *banList) rebuildLocked(now time.Time) {
	next := make(map[string]banEntry, len(b.all))
	for ip, e := range b.all {
		if e.active(now) {
			next[ip] = e
		}
	}
	b.cur.Store(&banSet{m: next})
}

func (b *banList) queueLocked(op banOp) {
	if b.store == nil {
		return
	}
	if len(b.pending) >= 4096 {
		// 队列积压：改成整表重写，宁可多写一点也不能丢。
		b.rewrite = true
		b.pending = nil
	} else if !b.rewrite {
		b.pending = append(b.pending, op)
	}
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// remove 解封。返回是否真的有一条在生效。
func (b *banList) remove(ipStr string) bool {
	if b == nil {
		return false
	}
	now := b.now()
	b.mu.Lock()
	e, ok := b.all[ipStr]
	delete(b.all, ipStr)
	b.rebuildLocked(now)
	b.queueLocked(banOp{del: true, ent: banEntry{IP: ipStr}})
	b.mu.Unlock()
	return ok && e.active(now)
}

// clear 清空全部封禁（含阶梯记忆）。
func (b *banList) clear() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	n := len(b.all)
	b.all = map[string]banEntry{}
	b.rewrite = true
	b.pending = nil
	b.rebuildLocked(b.now())
	b.mu.Unlock()
	b.wakeOnce()
	return n
}

func (b *banList) wakeOnce() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// list 返回全部条目（含已过期但仍在记忆窗口内的），生效的排在前面。
func (b *banList) list() []banEntry {
	if b == nil {
		return nil
	}
	now := b.now()
	b.mu.Lock()
	out := make([]banEntry, 0, len(b.all))
	for _, e := range b.all {
		out = append(out, e.clone())
	}
	b.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		ai, aj := out[i].active(now), out[j].active(now)
		if ai != aj {
			return ai
		}
		return out[i].LastAt.After(out[j].LastAt)
	})
	return out
}

// sweep 摘掉过期的、删掉记忆窗口外的行。由后台循环周期调用。
func (b *banList) sweep() {
	now := b.now()
	b.mu.Lock()
	var gone []string
	for ip, e := range b.all {
		if now.Sub(e.LastAt) > banRowKeep {
			gone = append(gone, ip)
			delete(b.all, ip)
		}
	}
	b.trimLocked()
	b.rebuildLocked(now)
	for _, ip := range gone {
		b.queueLocked(banOp{del: true, ent: banEntry{IP: ip}})
	}
	b.mu.Unlock()
	for _, ip := range gone {
		slog.Debug("自动封禁：遗忘一条陈旧记录", "ip", ip)
	}
}

// activeCount 报告当前生效条数。
func (b *banList) activeCount() int {
	if b == nil {
		return 0
	}
	now := b.now()
	n := 0
	for _, e := range b.cur.Load().m {
		if e.active(now) {
			n++
		}
	}
	return n
}

type banStats struct {
	Active       int       `json:"active"`
	Known        int       `json:"known"`
	Blocked      int64     `json:"blocked"`
	Exempted     int64     `json:"exempted"`
	PausedTill   time.Time `json:"paused_till,omitempty"`
	BaseDuration string    `json:"base_duration"`
}

func (b *banList) stats() banStats {
	if b == nil {
		return banStats{}
	}
	b.mu.Lock()
	known := len(b.all)
	paused := b.pausedTill
	base := b.base
	b.mu.Unlock()
	st := banStats{
		Active:       b.activeCount(),
		Known:        known,
		Blocked:      b.blocked.Load(),
		Exempted:     b.exempted.Load(),
		BaseDuration: base.String(),
	}
	if b.now().Before(paused) {
		st.PausedTill = paused
	}
	return st
}

// ---------- 持久化 ----------

// load 从表里恢复封禁。进程重启后封禁仍然生效 —— 否则重启就是一次
// 「攻击者免费解封」，而那恰好是攻击者能触发的动作（打崩进程）。
func (b *banList) load() error {
	if b == nil || b.store == nil {
		return nil
	}
	rows, err := b.store.readBans()
	if err != nil {
		return err
	}
	now := b.now()

	b.mu.Lock()
	for _, e := range rows {
		// 时间戳坏掉的行按「说不清有效期」处理：过期时间读不出来就丢掉
		// （没法判断它还算不算生效），活动时间读不出来则退回过期时间。
		if e.ExpiresAt.IsZero() {
			slog.Warn("自动封禁：丢掉一条时间戳读不出来的记录", "ip", e.IP)
			continue
		}
		if e.LastAt.IsZero() {
			e.LastAt = e.ExpiresAt
		}
		// 记忆窗口外的行直接丢：留着只会让阶梯层级凭一个很久以前的事件升级。
		if now.Sub(e.LastAt) > banRowKeep {
			continue
		}
		// 从库里读出来的，本来就是已经落过盘的。
		// 这一条必须设对：resync 靠它区分「外部删掉了」和「自己还没写下去」。
		e.persisted = true
		b.all[e.IP] = e
	}
	b.trimLocked()
	b.rebuildLocked(now)
	b.mu.Unlock()

	if n := b.activeCount(); n > 0 {
		slog.Warn("自动封禁：从库里恢复了仍在生效的封禁", "count", n,
			"hint", "用 goproxy -bans 查看，用 goproxy -unban all 清空")
	}
	return nil
}

// Start 起后台落盘与清扫。落盘与请求路径解耦：封禁写内存即生效，
// 库只是重启恢复用的，所以写库可以慢、可以攒。
func (b *banList) Start() {
	if b == nil {
		return
	}
	go b.persistLoop()
	go b.sweepLoop()
}

func (b *banList) persistLoop() {
	const debounce = 1500 * time.Millisecond
	t := time.NewTicker(banResyncInterval)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			b.flush()
			return
		case <-t.C:
			// 顺序很重要：先把自己攒的写下去，再从库里重读。
			// 反过来的话，还没落盘的封禁会被「库里没有」判成已被删除。
			b.flush()
			if err := b.resync(); err != nil {
				slog.Debug("封禁表重读失败", "err", err)
			}
		case <-b.wake:
			select {
			case <-time.After(debounce):
			case <-b.stop:
				b.flush()
				return
			}
			b.flush()
		}
	}
}

func (b *banList) sweepLoop() {
	t := time.NewTicker(banSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-t.C:
			b.sweep()
		}
	}
}

func (b *banList) Close() {
	if b == nil {
		return
	}
	b.stopOnce.Do(func() { close(b.stop) })
}

func (b *banList) flush() {
	if b.store == nil {
		return
	}
	b.mu.Lock()
	ops := b.pending
	b.pending = nil
	rewrite := b.rewrite
	b.rewrite = false
	var all []banEntry
	if rewrite {
		all = make([]banEntry, 0, len(b.all))
		for _, e := range b.all {
			all = append(all, e.clone())
		}
	}
	b.mu.Unlock()

	if len(ops) == 0 && !rewrite {
		return
	}
	err := b.store.withTx(func(tx *sql.Tx) error {
		if rewrite {
			if _, err := tx.Exec(`DELETE FROM ban_entries`); err != nil {
				return err
			}
			for _, e := range all {
				if err := upsertBanTx(tx, e); err != nil {
					return err
				}
			}
			return nil
		}
		for _, op := range ops {
			if op.del {
				if _, err := tx.Exec(`DELETE FROM ban_entries WHERE ip = ?`, op.ent.IP); err != nil {
					return err
				}
				continue
			}
			if err := upsertBanTx(tx, op.ent); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// 内存里已经生效了，落盘失败只影响「重启后还在不在」，
		// 所以这里告警而不是回滚 —— 把已经生效的封禁撤掉才是更坏的结果。
		slog.Warn("封禁条目落盘失败（内存里仍然生效）", "err", err)
		return
	}

	written := make([]banEntry, 0, len(ops))
	for _, op := range ops {
		if !op.del {
			written = append(written, op.ent)
		}
	}
	b.markPersisted(written, rewrite)
}

// markPersisted 把「这一版已经写进库了」标回去。
//
// 只标内容还一致的那些：期间又变过的条目由下一次 flush 负责，
// 抢着标会让「库里没有 = 被外部删了」的判断出错。
func (b *banList) markPersisted(written []banEntry, all bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if all {
		for ip, e := range b.all {
			e.persisted = true
			b.all[ip] = e
		}
		return
	}
	for _, w := range written {
		cur, ok := b.all[w.IP]
		if !ok || !cur.LastAt.Equal(w.LastAt) {
			continue
		}
		cur.persisted = true
		b.all[w.IP] = cur
	}
}

// resync 从库里重读一遍，让「另一个进程改过库」这件事能收敛过来。
//
// 为什么需要它：命令行 -unban 改的是库，而封禁的判定依据是**进程内存里的快照**。
// 没有这一步，服务运行期间命令行解封就是无效的 —— 界面上「已解封」、
// 请求仍然 403，是最难解释的一种不一致。
//
// 双向：外部删的会被摘掉，外部加（命令行封禁）的会被载入。
func (b *banList) resync() error {
	if b == nil || b.store == nil {
		return nil
	}
	rows, err := b.store.readBans()
	if err != nil {
		return err
	}
	now := b.now()

	// 这里不用 defer unlock：下面要带着结果出去写日志，
	// 而「持锁写日志」是另一类问题（日志慢会拖住所有封禁写入）。
	b.mu.Lock()

	inDB := make(map[string]banEntry, len(rows))
	for _, e := range rows {
		if e.ExpiresAt.IsZero() || now.Sub(e.LastAt) > banRowKeep {
			continue
		}
		inDB[e.IP] = e
	}

	var dropped []string
	for ip, cur := range b.all {
		if _, ok := inDB[ip]; ok {
			continue
		}
		// 只有「确实写下去过」的条目才有资格因为库里没有而被摘掉。
		if cur.persisted {
			delete(b.all, ip)
			dropped = append(dropped, ip)
		}
	}

	var added []banEntry
	for ip, row := range inDB {
		cur, ok := b.all[ip]
		switch {
		case !ok:
			row.persisted = true
			b.all[ip] = row
			added = append(added, row)
		case row.LastAt.After(cur.LastAt):
			row.persisted = true
			b.all[ip] = row
		}
	}
	b.trimLocked()
	b.rebuildLocked(now)
	b.mu.Unlock()

	for _, ip := range dropped {
		slog.Info("自动封禁：检测到外部解封，已解除", "ip", ip)
	}
	for _, e := range added {
		slog.Info("自动封禁：载入了一条外部写入的封禁", "ip", e.IP, "reason", e.Reason)
	}
	return nil
}

func upsertBanTx(tx *sql.Tx, e banEntry) error {
	samples := "[]"
	if len(e.Samples) > 0 {
		raw, err := json.Marshal(e.Samples)
		if err != nil {
			raw = []byte("[]")
		}
		samples = string(raw)
	}
	_, err := tx.Exec(`
INSERT INTO ban_entries (ip, reason, source, level, hits, created_at, expires_at, last_at, samples)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET
  reason = excluded.reason, source = excluded.source, level = excluded.level,
  hits = excluded.hits, created_at = excluded.created_at,
  expires_at = excluded.expires_at, last_at = excluded.last_at, samples = excluded.samples`,
		e.IP, e.Reason, e.Source, e.Level, e.Hits,
		formatLogTime(e.CreatedAt), formatLogTime(e.ExpiresAt), formatLogTime(e.LastAt), samples)
	return err
}

// ---------- 谁不该被封 ----------

// localNets 是不做自动封禁的网段：回环、私网、链路本地、CGNAT、组播与保留段。
//
// 它们的共同点是「不是来自外部网络的攻击者」：内网地址被封只会误伤自己人，
// 而自动封禁的整个目标是外部扫描。真要封内网某段，走人工黑名单
// （那条路不设护栏，见 guardSelfLockout 的说明）。
var localNets = func() []*net.IPNet {
	raw := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
		"2001:db8::/32",
	}
	out := make([]*net.IPNet, 0, len(raw))
	for _, s := range raw {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

func isLocalNet(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, n := range localNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseLogTime 解析 formatLogTime 写出（以及库里存着）的时间戳。
//
// 用 RFC3339Nano 收：它能吃下任意位数的小数秒，所以 formatLogTime 的毫秒格式
// 和手写的秒级格式都能解。
//
// 解析失败返回零值而不是报错 —— 一条时间坏掉的行不该让整个加载失败。
// 调用方按「零值 = 说不清有效期」处理，见 load 里的取舍。
func parseLogTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ---------- 记住正在操作控制台的人 ----------

// recentIPs 记住最近活跃过的来源地址，用途只有一个：别把正在操作控制台的人
// 自动封在门外。
//
// 蜜罐路径上没有 HTTP 请求上下文，用不了 consoleClientIPs(r)，所以只能在
// 鉴权通过时顺手记一笔。（guardSelfLockout 挡的是「保存一份会把自己挡住的
// 配置」，这里挡的是「自动判据把你封了」，两条路都得有。）
type recentIPs struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]time.Time
	now  func() time.Time
}

func newRecentIPs(ttl time.Duration) *recentIPs {
	return &recentIPs{ttl: ttl, seen: map[string]time.Time{}, now: time.Now}
}

func (r *recentIPs) remember(ip string) {
	if r == nil || ip == "" {
		return
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) > 512 {
		cut := now.Add(-r.ttl)
		for k, v := range r.seen {
			if v.Before(cut) {
				delete(r.seen, k)
			}
		}
	}
	r.seen[ip] = now
}

func (r *recentIPs) has(ip string) bool {
	if r == nil || ip == "" {
		return false
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.seen[ip]
	return ok && now.Sub(t) <= r.ttl
}
