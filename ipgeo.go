package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
)

/*
IP 地域查询（纯真 qqwry 库）

用途只有一个：在访问日志里把客户端 IP 补上「国家 / 省 / 市」，让人扫一眼就知道
这波流量从哪来。日志页是排查工具，看到一屏陌生 IP 却说不出地域，排查就只能靠外网查。

三个刻意的设计选择：

 1. **不 embed，运行时读文件**。qqwry.dat 有 26 MB，embed 进去会让每个二进制都胖
    26 MB，而且它是有更新周期的数据（纯真通常每几天一版），换库不该等于重新编译。
    所以它是个「可选的运行时数据文件」：找不到就明确显示「地域库未启用」，
    其余功能一个都不受影响。
 2. **不整份读进内存**。用 ReadAt 随机读：一次查询只读十几条索引 + 两三个字符串。
    26 MB 常驻内存对一台小 VPS 是真实成本，而内核页缓存已经足够快。
 3. **不在写日志的热路径上查**。环形缓冲里存的记录**永远不带地域**，
    地域是「出站时补上」的（见 App.enrichGeo）。理由：日志写入是每个请求都要走的
    路径且持着缓冲的锁，往里塞文件读取是把两件不相干的事绑在一起；
    而地域只有人打开日志页时才需要。

数据格式（这份库实测出来的，与一些老实现不同 —— 差异记在 resolve 的注释里）：
    header:  [0:4] 索引区起始偏移(LE)  [4:8] 最后一条索引的偏移(LE)
    索引项:  7 字节 —— 起始 IP(4, LE 读) + 记录偏移(3, LE)
    记录:    索引偏移指向的条目**以 4 字节起始 IP 开头**，记录体在其后；
             记录体首字节是模式：
               0x01  再跳一层：紧跟 3 字节是另一个记录的偏移
               0x02  紧跟 3 字节是「国家–省–市」串的偏移，之后是 ISP 串
               其它  本身就是一个「国家–省–市」串，ISP 串紧跟其后
    字符串都是 NUL 结尾的 GBK（不是长度前缀）。
*/

const (
	// GeoOK 等是查询结果的状态。分开这么多种，是因为它们对使用者是**不同的事**：
	// 「内网地址」是确定的结论，「库没启用」是部署问题，「未收录」是数据边界，
	// 「查询失败」是故障。全塞进一句「未知」会让人以为功能坏了。
	GeoOK          = "ok"
	GeoInternal    = "internal"
	GeoUnsupported = "unsupported"
	GeoUnknown     = "unknown"
	GeoBadIP       = "bad_ip"
	GeoUnavailable = "unavailable"
	GeoFailed      = "failed"
)

const (
	qqwryModeRedirect = 0x01
	qqwryModePointer  = 0x02
	qqwryHeaderSize   = 8
	qqwryIndexEntry   = 7

	// geoCacheMax 是查询缓存的条数上限。
	// 日志页上的来源 IP 基数很小（一屏几十个），4096 足够覆盖；
	// 满了之后按 map 的遍历顺序丢一半 —— Go 的 map 遍历本身就是随机的，
	// 不需要为「淘汰策略」引入额外数据结构。缓存只是省下重复的文件读，
	// 丢了也只是下次再读一遍，不影响正确性。
	geoCacheMax = 4096

	geoReadChunk   = 512
	geoMaxString   = 200
	geoMaxRedirect = 4
)

// GeoInfo 是一个 IP 的地域结论。
type GeoInfo struct {
	Status   string `json:"status"`
	Country  string `json:"country,omitempty"`
	Province string `json:"province,omitempty"`
	City     string `json:"city,omitempty"`
	District string `json:"district,omitempty"`
	// Detail 是库里的原始文本（地点串 + ISP），给界面做 tooltip。
	// 保留原文是因为省市切分是**启发式**的：切错了也要让人能看见原话。
	Detail string `json:"detail,omitempty"`
}

type geoDB struct {
	f          *os.File
	path       string
	size       int64
	mtime      time.Time
	indexStart uint32
	indexEnd   uint32
	count      int

	mu    sync.Mutex
	cache map[string]GeoInfo

	queries atomic.Int64
	hits    atomic.Int64
	misses  atomic.Int64
	errs    atomic.Int64
}

// geoState 是地域查询的运行时状态快照（含「为什么不可用」）。
// 用原子指针整体替换，所以查询路径无锁：查不到库时也能说清原因。
type geoState struct {
	db     *geoDB
	path   string
	reason string
}

func openGeoDB(path string) (*geoDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	head := make([]byte, qqwryHeaderSize)
	if _, err := io.ReadFull(f, head); err != nil {
		f.Close()
		return nil, fmt.Errorf("读文件头失败（%d 字节都读不到，可能不是 qqwry 库）: %w", qqwryHeaderSize, err)
	}
	is := binary.LittleEndian.Uint32(head[0:4])
	ie := binary.LittleEndian.Uint32(head[4:8])

	// 头部校验。不做这一步的话，把随便一个 .dat 放过去会变成
	// 「每次查询都返回垃圾」，而不是一句明确的「这不是 qqwry 库」——
	// 垃圾地名比报错难查得多。
	if is < qqwryHeaderSize || ie < is || int64(ie)+qqwryIndexEntry > fi.Size() {
		f.Close()
		return nil, fmt.Errorf("文件头不像 qqwry 库：索引区 %d..%d 超出文件大小 %d", is, ie, fi.Size())
	}
	count := int((ie-is)/qqwryIndexEntry) + 1
	if count <= 0 || count > 40_000_000 {
		f.Close()
		return nil, fmt.Errorf("索引条数不合理（%d）", count)
	}
	return &geoDB{
		f: f, path: path, size: fi.Size(), mtime: fi.ModTime(),
		indexStart: is, indexEnd: ie, count: count,
		cache: make(map[string]GeoInfo, 256),
	}, nil
}

func (g *geoDB) Close() {
	if g == nil || g.f == nil {
		return
	}
	_ = g.f.Close()
}

// lookup 是唯一的对外查询入口。永不返回错误：所有异常都变成 GeoInfo.Status，
// 因为调用方（日志渲染）只需要「显示什么」，不需要处理错误。
func (g *geoDB) lookup(ipStr string) GeoInfo {
	if g == nil {
		return GeoInfo{Status: GeoUnavailable}
	}
	g.queries.Add(1)

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return GeoInfo{Status: GeoBadIP}
	}
	// 内网/回环/保留段：qqwry 里本来就没有它们，这是**确定的结论**，
	// 不是「查不到」。日志页上「局域网」比「未知地区」有用得多。
	if isLocalNet(ip) {
		return GeoInfo{Status: GeoInternal, Country: "局域网"}
	}
	v4 := ip.To4()
	if v4 == nil {
		return GeoInfo{Status: GeoUnsupported, Detail: "地域库只覆盖 IPv4"}
	}
	key := v4.String()

	if gi, ok := g.cacheGet(key); ok {
		g.hits.Add(1)
		return gi
	}
	g.misses.Add(1)

	loc, isp, err := g.rawLookup(binary.BigEndian.Uint32(v4))
	if err != nil {
		g.errs.Add(1)
		if errors.Is(err, errGeoOutOfRange) {
			// 指针越界属于库自身的数据缺口，不是我们的故障
			return GeoInfo{Status: GeoUnknown, Detail: "地域库记录指针越界"}
		}
		return GeoInfo{Status: GeoFailed, Detail: err.Error()}
	}
	if strings.TrimSpace(loc) == "" {
		// 库在、但这段没收录。缓存它 —— 换库时缓存会随库实例一起换掉，
		// 所以「未收录」不会陈旧。
		gi := GeoInfo{Status: GeoUnknown}
		g.cachePut(key, gi)
		return gi
	}
	gi := splitGeo(loc, isp)
	g.cachePut(key, gi)
	return gi
}

func (g *geoDB) cacheGet(key string) (GeoInfo, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	gi, ok := g.cache[key]
	return gi, ok
}

func (g *geoDB) cachePut(key string, gi GeoInfo) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.cache) >= geoCacheMax {
		// 丢一半：map 遍历顺序随机，等价于随机淘汰
		n := 0
		for k := range g.cache {
			delete(g.cache, k)
			n++
			if n >= geoCacheMax/2 {
				break
			}
		}
	}
	g.cache[key] = gi
}

var errGeoOutOfRange = errors.New("地域库偏移越界")

func (g *geoDB) check(off int, need int) error {
	if off < 0 || int64(off)+int64(need) > g.size {
		return fmt.Errorf("%w: %d", errGeoOutOfRange, off)
	}
	return nil
}

func (g *geoDB) byteAt(off int) (byte, error) {
	if err := g.check(off, 1); err != nil {
		return 0, err
	}
	var b [1]byte
	if _, err := g.f.ReadAt(b[:], int64(off)); err != nil {
		return 0, err
	}
	return b[0], nil
}

func (g *geoDB) uint24(off int) (int, error) {
	if err := g.check(off, 3); err != nil {
		return 0, err
	}
	var b [3]byte
	if _, err := g.f.ReadAt(b[:], int64(off)); err != nil {
		return 0, err
	}
	return int(b[0]) | int(b[1])<<8 | int(b[2])<<16, nil
}

func (g *geoDB) uint32At(off int) (uint32, error) {
	if err := g.check(off, 4); err != nil {
		return 0, err
	}
	var b [4]byte
	if _, err := g.f.ReadAt(b[:], int64(off)); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

// nulString 读一个 NUL 结尾的 GBK 串，返回 (文本, NUL 之后的位置)。
func (g *geoDB) nulString(off int) (string, int, error) {
	if err := g.check(off, 1); err != nil {
		return "", off, err
	}
	var acc []byte
	pos := off
	buf := make([]byte, geoReadChunk)
	for len(acc) <= geoMaxString {
		n, err := g.f.ReadAt(buf, int64(pos))
		if n > 0 {
			chunk := buf[:n]
			if i := bytes.IndexByte(chunk, 0); i >= 0 {
				acc = append(acc, chunk[:i]...)
				return decodeGBK(acc), pos + i + 1, nil
			}
			acc = append(acc, chunk...)
			pos += n
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(acc) > 0 {
					return decodeGBK(acc), pos, nil
				}
				return "", pos, nil
			}
			return "", pos, err
		}
	}
	// 超长：库坏了。截断返回，并把「已经读到哪」告诉调用方，
	// 免得 ISP 串被当成地点串的一部分。
	return decodeGBK(acc[:geoMaxString]), pos, nil
}

func decodeGBK(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	s, err := simplifiedchinese.GBK.NewDecoder().Bytes(b)
	if err != nil {
		// 库里有少量坏字节是正常的（这份库实测约 0.3%）。宁可留几个替换字符，
		// 也不要因为一个字节毁掉整条记录 —— 地名后面还有 ISP 有用。
		return strings.ToValidUTF8(string(b), "?")
	}
	return string(s)
}

// rawLookup 返回 (地点串, ISP 串)。
func (g *geoDB) rawLookup(ip uint32) (string, string, error) {
	idx := g.searchIndex(ip)
	if idx < 0 {
		return "", "", nil // 没收录，不是错误
	}
	off, err := g.recordOffset(idx)
	if err != nil {
		return "", "", err
	}
	// 索引偏移指向的条目以 4 字节起始 IP 开头，记录体在其后。
	// （实测：把偏移处的 4 字节当成记录体首字节，会读出 0x05 / 0x72 这类
	//  非法模式字节 —— 那是 IP 的一部分。）
	return g.resolve(off+4, 0)
}

// searchIndex 二分找「起始 IP 不大于目标的最后一条」。
func (g *geoDB) searchIndex(ip uint32) int {
	lo, hi, found := 0, g.count-1, -1
	for lo <= hi {
		mid := (lo + hi) / 2
		v, err := g.uint32At(int(g.indexStart) + mid*qqwryIndexEntry)
		if err != nil {
			return -1
		}
		if v <= ip {
			found, lo = mid, mid+1
		} else {
			hi = mid - 1
		}
	}
	return found
}

func (g *geoDB) recordOffset(idx int) (int, error) {
	return g.uint24(int(g.indexStart) + idx*qqwryIndexEntry + 4)
}

// resolve 解析一条记录，返回 (地点串, ISP 串)。
//
// 与常见的老实现有一处**关键差异**：模式 0x02 后面那 3 字节，老实现当成
// 「忽略」，把紧跟其后的字符串当国家 —— 在这份库里那样读出来的是 ISP，
// 于是「国家」字段变成了「腾讯云」「Charter_Communications」这种东西，
// 地点整体错位（实测约一半记录会错）。这里按实测语义读：
// 那 3 字节是**地点串的偏移**，紧跟其后的才是 ISP。
func (g *geoDB) resolve(rec int, depth int) (string, string, error) {
	if depth > geoMaxRedirect {
		return "", "", errors.New("地域库重定向层数过深")
	}
	mode, err := g.byteAt(rec)
	if err != nil {
		return "", "", err
	}
	switch mode {
	case qqwryModeRedirect:
		target, err := g.uint24(rec + 1)
		if err != nil {
			return "", "", err
		}
		return g.resolve(target, depth+1)

	case qqwryModePointer:
		locOff, err := g.uint24(rec + 1)
		if err != nil {
			return "", "", err
		}
		loc, err := g.locationAt(locOff, depth+1)
		if err != nil {
			return "", "", err
		}
		isp, _, err := g.nulString(rec + 4)
		if err != nil {
			return "", "", err
		}
		return loc, isp, nil

	default:
		loc, end, err := g.nulString(rec)
		if err != nil {
			return "", "", err
		}
		isp, _, err := g.nulString(end)
		if err != nil {
			return "", "", err
		}
		return loc, isp, nil
	}
}

// locationAt 读地点串。这个位置偶尔还套一层重定向，所以先看首字节：
// 0x01/0x02 都不是合法的 GBK 首字节（GBK 首字节 ≥ 0x81），不会误判。
func (g *geoDB) locationAt(off int, depth int) (string, error) {
	if depth > geoMaxRedirect {
		return "", errors.New("地域库地点指针层数过深")
	}
	b, err := g.byteAt(off)
	if err != nil {
		return "", err
	}
	if b == qqwryModeRedirect || b == qqwryModePointer {
		target, err := g.uint24(off + 1)
		if err != nil {
			return "", err
		}
		return g.locationAt(target, depth+1)
	}
	s, _, err := g.nulString(off)
	return s, err
}

// ---------- 字段切分 ----------

// splitGeo 把「地点串 + ISP 串」切成国家 / 省 / 市。
//
// 粒度受库本身限制：库里给的是一个用「–」连起来的层级串，层级数不固定
// （实测这份库 2~5 段都有）。切分规则刻意简单，切不出来的部分一律留在
// Detail 里 —— 启发式切错时，原始串是唯一的还原依据。
func splitGeo(loc, isp string) GeoInfo {
	gi := GeoInfo{Status: GeoOK}
	loc = strings.TrimSpace(loc)
	isp = strings.TrimSpace(isp)
	// CZ88.NET 是这份库「没有 ISP 信息」的占位串，不是地名。
	if strings.EqualFold(isp, "CZ88.NET") {
		isp = ""
	}
	parts := splitGeoParts(loc)
	switch len(parts) {
	case 0:
		// 调用方已按空处理
	case 1:
		if prov, city := splitOldStyle(parts[0]); prov != "" {
			// 老式写法：「广东省深圳市」这种省市连写
			gi.Province, gi.City = prov, city
		} else {
			gi.Country = parts[0]
		}
	default:
		gi.Country = parts[0]
		gi.Province = parts[1]
		if len(parts) >= 3 {
			gi.City = parts[2]
		}
		if len(parts) > 3 {
			gi.District = strings.Join(parts[3:], "–")
		}
	}
	gi.Detail = loc
	if isp != "" {
		gi.Detail += " · " + isp
	}
	return gi
}

// splitGeoParts 按分隔符切分。库里的分隔符是 EN DASH（–），
// 也兼容普通连字符和长破折号。
func splitGeoParts(s string) []string {
	raw := strings.FieldsFunc(s, func(r rune) bool {
		return r == '\u2013' || r == '-' || r == '\u2014'
	})
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// provincePrefixes 是省级行政区的简称，用于老式写法（省市连写）的前缀匹配。
var provincePrefixes = []string{
	"北京", "天津", "上海", "重庆",
	"河北", "山西", "辽宁", "吉林", "黑龙江", "江苏", "浙江", "安徽",
	"福建", "江西", "山东", "河南", "湖北", "湖南", "广东", "海南",
	"四川", "贵州", "云南", "陕西", "甘肃", "青海", "台湾",
	"内蒙古", "广西", "西藏", "宁夏", "新疆", "香港", "澳门",
}

// splitOldStyle 处理「省市连写」的老式串，比如「广东省深圳市电信」。
// 匹配不上就返回空 —— 猜不出省市时，整串当国家展示比编一个省市更诚实。
func splitOldStyle(s string) (province, city string) {
	var hit string
	for _, p := range provincePrefixes {
		if strings.HasPrefix(s, p) && len(p) > len(hit) {
			hit = p
		}
	}
	if hit == "" {
		return "", ""
	}
	province = hit

	// 简称后面通常还跟着行政区划后缀（省 / 市 / 自治区 / 特别行政区），
	// 先摘掉再找城市 —— 不摘的话「广东省深圳市」会切出「省深圳市」这种城市名。
	// 长后缀排在前面，否则「壮族自治区」会被短后缀截错。
	rest := strings.TrimPrefix(s, hit)
	for _, suffix := range []string{
		"特别行政区", "壮族自治区", "维吾尔自治区", "回族自治区", "自治区", "省", "市",
	} {
		if strings.HasPrefix(rest, suffix) {
			rest = strings.TrimPrefix(rest, suffix)
			break
		}
	}
	if rest == "" {
		return province, ""
	}
	// 市/州/盟/地区之前的部分算城市
	for _, sep := range []string{"市", "州", "盟", "地区"} {
		if i := strings.Index(rest, sep); i >= 0 {
			city = rest[:i+len(sep)]
			break
		}
	}
	return province, city
}

// ---------- 文件位置与热更新 ----------

// geoPathCandidates 按优先级列出会去找 qqwry.dat 的位置。
//
// 顺序是「越明确越靠前」：
//  1. 显式指定（-qqwry / GOPROXY_QQWRY）—— 唯一能覆盖其余位置的方式
//  2. 配置库所在目录 —— install.sh 装出来的实例就是 /etc/goproxy/qqwry.dat
//  3. 可执行文件所在目录 —— 手动解开发布包直接跑的场景
//  4. 进程工作目录 —— 本地开发（go run . 时就是仓库目录）
func geoPathCandidates(explicit, configDB, exe string) []string {
	var out []string
	add := func(p string) {
		if p == "" {
			return
		}
		for _, e := range out {
			if e == p {
				return
			}
		}
		out = append(out, p)
	}
	if explicit != "" {
		add(explicit)
		return out
	}
	if configDB != "" {
		add(filepath.Join(filepath.Dir(configDB), "qqwry.dat"))
	}
	if exe != "" {
		add(filepath.Join(filepath.Dir(exe), "qqwry.dat"))
	}
	if wd, err := os.Getwd(); err == nil {
		add(filepath.Join(wd, "qqwry.dat"))
	}
	return out
}

func findGeoDB(explicit, configDB, exe string) (string, []string) {
	cands := geoPathCandidates(explicit, configDB, exe)
	for _, p := range cands {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, cands
		}
	}
	return "", cands
}

// SetGeoPath 显式指定地域库路径（-qqwry / GOPROXY_QQWRY）。
//
// 只在启动时、第一次 reload 之前调用，所以不加锁 —— 之后 geoHint 只读。
// 非空时不再去猜其它位置：显式配置不该被兜底逻辑悄悄盖过。
func (a *App) SetGeoPath(p string) {
	a.geoHint = strings.TrimSpace(p)
}

// refreshGeo 载入或重新载入地域库。
//
// 「更新时机」就是这里：启动时一次，之后每次配置重载再检查一次
// （文件 mtime 或大小变了才真正重开）。所以换库的动作是
// 「覆盖 qqwry.dat + POST /_goproxy/reload」，不必重启进程；
// 缓存随库实例一起换掉，不会出现新旧库混用。
func (a *App) refreshGeo(explicit string) {
	prev := a.geo.Load()

	path, cands := findGeoDB(explicit, a.configDB, executablePath())
	if path == "" {
		if prev == nil || prev.db != nil {
			slog.Warn("未找到 IP 地域库，日志里的地域信息将显示为「未启用」",
				"looking_for", "qqwry.dat", "tried", cands,
				"hint", "把 qqwry.dat 放到配置库同目录，或用 -qqwry 指定路径")
		}
		a.geo.Store(&geoState{reason: "未找到 qqwry.dat（找过：" + strings.Join(cands, "、") + "）"})
		return
	}

	// 同一个文件、且没变过 → 保持现状（缓存和统计都留着）
	if prev != nil && prev.db != nil && prev.db.path == path {
		if fi, err := os.Stat(path); err == nil &&
			fi.ModTime().Equal(prev.db.mtime) && fi.Size() == prev.db.size {
			return
		}
	}

	db, err := openGeoDB(path)
	if err != nil {
		slog.Warn("IP 地域库载入失败，地域信息将显示为「查询失败」", "path", path, "err", err)
		a.geo.Store(&geoState{path: path, reason: err.Error()})
		return
	}
	if prev != nil && prev.db != nil {
		prev.db.Close()
	}
	a.geo.Store(&geoState{db: db})
	slog.Info("IP 地域库已载入",
		"path", path, "entries", db.count,
		"file_time", db.mtime.Format("2006-01-02 15:04:05"),
		"size_mb", fmt.Sprintf("%.1f", float64(db.size)/1048576))
}

func (a *App) geoLookup(ipStr string) GeoInfo {
	if ipStr == "" {
		return GeoInfo{}
	}
	st := a.geo.Load()
	if st == nil {
		return GeoInfo{Status: GeoUnavailable}
	}
	if st.db == nil {
		return GeoInfo{Status: GeoUnavailable, Detail: st.reason}
	}
	return st.db.lookup(ipStr)
}

// enrichGeo 给一批日志补地域。只作用于**出站的副本**：
// 环形缓冲里那份始终不带地域（理由见本文件开头）。
func (a *App) enrichGeo(entries []LogEntry) {
	if a == nil {
		return
	}
	for i := range entries {
		a.enrichGeoOne(&entries[i])
	}
}

// enrichGeoOne 给单条日志补地域。SSE 推送走它。
func (a *App) enrichGeoOne(e *LogEntry) {
	if a == nil || e == nil || e.ClientIP == "" {
		return
	}
	gi := a.geoLookup(e.ClientIP)
	if gi.Status == "" {
		return
	}
	e.IPGeo = &gi
}

// geoMeta 是给界面的地域库自述：来源、版本时间、统计。
type geoMeta struct {
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Entries   int    `json:"entries,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Queries   int64  `json:"queries"`
	Hits      int64  `json:"hits"`
	Misses    int64  `json:"misses"`
	Errors    int64  `json:"errors"`
}

func (a *App) geoMeta() geoMeta {
	st := a.geo.Load()
	if st == nil || st.db == nil {
		m := geoMeta{Reason: "未启用"}
		if st != nil {
			m.Path = st.path
			m.Reason = st.reason
			if m.Reason == "" {
				m.Reason = "未启用"
			}
		}
		return m
	}
	db := st.db
	return geoMeta{
		Available: true,
		Path:      db.path,
		Entries:   db.count,
		UpdatedAt: db.mtime.Format(time.RFC3339),
		Queries:   db.queries.Load(),
		Hits:      db.hits.Load(),
		Misses:    db.misses.Load(),
		Errors:    db.errs.Load(),
	}
}
