package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func gbkBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(s))
	if err != nil {
		t.Fatalf("GBK 编码 %q 失败: %v", s, err)
	}
	return b
}

// synthEntry 是往合成库里放的一条记录。
type synthEntry struct {
	startIP string
	// mode:
	//   "ptr"     0x02：3 字节指向地点串，紧跟 ISP 串（这份库的常见形态）
	//   "redirect" 0x01：再跳一层到另一个记录
	//   "plain"    直接就是地点串 + ISP 串
	mode   string
	loc    string
	isp    string
	locRef int // redirect 指向的记录序号
}

// buildQQWry 造一份最小的 qqwry 库。
//
// 为什么要自己造：解析器的正确性不该依赖那份 26 MB 的真实文件存在。
// 这里把三种记录形态都放进去，字节布局按实测格式写（索引项以 4 字节起始 IP
// 开头、记录体在其后；字符串 NUL 结尾的 GBK）。
func buildQQWry(t *testing.T, entries []synthEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	buf.Write(make([]byte, qqwryHeaderSize)) // 头部占位，最后回填

	// 第一遍：把共享的地点串写进「串池」，记下偏移。
	//
	// 必须与记录分两遍写。写在一条语句里（writeUint24(&buf, writeLoc(...))）会踩
	// 一个很隐蔽的坑：Go 先求值参数，writeLoc 把串写进缓冲区、缓冲区长度前移，
	// 紧接着的 3 字节指针就被写到了串后面 —— 造出来的库带着错位的指针。
	// （这个 bug 造出来的正是「越界指针」，也正是解析器测试要抓的那类错位。）
	locOff := map[string]int{}
	for _, e := range entries {
		if e.mode != "ptr" {
			continue
		}
		if _, ok := locOff[e.loc]; ok {
			continue
		}
		off := buf.Len()
		buf.Write(gbkBytes(t, e.loc))
		buf.WriteByte(0)
		locOff[e.loc] = off
	}

	// 第二遍：先算好每条记录的偏移，再写。
	//
	// 必须先全部算完再写：0x01 记录里要填的是**目标记录的偏移**，而目标可能排在
	// 它后面（本例就是）。边算边写会填进去一个 0，读出来是文件头的字节 ——
	// 这正是「重定向必须两遍」的原因。
	recOff := make([]int, len(entries))
	cursor := buf.Len()
	for i, e := range entries {
		recOff[i] = cursor + 4 // 记录体之前有 4 字节起始 IP
		body := 0
		switch e.mode {
		case "redirect":
			body = 1 + 3
		case "ptr":
			body = 1 + 3 + len(gbkBytes(t, e.isp)) + 1
		case "plain":
			body = len(gbkBytes(t, e.loc)) + 1 + len(gbkBytes(t, e.isp)) + 1
		default:
			t.Fatalf("未知 mode %q", e.mode)
		}
		cursor += 4 + body
	}

	for i, e := range entries {
		ipv4 := net.ParseIP(e.startIP).To4()
		if ipv4 == nil {
			t.Fatalf("%q 不是 IPv4", e.startIP)
		}
		if got := buf.Len() + 4; got != recOff[i] {
			t.Fatalf("偏移预算与写入不一致：预算 %d，实际 %d", recOff[i], got)
		}
		binary.Write(&buf, binary.LittleEndian, binary.BigEndian.Uint32(ipv4))

		switch e.mode {
		case "redirect":
			buf.WriteByte(qqwryModeRedirect)
			writeUint24(&buf, recOff[e.locRef])
		case "ptr":
			buf.WriteByte(qqwryModePointer)
			writeUint24(&buf, locOff[e.loc])
			buf.Write(gbkBytes(t, e.isp))
			buf.WriteByte(0)
		case "plain":
			buf.Write(gbkBytes(t, e.loc))
			buf.WriteByte(0)
			buf.Write(gbkBytes(t, e.isp))
			buf.WriteByte(0)
		}
	}

	indexStart := buf.Len()
	for i, e := range entries {
		ipv4 := net.ParseIP(e.startIP).To4()
		binary.Write(&buf, binary.LittleEndian, binary.BigEndian.Uint32(ipv4))
		writeUint24(&buf, recOff[i]-4) // 索引偏移 = 记录起点 - 4（读取方会 +4）
	}
	indexEnd := indexStart + (len(entries)-1)*qqwryIndexEntry

	out := buf.Bytes()
	binary.LittleEndian.PutUint32(out[0:4], uint32(indexStart))
	binary.LittleEndian.PutUint32(out[4:8], uint32(indexEnd))
	return out
}

func writeUint24(buf *bytes.Buffer, v int) {
	buf.Write([]byte{byte(v), byte(v >> 8), byte(v >> 16)})
}

func writeSynthDB(t *testing.T, dir string, entries []synthEntry) string {
	t.Helper()
	p := filepath.Join(dir, "qqwry.dat")
	if err := os.WriteFile(p, buildQQWry(t, entries), 0o644); err != nil {
		t.Fatalf("写合成库失败: %v", err)
	}
	return p
}

func TestGeoDBParsesAllRecordShapes(t *testing.T) {
	dir := t.TempDir()
	path := writeSynthDB(t, dir, []synthEntry{
		// 0x02：地点串在别处、ISP 紧跟模式字节
		{startIP: "1.0.0.0", mode: "ptr", loc: "中国–测试省–测试市", isp: "测试运营商"},
		// 0x01：再跳一层，最终落到上一条那种形态
		{startIP: "2.0.0.0", mode: "redirect", locRef: 2},
		// 被 0x01 指向的那条
		{startIP: "3.0.0.0", mode: "ptr", loc: "美国–测试州–测试城", isp: "海外运营商"},
		// plain：地点串 + ISP 串直接排列
		{startIP: "4.0.0.0", mode: "plain", loc: "中国–另一省–另一市", isp: "另一个运营商"},
		// 空地点串：库在、但这条没收录 → unknown
		{startIP: "5.0.0.0", mode: "plain", loc: "", isp: ""},
	})

	db, err := openGeoDB(path)
	if err != nil {
		t.Fatalf("打开合成库失败: %v", err)
	}
	defer db.Close()
	if db.count != 5 {
		t.Errorf("索引条数应为 5，实际 %d", db.count)
	}

	cases := []struct {
		ip       string
		status   string
		country  string
		province string
		city     string
		isp      string
	}{
		{"1.2.3.4", GeoOK, "中国", "测试省", "测试市", "测试运营商"},
		{"2.9.9.9", GeoOK, "美国", "测试州", "测试城", "海外运营商"},
		{"4.0.0.1", GeoOK, "中国", "另一省", "另一市", "另一个运营商"},
		{"5.0.0.1", GeoUnknown, "", "", "", ""},
	}
	for _, c := range cases {
		gi := db.lookup(c.ip)
		if gi.Status != c.status {
			t.Errorf("%s：状态应为 %s，实际 %s（%+v）", c.ip, c.status, gi.Status, gi)
			continue
		}
		if c.status != GeoOK {
			continue
		}
		if gi.Country != c.country || gi.Province != c.province || gi.City != c.city {
			t.Errorf("%s：地域切分不对，得到 %s/%s/%s，期望 %s/%s/%s",
				c.ip, gi.Country, gi.Province, gi.City, c.country, c.province, c.city)
		}
		if !strings.Contains(gi.Detail, c.isp) {
			t.Errorf("%s：Detail 里应当有 ISP %q，实际 %q", c.ip, c.isp, gi.Detail)
		}
	}

	// 再查一遍同一个 IP：应当命中缓存（缓存的意义就是在日志页反复渲染时不再读文件）
	db.lookup("1.2.3.4")
	if db.hits.Load() == 0 {
		t.Error("重复查询应当命中缓存")
	}
	if db.queries.Load() < 2 {
		t.Errorf("查询计数应当把两次都算上，实际 %d", db.queries.Load())
	}
}

func TestGeoDBRejectsGarbageFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "qqwry.dat")
	if err := os.WriteFile(p, []byte("这不是一个 qqwry 库，只是一段文本"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 宁可明确报「不是库」，也不要每次查询都返回垃圾地名
	if _, err := openGeoDB(p); err == nil {
		t.Error("随便一个文件不该被当成 qqwry 库")
	}
}

func TestGeoStatusPaths(t *testing.T) {
	// 库里没有可用数据时：明确区分「没启用」「格式不对」「内网」「IPv6」
	db := &geoDB{cache: map[string]GeoInfo{}, size: 0}
	if gi := db.lookup("不是IP"); gi.Status != GeoBadIP {
		t.Errorf("非法 IP 应当是 bad_ip，实际 %s", gi.Status)
	}
	if gi := db.lookup("127.0.0.1"); gi.Status != GeoInternal {
		t.Errorf("回环应当是 internal，实际 %s", gi.Status)
	}
	if gi := db.lookup("192.168.1.1"); gi.Status != GeoInternal {
		t.Errorf("私网应当是 internal，实际 %s", gi.Status)
	}
	if gi := db.lookup("2001:4860:4860::8888"); gi.Status != GeoUnsupported {
		t.Errorf("IPv6 应当是 unsupported（库不含 IPv6），实际 %s", gi.Status)
	}

	var nilDB *geoDB
	if gi := nilDB.lookup("8.8.8.8"); gi.Status != GeoUnavailable {
		t.Errorf("库为空应当是 unavailable，实际 %s", gi.Status)
	}
}

func TestGeoAppMetaWithoutFile(t *testing.T) {
	a := &App{}
	m := a.geoMeta()
	if m.Available {
		t.Error("没载入库时 geoMeta 应当报不可用")
	}
	if m.Reason == "" {
		t.Error("不可用时必须给出原因，界面要显示它")
	}
	// 查询也要给出可展示的结论，而不是空字符串
	if gi := a.geoLookup("8.8.8.8"); gi.Status != GeoUnavailable {
		t.Errorf("未载入时查询应当返回 unavailable，实际 %s", gi.Status)
	}
	if gi := a.geoLookup(""); gi.Status != "" {
		t.Errorf("没有 IP 时不该编一个状态出来，实际 %s", gi.Status)
	}
}

func TestGeoPathCandidatesPriority(t *testing.T) {
	cands := geoPathCandidates("", filepath.Join("etc", "goproxy", "goproxy.db"), filepath.Join("usr", "local", "bin", "goproxy"))
	if len(cands) < 2 {
		t.Fatalf("应当给出多个候选位置，实际 %v", cands)
	}
	if !strings.HasPrefix(cands[0], filepath.Join("etc", "goproxy")) {
		t.Errorf("配置库同目录应当排在候选第一位，实际 %v", cands)
	}
	// 显式指定时只用它 —— 不该再被兜底位置盖过
	explicit := geoPathCandidates("/data/geo/qqwry.dat", "etc/goproxy/goproxy.db", "usr/local/bin/goproxy")
	if len(explicit) != 1 || explicit[0] != "/data/geo/qqwry.dat" {
		t.Errorf("显式指定应当独占候选列表，实际 %v", explicit)
	}
}

// closeGeoOnCleanup 注册「测试结束前关掉地域库的文件句柄」。
//
// Windows 上不关的话，t.TempDir 的清理会报「文件正被另一个程序使用」，
// 而那个报错完全指不到真正的原因 —— 和 storehelp_test.go 里记的是同一类坑。
func closeGeoOnCleanup(t *testing.T, a *App) {
	t.Helper()
	t.Cleanup(func() {
		if st := a.geo.Load(); st != nil && st.db != nil {
			st.db.Close()
		}
	})
}

func TestGeoRefreshReloadsWhenFileChanges(t *testing.T) {
	dir := t.TempDir()
	// 把配置库放在同一个目录里，这样候选位置的第一个就命中
	a := &App{configDB: filepath.Join(dir, "goproxy.db")}
	closeGeoOnCleanup(t, a)

	// 先造一个只有 1.0.0.0 段的库
	writeSynthDB(t, dir, []synthEntry{
		{startIP: "1.0.0.0", mode: "ptr", loc: "中国–旧省–旧市", isp: "旧运营商"},
	})
	a.refreshGeo("")
	if m := a.geoMeta(); !m.Available {
		t.Fatalf("库应当已载入，实际 %+v", m)
	}
	if gi := a.geoLookup("1.2.3.4"); gi.Province != "旧省" {
		t.Fatalf("载入后应当能查到，实际 %+v", gi)
	}
	// 缓存里有值了，才能验证「换库之后缓存不会串味」
	if gi := a.geoLookup("1.2.3.4"); gi.Province != "旧省" {
		t.Fatalf("第二次查询不一致: %+v", gi)
	}

	// 覆盖成新内容，并把 mtime 推到明显的未来（有些文件系统时间戳粒度粗，
	// 覆盖后 mtime 可能没变，那会让「变了才重载」的判断失效 —— 测试要能
	// 明确区分这两种情况）
	writeSynthDB(t, dir, []synthEntry{
		{startIP: "1.0.0.0", mode: "ptr", loc: "中国–新省–新市", isp: "新运营商"},
	})
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filepath.Join(dir, "qqwry.dat"), future, future); err != nil {
		t.Fatalf("改 mtime 失败: %v", err)
	}

	a.refreshGeo("")
	gi := a.geoLookup("1.2.3.4")
	if gi.Province != "新省" {
		t.Errorf("文件变了之后应当换用新库（缓存也要跟着失效），实际 %+v", gi)
	}

	// 文件没变时不该重载：命中统计应当继续累加
	before := a.geoMeta().Queries
	a.refreshGeo("")
	a.geoLookup("9.9.9.9")
	if after := a.geoMeta().Queries; after <= before {
		t.Errorf("没换库时不该重置统计：before=%d after=%d", before, after)
	}
}

func TestNoteGeoMissingFileIsNotFatal(t *testing.T) {
	dir := t.TempDir()
	a := &App{configDB: filepath.Join(dir, "goproxy.db")}
	closeGeoOnCleanup(t, a)
	a.refreshGeo(filepath.Join(dir, "不存在.dat"))
	m := a.geoMeta()
	if m.Available {
		t.Error("文件不存在时不该报可用")
	}
	if !strings.Contains(m.Reason, "不存在.dat") && !strings.Contains(m.Reason, "qqwry.dat") {
		t.Errorf("原因里应当带上找过的路径，实际 %q", m.Reason)
	}
}

func TestEnrichGeoOnlyTouchesCopies(t *testing.T) {
	dir := t.TempDir()
	a := &App{configDB: filepath.Join(dir, "goproxy.db")}
	closeGeoOnCleanup(t, a)
	writeSynthDB(t, dir, []synthEntry{
		{startIP: "1.0.0.0", mode: "ptr", loc: "中国–某省–某市", isp: "某运营商"},
	})
	a.refreshGeo("")

	// 真的日志缓冲：Add 进去的记录不该被改动（地域只补在出站副本上）
	buf := newLogBuffer(4)
	stored := buf.Add(LogEntry{ClientIP: "1.2.3.4", Path: "/"})
	if stored.IPGeo != nil {
		t.Error("写入环形缓冲的记录不该带地域 —— 那是每个请求都要走的路径，不该读文件")
	}
	if got := buf.Recent(1)[0]; got.IPGeo != nil {
		t.Error("缓冲里存的记录也不该带地域")
	}

	buf.Add(LogEntry{ClientIP: "1.2.3.4", Path: "/"})
	entries := buf.Recent(10)
	a.enrichGeo(entries)
	if entries[0].IPGeo == nil || entries[0].IPGeo.Province != "某省" {
		t.Errorf("出站副本应当被补上地域，实际 %+v", entries[0].IPGeo)
	}
	// 原缓冲依然干净
	if got := buf.Recent(1)[0]; got.IPGeo != nil {
		t.Error("enrichGeo 只能改副本，不能写回缓冲")
	}
}

func TestSplitGeoHeuristics(t *testing.T) {
	cases := []struct {
		loc, isp                string
		country, province, city string
		district                string
	}{
		{"中国–江苏–南京", "电信", "中国", "江苏", "南京", ""},
		{"中国–北京–北京–海淀区", "联通", "中国", "北京", "北京", "海淀区"},
		{"美国–加利福尼亚州–圣克拉拉–山景城", "谷歌", "美国", "加利福尼亚州", "圣克拉拉", "山景城"},
		{"澳大利亚", "APNIC", "澳大利亚", "", "", ""},
		{"美国–密苏里州", "CZ88.NET", "美国", "密苏里州", "", ""},
		// 老式省市连写
		{"广东省深圳市", "", "", "广东", "深圳市", ""},
		// 单段但不是省名 → 整串当国家，别硬编省市
		{"罗马尼亚", "", "罗马尼亚", "", "", ""},
	}
	for _, c := range cases {
		gi := splitGeo(c.loc, c.isp)
		if gi.Country != c.country || gi.Province != c.province || gi.City != c.city || gi.District != c.district {
			t.Errorf("%q/%q → %s|%s|%s|%s，期望 %s|%s|%s|%s",
				c.loc, c.isp, gi.Country, gi.Province, gi.City, gi.District,
				c.country, c.province, c.city, c.district)
		}
		if !strings.Contains(gi.Detail, c.loc) {
			t.Errorf("Detail 必须保留原始串（切分是启发式的，原话是唯一还原依据）：%q", gi.Detail)
		}
	}

	// CZ88.NET 是「没有 ISP 信息」的占位串，不该出现在 Detail 里当地名用
	if gi := splitGeo("美国", "CZ88.NET"); strings.Contains(gi.Detail, "CZ88.NET") {
		t.Errorf("CZ88.NET 是占位串，不该留在 Detail 里：%q", gi.Detail)
	}
}

// ---------- 真实库（有就跑，没有就跳过）----------

// realQQWryPath 找那份真实的地域库。找不到就返回空 —— 测试里跳过。
//
// 它是个 26 MB 的运行时数据文件，不进仓库（.gitignore 挡着），
// 所以 CI 上必然没有。这里的取舍：**本地用它验证解析器真的读得对，
// CI 上用合成库验证逻辑正确**，两边都不靠对方。
func realQQWryPath() string {
	for _, p := range []string{
		filepath.Join("..", "qqwry.dat"),
		"qqwry.dat",
		filepath.Join("..", "..", "qqwry.dat"),
	} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func TestGeoRealDatabaseKnownIPs(t *testing.T) {
	path := realQQWryPath()
	if path == "" {
		t.Skip("没找到真实的 qqwry.dat（它是 .gitignore 的运行时文件），跳过")
	}
	db, err := openGeoDB(path)
	if err != nil {
		t.Fatalf("打开真实库失败: %v", err)
	}
	defer db.Close()

	// 挑几个稳定的常识地址。断言刻意宽松（只要求包含关键地名），
	// 因为库会定期更新，地名措辞可能微调。
	cases := []struct {
		ip      string
		country string
		mustHas string
	}{
		{"8.8.8.8", "美国", "谷歌"},
		{"220.181.38.148", "中国", "北京"},
		{"114.114.114.114", "中国", "南京"},
	}
	for _, c := range cases {
		gi := db.lookup(c.ip)
		if gi.Status != GeoOK {
			t.Errorf("%s：应当是 ok，实际 %s（%s）", c.ip, gi.Status, gi.Detail)
			continue
		}
		if gi.Country != c.country {
			t.Errorf("%s：国家应为 %q，实际 %q（原文 %q）", c.ip, c.country, gi.Country, gi.Detail)
		}
		if !strings.Contains(gi.Detail, c.mustHas) {
			t.Errorf("%s：原始串里应当含有 %q，实际 %q", c.ip, c.mustHas, gi.Detail)
		}
	}
}

// TestGeoRealDatabaseParseRate 是解析器的防回归闸门。
//
// 直接抽样索引区：如果将来有人（或我）改错了记录布局，成功率会立刻崩下来。
// 实测正确解析时干净率约 99.6%，这里留足余量卡在 95%。
func TestGeoRealDatabaseParseRate(t *testing.T) {
	path := realQQWryPath()
	if path == "" {
		t.Skip("没找到真实的 qqwry.dat，跳过")
	}
	db, err := openGeoDB(path)
	if err != nil {
		t.Fatalf("打开真实库失败: %v", err)
	}
	defer db.Close()

	const sample = 400
	clean, dirty := 0, 0
	for i := 0; i < sample; i++ {
		idx := i * (db.count / sample)
		off, err := db.recordOffset(idx)
		if err != nil {
			t.Fatalf("取索引 %d 的记录偏移失败: %v", idx, err)
		}
		loc, isp, err := db.resolve(off+4, 0)
		if err != nil {
			if err == errGeoOutOfRange {
				dirty++
				continue
			}
			t.Fatalf("解析索引 %d 的记录失败: %v", idx, err)
		}
		if strings.ContainsRune(loc, '\uFFFD') || strings.ContainsRune(isp, '\uFFFD') ||
			len([]rune(loc)) > 60 || len([]rune(isp)) > 60 {
			dirty++
			continue
		}
		clean++
	}
	rate := float64(clean) * 100 / float64(clean+dirty)
	t.Logf("真实库解析干净率 %.1f%%（%d/%d）", rate, clean, clean+dirty)
	if rate < 95 {
		t.Errorf("解析干净率只有 %.1f%%，记录布局可能又读错了", rate)
	}
}
