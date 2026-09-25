package main

// `-config-check` 的测试。
//
// 这个功能的全部价值在于两句话，所以测试也围绕这两句组织：
//
//  1. **它说的就是启动时会说的** —— 所以每条「不通过」的用例都同时跑一遍真启动路径
//     （prepareConfigStore / readConfigFile），断言两者的判词一致。只测一边的话，
//     预检完全可能「自己一套判断、与启动无关」，而那是最坏的结果：
//     它会在该拦的时候放行，或者在该放行的时候拦住。
//  2. **它什么都不改** —— 所以有一条专门的用例给库文件与目录拍快照、跑完再比。
//     「试跑」动手了比不试跑更糟（真迁移一次，还在跑的旧二进制就面对一个
//     它不认识的库）。

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"database/sql"
)

// 一份最简的合法配置（顶层字段留空，靠 applyTopDefaults 补）。
const goodConfigJSON = `{"default_ports":[18080]}`

// 一份 v0.7.x 写法的配置：路由内联 acl —— v0.8.0 起必须拒绝，并给出迁移映射。
// 这正是历史上真正拦住过升级的那种内容，用它来验预检「能不能拦住」。
const legacyInlineACLConfigJSON = `{
  "routes": [
    {
      "id": "web",
      "listen_port": 8080,
      "target": "http://127.0.0.1:9000",
      "acl": {"mode": "allow", "cidrs": ["10.0.0.0/8"]}
    }
  ]
}`

func TestConfigCheckPassesOnSeededDB(t *testing.T) {
	db := tempConfigDB(t)
	seedRawConfig(t, db, []byte(goodConfigJSON))

	note, err := checkConfigUsable(db)
	if err != nil {
		t.Fatalf("合法配置应当通过预检，却被拒：%v", err)
	}
	if !strings.Contains(note, "可以加载") || !strings.Contains(note, "1 个默认端口") {
		t.Errorf("通过时的说明应当带上读到了什么，实际是 %q", note)
	}
}

// TestConfigCheckSaysTheSameThingAsStartup 是「判词一致」那条断言。
func TestConfigCheckSaysTheSameThingAsStartup(t *testing.T) {
	// 用 schema 版本对不上来制造一个「启动必然失败」的局面：
	// 这是最容易两边说法不一致的一格（migrate 与只读预检走的是两条代码路径）。
	db := tempConfigDB(t)
	seedRawConfig(t, db, []byte(goodConfigJSON))

	// 先把连接池关掉再改版本号。这一步不是可有可无的：
	// storeFor 会**按路径缓存连接**，同进程里第二次打开不会重跑 migrate，
	// 于是「启动路径会不会失败」在缓存还在的情况下永远问不出答案。
	// 关了它，"准备启动"才等价于"新进程启动"。
	if err := closeStore(db); err != nil {
		t.Fatalf("关库失败: %v", err)
	}
	// 直接把库里的版本改成一个未来值。绕过 configStore 自己写：
	// 就是要造一个「库比程序新」的真实局面。
	overwriteSchemaVersion(t, db, "99")

	_, checkErr := checkConfigUsable(db)
	if checkErr == nil {
		t.Fatal("schema 版本对不上时预检应当失败")
	}

	startupErr := prepareConfigStoreForTest(t, db)
	if startupErr == nil {
		t.Fatal("schema 版本对不上时启动也应当失败（前提不成立）")
	}

	if checkErr.Error() != startupErr.Error() {
		t.Errorf("预检与启动的判词必须一字不差，否则预检就只是另一个会漂移的说法：\n预检：%s\n启动：%s",
			checkErr, startupErr)
	}
	if !strings.Contains(checkErr.Error(), "99") {
		t.Errorf("判词里应当带上实际读到的版本号：%s", checkErr)
	}
}

// TestConfigCheckRejectsLegacySeedWhenDBEmpty 覆盖最容易写漏的一格：
// 库是空的，而启动会去导入同目录的 config.json —— 只看库（空的）会得出
// 「一切正常」，可实际启动会当场失败。
func TestConfigCheckRejectsLegacySeedWhenDBEmpty(t *testing.T) {
	db := tempConfigDB(t)
	// 建一个空库（有表、没有配置）。
	st, err := openConfigStore(db)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("关库失败: %v", err)
	}
	seedLegacyConfigFile(t, filepath.Dir(db), []byte(legacyInlineACLConfigJSON))

	_, err = checkConfigUsable(db)
	if err == nil {
		t.Fatal("空库 + 旧写法 config.json 必须被判为不通过")
	}
	// 迁移映射必须完整地在里面：这是这个功能存在的全部意义。
	for _, want := range []string{"ip_lists", "config.json", "迁移"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("判词里缺少 %q，实际是：\n%s", want, err)
		}
	}

	// 换成一份合法种子就应当通过（否则这条检查会把正常场景也拦住）。
	writeFileStr(t, filepath.Join(filepath.Dir(db), "config.json"), goodConfigJSON)
	if _, err := checkConfigUsable(db); err != nil {
		t.Errorf("合法的 config.json 不该被拒：%v", err)
	}
}

// TestConfigCheckRejectsJSONPathAsDB 覆盖升级最常见的误操作：-c 还指在 config.json 上。
func TestConfigCheckRejectsJSONPathAsDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeFileStr(t, path, goodConfigJSON)

	_, err := checkConfigUsable(path)
	if err == nil {
		t.Fatal("把 config.json 当配置库必须被拦住")
	}
	if !strings.Contains(err.Error(), "不是 SQLite 数据库") {
		t.Errorf("应当给出「这不是 SQLite 库」的判词，实际：%v", err)
	}
}

// TestConfigCheckDoesNotTouchAnything 是「它不改动配置数据」那条断言。
//
// 断言写成「除 SQLite 的运行时文件外，一个字节都不许变」，而不是「目录不许变」——
// 后者做不到，理由是实测出来的：WAL 模式下**任何**连接（包括只读连接）都要用
// `-shm` 这个共享内存索引协调读位置，而打开一个 WAL 库还可能凭空出现一个
// 0 字节的 `-wal`。两者都不承载配置数据（-shm 是索引、空 -wal 说明什么都没写），
// 但把它们算进「不许变」会让这条断言变成假的 —— 而假断言比没有断言更糟。
//
// 真正承载配置的是主库：它的字节必须一模一样。
func TestConfigCheckDoesNotTouchAnything(t *testing.T) {
	db := tempConfigDB(t)
	seedRawConfig(t, db, []byte(goodConfigJSON))
	// 先关掉连接池：否则库文件被持有，快照与复查之间会因为 WAL 检查点而抖动。
	if err := closeStore(db); err != nil {
		t.Fatalf("关库失败: %v", err)
	}
	dir := filepath.Dir(db)

	before := snapshotDir(t, dir)
	if len(before) == 0 {
		t.Fatal("快照为空，前提不成立")
	}

	if _, err := checkConfigUsable(db); err != nil {
		t.Fatalf("这份配置应当通过预检：%v", err)
	}

	after := snapshotDir(t, dir)
	for _, problem := range snapshotProblems(before, after) {
		t.Errorf("预检改动了配置数据：%s", problem)
	}
}

// snapshotProblems 比较两份目录快照，返回**不允许出现**的差异。
//
// 允许的两类差异都在 SQLite 的运行时文件上，理由见上面那条测试：
//   - -shm 内容变化（共享内存索引，任何连接都会碰）；
//   - -wal 新增（且必须为空 —— 空说明没写任何事务，不空就说明真写了东西）。
func snapshotProblems(before, after []string) []string {
	toMap := func(list []string) map[string]string {
		m := map[string]string{}
		for _, l := range list {
			parts := strings.SplitN(l, " ", 2)
			m[parts[0]] = l
		}
		return m
	}
	b, a := toMap(before), toMap(after)

	var problems []string
	for name, line := range a {
		if old, ok := b[name]; ok {
			if old != line && !strings.HasSuffix(name, "-shm") {
				problems = append(problems, name+" 内容变了：之前 "+old+"，之后 "+line)
			}
			continue
		}
		// 新增的文件：只放过空的 -wal / 任意 -shm。
		if strings.HasSuffix(name, "-shm") {
			continue
		}
		if strings.HasSuffix(name, "-wal") && strings.Contains(line, " size=0 ") {
			continue
		}
		problems = append(problems, "凭空多出文件 "+line)
	}
	for name, line := range b {
		if _, ok := a[name]; !ok {
			problems = append(problems, "文件被删掉了 "+line)
		}
	}
	return problems
}

// TestConfigCheckDoesNotCreateMissingDB 是同一个不变量的另一半：
// 库不存在时，预检**不能顺手把它建出来**（sqlite 的 open 带 CREATE 标志，
// 对着不存在的路径 Ping 会留下一个 0 字节文件）。
func TestConfigCheckDoesNotCreateMissingDB(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "goproxy.db")

	note, err := checkConfigUsable(db)
	if err != nil {
		t.Fatalf("全新安装（没有库、也没有 config.json）应当通过：%v", err)
	}
	if !strings.Contains(note, "还不存在") {
		t.Errorf("应当说明「库还不存在、启动时会创建」，实际 %q", note)
	}
	if _, err := os.Stat(db); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("预检不该创建配置文件，但 %s 已经存在了", db)
	}
}

// TestConfigCheckUnsupportedOnOldBinary 守住「降级到旧版本」这条路。
//
// 用一个不认识 -config-check 的二进制（测试进程自己就是：testing 会先 flag.Parse，
// 遇到未定义的开关就按 flag 包的标准方式报错并退出 2），断言它被认成
// **跳过**而不是**失败** —— 否则一次正常的降级会被自己的检查拦住，
// 而拦住它的理由是「你没带这个开关」，与配置毫无关系。
func TestConfigCheckUnsupportedOnOldBinary(t *testing.T) {
	_, err := checkBinaryConfigUsable(context.Background(), os.Args[0], tempConfigDB(t))
	if !errors.Is(err, errConfigCheckUnsupported) {
		t.Fatalf("应当被认成「不认识这个开关」，实际：%v", err)
	}
}

// TestInstallBlockedWhenConfigIncompatible 是 HTTP 那一层的闭环：
// 预检没过时安装必须被拒（409），带 force 才放行且要带回警告。
func TestInstallBlockedWhenConfigIncompatible(t *testing.T) {
	um, exe := testManager(t)
	um.preflight = failingPreflight("迁移映射：把 acl.mode/cidrs 改成顶层 ip_lists")
	app := &App{upgrade: um}

	stageFakeBinary(t, app, "NEW-BINARY")

	// (1) 不带 force：必须 409，且原因要带上（否则界面只剩一句「安装失败」）
	rec := httptest.NewRecorder()
	app.handleUpgradeInstall(rec, httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/install",
		strings.NewReader(`{}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("配置不兼容时应当 409，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ip_lists") {
		t.Errorf("409 的响应里必须带上迁移映射，实际：%s", rec.Body.String())
	}
	assertContent(t, exe, "OLD-BINARY") // 被拒时绝不能已经换掉文件

	// (2) 带 force：放行，但响应里必须有 warning —— 这种升级的结果可能是服务起不来，
	// 不能让它看起来像一次普通成功。
	rec2 := httptest.NewRecorder()
	app.handleUpgradeInstall(rec2, httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/install",
		strings.NewReader(`{"force":true}`)))
	if rec2.Code != http.StatusOK {
		t.Fatalf("带 force 时应当放行，实际 %d：%s", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "warning") {
		t.Errorf("强制安装的响应里必须有 warning，实际：%s", rec2.Body.String())
	}
	assertContent(t, exe, "NEW-BINARY")
}

// stageFakeBinary 走真实的上传接口把一个假二进制暂存进去。
func stageFakeBinary(t *testing.T, app *App, content string) {
	t.Helper()
	body, ctype := multipartBody(t, "file", "goproxy-linux-amd64", content)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/upload", body)
	req.Header.Set("Content-Type", ctype)
	app.handleUpgradeUpload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("上传失败 %d：%s", rec.Code, rec.Body.String())
	}
}

// multipartBody 拼一个 multipart/form-data 请求体，返回 body 与 Content-Type。
func multipartBody(t *testing.T, field, filename, content string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("构造 multipart 失败: %v", err)
	}
	if _, err := fw.Write([]byte(content)); err != nil {
		t.Fatalf("写 multipart 失败: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("收尾 multipart 失败: %v", err)
	}
	return &body, mw.FormDataContentType()
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

// overwriteSchemaVersion 直接改库里的 schema 版本，绕过 configStore。
func overwriteSchemaVersion(t *testing.T, dbPath, v string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE meta SET value = ? WHERE key = 'schema_version'`, v); err != nil {
		t.Fatalf("改 schema 版本失败: %v", err)
	}
}

// prepareConfigStoreForTest 跑一遍启动时的配置路径，只取它的错误。
//
// 它会把库建出来、也可能导入种子 —— 这些副作用在这里是**要的**：
// 这条用例要回答的正是「真启动会怎么说」。
func prepareConfigStoreForTest(t *testing.T, dbPath string) error {
	t.Helper()
	err := prepareConfigStore(dbPath)
	// 连接池留着会让 TempDir 删不掉（Windows 上尤其明显）。
	t.Cleanup(func() { _ = closeStore(dbPath) })
	if err != nil {
		return err
	}
	_, _, lerr := readConfigFile(dbPath)
	return lerr
}

// snapshotDir 记录目录里每个文件的名字、大小与内容哈希。
func snapshotDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读目录失败: %v", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name()+"/")
			continue
		}
		p := filepath.Join(dir, e.Name())
		fi, err := e.Info()
		if err != nil {
			t.Fatalf("读 %s 信息失败: %v", p, err)
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatalf("打开 %s 失败: %v", p, err)
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			t.Fatalf("读 %s 失败: %v", p, err)
		}
		f.Close()
		out = append(out, e.Name()+" size="+strconv.FormatInt(fi.Size(), 10)+
			" sha="+hex.EncodeToString(h.Sum(nil))[:16])
	}
	sort.Strings(out)
	return out
}
