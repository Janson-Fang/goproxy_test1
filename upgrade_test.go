package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 版本号解析与比较
// ---------------------------------------------------------------------------

func TestParseBuildVersion(t *testing.T) {
	cases := []struct {
		raw     string
		ok      bool
		commits int
		dirty   bool
	}{
		{"v0.9.1", true, 0, false},
		{"0.9.1", true, 0, false}, // 不带 v 也认
		{"v0.9.1-3-gabc1234", true, 3, false},
		{"v0.9.1-dirty", true, 0, true},
		{"v0.9.1-3-gabc1234-dirty", true, 3, true},
		{"v0.10.0", true, 0, false},
		{"abc1234", false, 0, false}, // 没有 tag 时 git describe 给的是提交号
		{"dev", false, 0, false},
		{"", false, 0, false},
		{"v0.9.1-rc1", false, 0, false}, // 预发布号不认，宁可说「比不了」
	}
	for _, c := range cases {
		got := parseBuildVersion(c.raw)
		if got.OK != c.ok {
			t.Errorf("parseBuildVersion(%q).OK = %v，期望 %v", c.raw, got.OK, c.ok)
			continue
		}
		if !c.ok {
			continue
		}
		if got.Commits != c.commits {
			t.Errorf("parseBuildVersion(%q).Commits = %d，期望 %d", c.raw, got.Commits, c.commits)
		}
		if got.Dirty != c.dirty {
			t.Errorf("parseBuildVersion(%q).Dirty = %v，期望 %v", c.raw, got.Dirty, c.dirty)
		}
	}
}

func TestCompareBuild(t *testing.T) {
	must := func(s string) buildVersion {
		t.Helper()
		v := parseBuildVersion(s)
		if !v.OK {
			t.Fatalf("解析不了 %q", s)
		}
		return v
	}
	cases := []struct {
		a, b string
		want int
	}{
		{"v0.9.1", "v0.9.2", -1},
		{"v0.9.2", "v0.9.1", 1},
		{"v0.9.1", "v0.9.1", 0},
		// 按字符串比会把这条判反（'1' < '9'），这是最要命的那个坑
		{"v0.10.0", "v0.9.1", 1},
		// tag 之后还有提交 = 比 tag 新
		{"v0.9.1-3-gabc", "v0.9.1", 1},
		{"v0.9.1", "v0.9.1-3-gabc", -1},
		{"v0.9.1-2-gabc", "v0.9.1-3-gabc", -1},
		// 脏工作区只是标记，不参与排序
		{"v0.9.1-dirty", "v0.9.1", 0},
	}
	for _, c := range cases {
		if got := compareBuild(must(c.a), must(c.b)); got != c.want {
			t.Errorf("compareBuild(%s, %s) = %d，期望 %d", c.a, c.b, got, c.want)
		}
		if got := compareBuild(must(c.b), must(c.a)); got != -c.want {
			t.Errorf("compareBuild(%s, %s) = %d，期望 %d（反向必须对称）", c.b, c.a, got, -c.want)
		}
	}
}

func TestCompareBuildRefusesIncomparable(t *testing.T) {
	// 比不了的时候必须返回 0 并且让调用方靠 OK 区分，而不是硬当成「相等」
	a := parseBuildVersion("dev")
	b := parseBuildVersion("v9.9.9")
	if a.OK || !b.OK {
		t.Fatalf("前提不成立：%v %v", a.OK, b.OK)
	}
	if got := compareBuild(a, b); got != 0 {
		t.Errorf("比不了时应当返回 0，得到 %d", got)
	}
}

// ---------------------------------------------------------------------------
// 环境判断
// ---------------------------------------------------------------------------

func TestDetectUpgradeEnvSupportsNormalPath(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "goproxy")
	writeFileStr(t, exe, "old")
	env := detectUpgradeEnv(exe, filepath.Join(filepath.Dir(exe), "goproxy.db"))
	if !env.supported() {
		t.Fatalf("正常路径应当支持自升级，却被判为：%s", env.Reason)
	}
	if env.Strategy == strategyUnsupported {
		t.Errorf("策略不该是 unsupported")
	}
	if !env.Writable {
		t.Errorf("临时目录应当可写")
	}
}

func TestDetectUpgradeEnvRejectsGoBuildTemp(t *testing.T) {
	// go run / go test 的可执行文件落在 <tmp>/go-buildXXXX/b001/exe/ 下面，
	// 那种路径上替换文件对下次启动毫无影响，必须在界面上就说清楚。
	dir := filepath.Join(os.TempDir(), "go-build123", "b001", "exe")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("建不了临时目录：%v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(os.TempDir(), "go-build123")) })
	exe := filepath.Join(dir, "goproxy")
	writeFileStr(t, exe, "old")
	env := detectUpgradeEnv(exe, filepath.Join(filepath.Dir(exe), "goproxy.db"))
	if env.supported() {
		t.Fatalf("go-build 临时目录不该被支持")
	}
	if !strings.Contains(env.Reason, "go run") {
		t.Errorf("原因里应当提到 go run：%s", env.Reason)
	}
}

func TestDetectUpgradeEnvRejectsMissingExe(t *testing.T) {
	env := detectUpgradeEnv("", "")
	if env.supported() {
		t.Fatal("拿不到可执行文件路径时不该支持自升级")
	}
	if env.Reason == "" {
		t.Error("必须给出原因")
	}
}

// ---------------------------------------------------------------------------
// 替换 / 备份
// ---------------------------------------------------------------------------

func TestSwapBinaryReplacesAndBacksUp(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "goproxy")
	staged := exe + ".staged"
	backup := exe + ".old"
	writeFileStr(t, exe, "OLD")
	writeFileStr(t, staged, "NEW")

	if err := swapBinary(exe, staged, backup, exe+".swap-old-test"); err != nil {
		t.Fatalf("swapBinary: %v", err)
	}
	assertContent(t, exe, "NEW")
	assertContent(t, backup, "OLD")
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Errorf("暂存文件应当已经被 rename 走")
	}
	if _, err := os.Stat(exe + ".swap-old"); !os.IsNotExist(err) {
		t.Errorf("中间的 swap-old 应当被清理掉")
	}
}

func TestSwapBinaryRestoresExeWhenNewFileUnusable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "goproxy")
	writeFileStr(t, exe, "OLD")

	// 新文件不存在，rename 必然失败
	err := swapBinary(exe, filepath.Join(dir, "not-there"), exe+".old", exe+".swap-old-test")
	if err == nil {
		t.Fatal("新文件不存在时应当失败")
	}
	// 关键：失败之后路径上必须还有东西，否则 systemd 重启会得到 203/EXEC
	assertContent(t, exe, "OLD")
}

func TestStageFromDiskRejectsWrongSHA(t *testing.T) {
	um, exe := testManager(t)
	writeFileStr(t, exe+".staged", "BYTES")

	_, err := um.stageFromDisk(strings.Repeat("0", 64))
	if err == nil {
		t.Fatal("sha256 对不上时应当拒绝")
	}
	var ae *apiError
	if !errors.As(err, &ae) || ae.code != "upgrade_sha256_mismatch" {
		t.Fatalf("错误码不对：%v", err)
	}

	sum, err := hashFile(exe + ".staged")
	if err != nil {
		t.Fatal(err)
	}
	st, err := um.stageFromDisk(sum)
	if err != nil {
		t.Fatalf("sha256 正确时应当通过：%v", err)
	}
	if st.Size != int64(len("BYTES")) || st.Version != "v9.9.9" || st.SHA256 != sum {
		t.Errorf("暂存信息不对：%+v", st)
	}
	if v := um.stagedView(); !v.Present || !v.Verified || v.Version != "v9.9.9" {
		t.Errorf("stagedView 不对：%+v", v)
	}
}

// ---------------------------------------------------------------------------
// 管理接口
// ---------------------------------------------------------------------------

func TestHandleUpgradeState(t *testing.T) {
	um, exe := testManager(t)
	writeFileStr(t, exe+".old", "PREVIOUS")
	app := &App{upgrade: um}

	rec := httptest.NewRecorder()
	app.handleUpgradeState(rec, httptest.NewRequest(http.MethodGet, "/_goproxy/upgrade", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d：%s", rec.Code, rec.Body.String())
	}
	var got upgradeStateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Runtime.Exe != exe || got.Runtime.Version != version {
		t.Errorf("运行时信息不对：%+v", got.Runtime)
	}
	if !got.Supported {
		t.Errorf("临时目录（非 go-build）应当支持自升级：%s", got.Reason)
	}
	if !got.Backup.Present || got.Backup.Version != "v9.9.9" {
		t.Errorf("备份信息不对：%+v", got.Backup)
	}
	if got.Busy {
		t.Error("没有升级动作在跑时不该是 busy")
	}
}

func TestUploadThenInstallFlow(t *testing.T) {
	um, exe := testManager(t)
	app := &App{upgrade: um}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", "goproxy-linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("NEW-BINARY")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	app.handleUpgradeUpload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("上传失败 %d：%s", rec.Code, rec.Body.String())
	}
	var staged upgradeStagedView
	if err := json.Unmarshal(rec.Body.Bytes(), &staged); err != nil {
		t.Fatal(err)
	}
	if !staged.Present || !staged.Verified || staged.Version != "v9.9.9" {
		t.Fatalf("暂存状态不对：%+v", staged)
	}

	done := make(chan upgradeEnv, 1)
	um.restart = func(env upgradeEnv) error { done <- env; return nil }

	rec2 := httptest.NewRecorder()
	app.handleUpgradeInstall(rec2, httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/install",
		strings.NewReader(`{}`)))
	if rec2.Code != http.StatusOK {
		t.Fatalf("安装失败 %d：%s", rec2.Code, rec2.Body.String())
	}
	assertContent(t, exe, "NEW-BINARY")
	assertContent(t, exe+".old", "OLD-BINARY")

	select {
	case env := <-done:
		if env.Exe != exe {
			t.Errorf("替换进程时给的路径是 %q，期望 %q", env.Exe, exe)
		}
	case <-time.After(3 * time.Second):
		t.Error("安装成功后应当触发进程替换")
	}
}

// TestUploadTarGzIsExtracted 覆盖「传上来的是发布用的 tar.gz」这条路：
// 服务端按文件头认出 gzip 并解出里面的 goproxy，而不是把压缩包本身当二进制。
// 归档解包逻辑是上传这条路上唯一的复杂步骤，必须有用例守着。
func TestUploadTarGzIsExtracted(t *testing.T) {
	um, _ := testManager(t)
	app := &App{upgrade: um}

	archive := buildTarGz(t, map[string][]byte{
		"./goproxy":   []byte("NEW-BINARY"),
		"./README.md": []byte("docs"),
	})

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", "goproxy-linux-amd64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(archive); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	app.handleUpgradeUpload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("上传 tar.gz 失败 %d：%s", rec.Code, rec.Body.String())
	}

	got, err := os.ReadFile(um.stagePath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("NEW-BINARY")) {
		t.Errorf("暂存位上应当是解出来的二进制 %q，得到 %q", "NEW-BINARY", got)
	}
}

// TestInstallRejectsLegacySource 守住「旧字段必须报错」。
//
// v0.11.0 删掉了下载式升级，但旧的控制台页面（浏览器缓存）仍会带上
// `{"source":"github"}`。静默忽略它会让这个请求变成另一个意思 ——
// 「装服务端手上那份暂存文件」，而不是用户以为的「去下载一版」。
func TestInstallRejectsLegacySource(t *testing.T) {
	um, _ := testManager(t)
	app := &App{upgrade: um}

	rec := httptest.NewRecorder()
	app.handleUpgradeInstall(rec, httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/install",
		strings.NewReader(`{"source":"github"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("带旧 source 字段的请求应当被拒，得到 %d：%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "upgrade_source_removed") {
		t.Errorf("错误码不对：%s", rec.Body.String())
	}
}

func TestInstallRefusesNothingStaged(t *testing.T) {
	um, _ := testManager(t)
	app := &App{upgrade: um}
	rec := httptest.NewRecorder()
	app.handleUpgradeInstall(rec, httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/install",
		strings.NewReader(`{}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("没有暂存文件时应当 409，得到 %d：%s", rec.Code, rec.Body.String())
	}
}

func TestRollbackRestoresBackup(t *testing.T) {
	um, exe := testManager(t)
	writeFileStr(t, exe+".old", "PREVIOUS-BINARY")
	app := &App{upgrade: um}

	rec := httptest.NewRecorder()
	app.handleUpgradeRollback(rec, httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/rollback",
		strings.NewReader("{}")))
	if rec.Code != http.StatusOK {
		t.Fatalf("回退失败 %d：%s", rec.Code, rec.Body.String())
	}
	assertContent(t, exe, "PREVIOUS-BINARY")
	// 回退之后备份变成「刚才在跑的那一版」，所以还能再切回去
	assertContent(t, exe+".old", "OLD-BINARY")
}

func TestRollbackWithoutBackup(t *testing.T) {
	um, _ := testManager(t)
	app := &App{upgrade: um}
	rec := httptest.NewRecorder()
	app.handleUpgradeRollback(rec, httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/rollback",
		strings.NewReader("{}")))
	if rec.Code != http.StatusConflict {
		t.Fatalf("没有备份时应当 409，得到 %d：%s", rec.Code, rec.Body.String())
	}
}

func TestUpgradeActionIsSerialized(t *testing.T) {
	um, _ := testManager(t)
	app := &App{upgrade: um}
	// 手动占住 busy：第二个动作必须被拒绝，而不是两个升级互相踩
	if !um.begin() {
		t.Fatal("第一次 begin 应当成功")
	}
	rec := httptest.NewRecorder()
	app.handleUpgradeRollback(rec, httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/rollback",
		strings.NewReader("{}")))
	if rec.Code != http.StatusConflict {
		t.Fatalf("忙的时候应当 409，得到 %d：%s", rec.Code, rec.Body.String())
	}
	um.end()
}

// ---------------------------------------------------------------------------
// 真正执行二进制的那条路径
// ---------------------------------------------------------------------------

func TestVerifyBinaryRejectsGarbage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-a-binary")
	writeFileStr(t, p, "这不是一个可执行文件")
	if _, _, err := verifyBinary(p); err == nil {
		t.Fatal("普通文本文件不该通过验证")
	}
}

// TestVerifyBinaryAcceptsRealGoproxy 真的编译一个小程序再执行它，
// 覆盖「验证 = 真的跑一次 -version」这条生产路径。
//
// 没有 go 工具链（或本机建不了）就跳过：这条测试的价值是覆盖真实路径，
// 为它引入一个「必须能编译」的硬依赖不值得。
func TestVerifyBinaryAcceptsRealGoproxy(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("本机没有 go 工具链，跳过")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	program := "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"goproxy v9.9.9 (commit deadbee)\") }\n"
	if err := os.WriteFile(src, []byte(program), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "fake-goproxy")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=", "CGO_ENABLED=0")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("本机编译不出测试二进制，跳过：%v（%s）", err, truncateForMsg(string(msg)))
	}
	bv, commit, err := verifyBinary(out)
	if err != nil {
		t.Fatalf("真二进制应当通过验证：%v", err)
	}
	if bv.Raw != "v9.9.9" || commit != "deadbee" {
		t.Errorf("自述版本解析结果不对：%q %q", bv.Raw, commit)
	}
}

func TestNewUpgradeManagerWiresRealBehaviours(t *testing.T) {
	// 注入点必须有默认值，否则生产路径上 verify/restart 会是 nil 调用
	um := newUpgradeManagerFor(filepath.Join(t.TempDir(), "goproxy"), filepath.Join(t.TempDir(), "goproxy.db"))
	if um.verify == nil || um.restart == nil || um.restartDelay != upgradeRestartDelay {
		t.Fatalf("默认注入点没接上：verify=%v restart=%v delay=%v",
			um.verify != nil, um.restart != nil, um.restartDelay)
	}
}

// ---------------------------------------------------------------------------
// 测试辅助
// ---------------------------------------------------------------------------

// testManager 造一个指向临时目录的 manager，并把「真会动格」的两件事换成替身。
func testManager(t *testing.T) (*upgradeManager, string) {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "goproxy")
	writeFileStr(t, exe, "OLD-BINARY")
	um := newUpgradeManagerFor(exe, filepath.Join(filepath.Dir(exe), "goproxy.db"))
	um.verify = func(string) (buildVersion, string, error) {
		return parseBuildVersion("v9.9.9"), "deadbee", nil
	}
	um.restart = func(upgradeEnv) error { return nil }
	um.restartDelay = 0
	return um, exe
}

func buildTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names) // map 迭代顺序随机，排一下让产物稳定
	for _, n := range names {
		b := files[n]
		hdr := &tar.Header{Name: n, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func writeFileStr(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func assertContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 %s 失败：%v", path, err)
	}
	if string(got) != want {
		t.Errorf("%s 的内容是 %q，期望 %q", path, got, want)
	}
}

// TestParkedPathIsUniquePerSwap 守住 Windows 上那个坑的一部分：
// 两次替换必须用不同的临时名字，否则第二次会撞上「删不掉的旧映像」。
func TestParkedPathIsUniquePerSwap(t *testing.T) {
	um, _ := testManager(t)
	a, b := um.parkedPath(), um.parkedPath()
	if a == b {
		t.Fatalf("同一个进程里两次替换必须用不同的临时名，实际都是 %s", a)
	}
	if !strings.HasPrefix(a, um.exe+".swap-old") || !strings.HasPrefix(b, um.exe+".swap-old") {
		t.Errorf("临时名应当以 <exe>.swap-old 开头（下次启动要按这个前缀清理）：%q %q", a, b)
	}
}

func TestCleanupRemovesLeftoversButKeepsBackup(t *testing.T) {
	_, exe := testManager(t)
	writeFileStr(t, exe+".staged", "S")
	writeFileStr(t, exe+".swap-old-111", "P1")
	writeFileStr(t, exe+".swap-old-222", "P2")
	writeFileStr(t, exe+".old", "BACKUP")

	cleanupUpgradeLeftovers(exe)

	for _, p := range []string{exe + ".staged", exe + ".swap-old-111", exe + ".swap-old-222"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s 应当被清理掉", filepath.Base(p))
		}
	}
	// 备份必须留着：它是回退的唯一依据，清掉等于把回退能力一起清掉了
	assertContent(t, exe+".old", "BACKUP")
}

// TestTwoInstallsThroughManagerInARow 覆盖「同一个进程里连续替换两次」。
//
// 这正是 Windows 上实测踩到的那个坑：第一次替换之后旧映像仍被当前进程锁着、
// 删不掉，只能以 .swap-old-<时间戳> 的名字留在磁盘上；第二次替换（比如升级完
// 想回退）如果还用那个固定的名字，rename 的目标正好是那个锁着的文件，直接
// Access is denied。Linux 上 rename 会直接覆盖，所以这个用例在 Linux 上恒过，
// 但它把「同一个进程里能连换两次」这条不变量钉住了。
func TestTwoInstallsThroughManagerInARow(t *testing.T) {
	um, exe := testManager(t)
	env := um.env()
	if !env.supported() {
		t.Skipf("环境不支持自升级：%s", env.Reason)
	}
	for i, content := range []string{"V1", "V2"} {
		writeFileStr(t, exe+".staged", content)
		st, err := um.stageFromDisk("")
		if err != nil {
			t.Fatalf("第 %d 次暂存失败：%v", i+1, err)
		}
		if err := um.install(env, st); err != nil {
			t.Fatalf("第 %d 次替换失败：%v", i+1, err)
		}
		assertContent(t, exe, content)
	}
	// 第二次替换会把「第一次换上去的那份」备份下来
	assertContent(t, exe+".old", "V1")
}

// ---------------------------------------------------------------------------
// 托管升级（binary 目录写不进去时：控制台暂存，root 应用）
//
// 这条路的现实来源：install.sh 装出来的实例里服务以 goproxy 身份跑，
// ReadWritePaths 只放行 $STATE_DIR 与 $CONFIG_DIR，而 /usr/local/bin 归 root，
// 于是进程死活写不进二进制目录  但它仍然能下载、校验、验证。
// ---------------------------------------------------------------------------

// makeExeDirReadOnly 让「二进制目录不可写」在测试里可复现。
//
// Windows 上造不出真正不可写的目录（目录只读属性与 Unix 权限位不是一回事），
// 所以在判断函数上做替换；新增的每处替换都必须自己恢复，避免串到别的用例。
func makeExeDirReadOnly(t *testing.T, exeDir string) {
	t.Helper()
	saved := upgradeDirWritable
	t.Cleanup(func() { upgradeDirWritable = saved })
	upgradeDirWritable = func(d string) bool {
		return filepath.Clean(d) != filepath.Clean(exeDir)
	}
}

func TestDetectUpgradeEnvDelegatesWhenExeDirReadOnly(t *testing.T) {
	exeDir := t.TempDir()
	stateDir := t.TempDir()
	exe := filepath.Join(exeDir, "goproxy")
	writeFileStr(t, exe, "old")
	cfg := filepath.Join(stateDir, "goproxy.db")

	makeExeDirReadOnly(t, exeDir)

	env := detectUpgradeEnv(exe, cfg)
	if !env.supported() {
		t.Fatalf("二进制目录不可写时应当降级为托管升级，而不是直接不支持：%s", env.Reason)
	}
	if env.Writable {
		t.Error("不该认为二进制目录可写")
	}
	if !env.Delegated {
		t.Error("应当标记为 Delegated")
	}
	if env.canSwap() {
		t.Error("canSwap 应为 false：进程不能自己换")
	}
	want := filepath.Join(stateDir, "upgrade")
	if env.StageDir != want {
		t.Errorf("暂存目录 = %q，期望 %q", env.StageDir, want)
	}
	if fi, err := os.Stat(want); err != nil || !fi.IsDir() {
		t.Errorf("暂存目录应当被建出来：%v", err)
	}
}

func TestDetectUpgradeEnvUnsupportedWhenNothingWritable(t *testing.T) {
	exeDir := t.TempDir()
	exe := filepath.Join(exeDir, "goproxy")
	writeFileStr(t, exe, "old")

	saved := upgradeDirWritable
	t.Cleanup(func() { upgradeDirWritable = saved })
	upgradeDirWritable = func(string) bool { return false }

	env := detectUpgradeEnv(exe, filepath.Join(exeDir, "goproxy.db"))
	if env.supported() {
		t.Fatal("两边都写不进去时应当判为不支持")
	}
	if !strings.Contains(env.Reason, "没有写权限") {
		t.Errorf("原因里应当说明写权限问题：%s", env.Reason)
	}
}

func TestStagedCandidatesCoversDelegatedDir(t *testing.T) {
	exeDir := t.TempDir()
	stateDir := t.TempDir()
	exe := filepath.Join(exeDir, "goproxy")
	cfg := filepath.Join(stateDir, "goproxy.db")
	um := newUpgradeManagerFor(exe, cfg)

	got := um.stagedCandidates()
	if len(got) != 2 {
		t.Fatalf("应当有两个候选暂存位，得到 %v", got)
	}
	if got[0] != exe+".staged" {
		t.Errorf("第一个候选应当是二进制旁边：%q", got[0])
	}
	if want := filepath.Join(stateDir, "upgrade", "goproxy.staged"); got[1] != want {
		t.Errorf("第二个候选应当是状态目录：%q，期望 %q", got[1], want)
	}
	// 文件放在状态目录里也必须能被找出来（root 应用那条路依赖它）
	if err := os.MkdirAll(filepath.Dir(got[1]), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFileStr(t, got[1], "STAGED")
	if found := um.findStaged(); found != got[1] {
		t.Errorf("findStaged = %q，期望 %q", found, got[1])
	}
}

func TestApplyCommandIsCopyPasteable(t *testing.T) {
	dir := t.TempDir()
	um := newUpgradeManagerFor(filepath.Join(dir, "goproxy"), "/etc/goproxy/goproxy.db")
	cmd := um.applyCommand(false)
	if !strings.HasSuffix(cmd, "-upgrade-apply") || !strings.Contains(cmd, um.exe) {
		t.Errorf("applyCommand 不像一条能跑的 sudo 命令：%q", cmd)
	}
	if !strings.Contains(cmd, "-c /etc/goproxy/goproxy.db ") {
		t.Errorf("applyCommand 少了 -c：%q", cmd)
	}
	if got := um.applyCommand(true); !strings.HasSuffix(got, "-upgrade-rollback") {
		t.Errorf("回退命令不对：%q", got)
	}

	// 路径里有空格要加引号，否则复制出去就是一串报错
	um2 := newUpgradeManagerFor("/opt/my proxy/goproxy", "/etc/my state/goproxy.db")
	got := um2.applyCommand(false)
	if !strings.Contains(got, "'/opt/my proxy/goproxy'") || !strings.Contains(got, "'/etc/my state/goproxy.db'") {
		t.Errorf("带空格的路径没有加引号：%s", got)
	}
}

func TestUpgradeDelegatesToRootOnReadOnlyExeDir(t *testing.T) {
	exeDir := t.TempDir()
	stateDir := t.TempDir()
	exe := filepath.Join(exeDir, "goproxy")
	writeFileStr(t, exe, "OLD-BINARY")
	cfg := filepath.Join(stateDir, "goproxy.db")

	um := newUpgradeManagerFor(exe, cfg)
	um.verify = func(string) (buildVersion, string, error) {
		return parseBuildVersion("v9.9.9"), "deadbee", nil
	}
	um.restartDelay = 0
	um.restart = func(upgradeEnv) error {
		t.Error("托管模式下不该由服务自己替换进程")
		return nil
	}
	makeExeDirReadOnly(t, exeDir)

	app := &App{upgrade: um}
	wantStage := filepath.Join(stateDir, "upgrade", "goproxy.staged")

	// 1) 上传：应当落到状态目录，而不是（不可写的）二进制旁边
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", "goproxy-linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("NEW-BINARY")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	app.handleUpgradeUpload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("上传失败 %d：%s", rec.Code, rec.Body.String())
	}
	var staged upgradeStagedView
	if err := json.Unmarshal(rec.Body.Bytes(), &staged); err != nil {
		t.Fatal(err)
	}
	if staged.Path != wantStage {
		t.Errorf("暂存路径 = %q，期望 %q", staged.Path, wantStage)
	}

	// 2) 安装：回 200（已暂存，不是失败）+ needs_root + 命令，且绝对不能动 exe
	rec2 := httptest.NewRecorder()
	app.handleUpgradeInstall(rec2, httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/install",
		strings.NewReader(`{}`)))
	if rec2.Code != http.StatusOK {
		t.Fatalf("托管安装应当回 200，得到 %d：%s", rec2.Code, rec2.Body.String())
	}
	var out upgradeInstallResult
	if err := json.Unmarshal(rec2.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.NeedsRoot || !strings.Contains(out.ApplyCommand, "-upgrade-apply") {
		t.Errorf("应当要求 root 应用并给出命令：%+v", out)
	}
	if out.StagedPath != wantStage || out.StagedSHA256 == "" {
		t.Errorf("应当报出待应用文件的落点与哈希：%+v", out)
	}
	assertContent(t, exe, "OLD-BINARY")
	if _, err := os.Stat(exe + ".old"); !os.IsNotExist(err) {
		t.Error("托管模式下不该产生 .old（那是 root 应用时才备份的）")
	}
	if _, err := os.Stat(wantStage); err != nil {
		t.Errorf("暂存文件应当留着等 root 应用：%v", err)
	}

	// 3) 状态接口：needs_root + 两个命令 + 暂存目录 + 能看到暂存文件
	rec3 := httptest.NewRecorder()
	app.handleUpgradeState(rec3, httptest.NewRequest(http.MethodGet, "/_goproxy/upgrade", nil))
	var st upgradeStateResponse
	if err := json.Unmarshal(rec3.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Supported || st.Writable || !st.NeedsRoot {
		t.Errorf("状态不对：supported=%v writable=%v needs_root=%v", st.Supported, st.Writable, st.NeedsRoot)
	}
	if st.ApplyCommand == "" || st.RollbackCommand == "" || st.StageDir != filepath.Join(stateDir, "upgrade") {
		t.Errorf("状态里应当带上命令与暂存目录：%+v", st)
	}
	if !st.Staged.Present {
		t.Error("状态里应当看到待安装的暂存文件")
	}

	// 4) 回退：同样只给命令
	writeFileStr(t, exe+".old", "PREVIOUS-BINARY")
	rec4 := httptest.NewRecorder()
	app.handleUpgradeRollback(rec4, httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/rollback",
		strings.NewReader("{}")))
	if rec4.Code != http.StatusOK {
		t.Fatalf("托管回退应当回 200，得到 %d：%s", rec4.Code, rec4.Body.String())
	}
	var rb upgradeInstallResult
	if err := json.Unmarshal(rec4.Body.Bytes(), &rb); err != nil {
		t.Fatal(err)
	}
	if !rb.NeedsRoot || !strings.Contains(rb.ApplyCommand, "-upgrade-rollback") {
		t.Errorf("回退应当要求 root 应用：%+v", rb)
	}
	assertContent(t, exe, "OLD-BINARY")
}

// TestRollbackSwapDoesNotClobberItsSource 盯住回退时的那个别名陷阱。
//
// swapBinary 的第一步是「把当前二进制备份到 backupPath」；如果回退的源就是
// backupPath 自己，这一步会先把源覆盖成当前版本，最后装上去的还是原来那一版
// 现象是「回退成功但版本没变」。所以回退必须先复制出一份暂存的源。
func TestRollbackSwapDoesNotClobberItsSource(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "goproxy")
	backup := exe + ".old"
	writeFileStr(t, exe, "CURRENT")
	writeFileStr(t, backup, "PREVIOUS")

	src, err := prepareRollbackSource(exe, backup)
	if err != nil {
		t.Fatalf("prepareRollbackSource: %v", err)
	}
	if filepath.Clean(src) == filepath.Clean(backup) {
		t.Fatal("回退的源不能就是备份文件本身")
	}
	if err := swapBinary(exe, src, backup, exe+".swap-old-test"); err != nil {
		t.Fatalf("swapBinary: %v", err)
	}
	assertContent(t, exe, "PREVIOUS")   // 真的回退了
	assertContent(t, backup, "CURRENT") // 备份换成「刚离开的那一版」，还能再切回去
}

// TestPrepareRollbackSourceWithoutBackup 备份不存在时要给出能看懂的错。
func TestPrepareRollbackSourceWithoutBackup(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "goproxy")
	writeFileStr(t, exe, "CURRENT")
	if _, err := prepareRollbackSource(exe, exe+".old"); err == nil {
		t.Fatal("没有备份时应当报错")
	}
}
