package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func TestPlatformAssetNames(t *testing.T) {
	pkg, sums := platformAssetNames()
	if !strings.HasPrefix(pkg, "goproxy-"+runtime.GOOS+"-"+runtime.GOARCH) {
		t.Errorf("资源名 %q 的平台部分不对", pkg)
	}
	if !strings.HasSuffix(pkg, ".tar.gz") {
		t.Errorf("资源名 %q 应当以 .tar.gz 结尾（发布产物就是 tar.gz）", pkg)
	}
	if sums != "SHA256SUMS-"+runtime.GOARCH+".txt" {
		t.Errorf("校验和文件名 %q 与 CI 打出来的不一致", sums)
	}
}

func TestTagFromReleaseURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/owner/repo/releases/tag/v0.9.1", "v0.9.1"},
		{"/owner/repo/releases/tag/v0.9.1/", "v0.9.1"},
		{"/owner/repo/releases/latest", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := tagFromReleaseURL(c.in); got != c.want {
			t.Errorf("tagFromReleaseURL(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestParseSums(t *testing.T) {
	raw := []byte("aaaa\n" +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  goproxy-linux-amd64.tar.gz\n" +
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  SHA256SUMS-amd64.txt\n")
	got := parseSums(raw, "goproxy-linux-amd64.tar.gz")
	if got != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Errorf("parseSums 取错了行：%q", got)
	}
	// 镜像站经常回一个 200 的 HTML 错误页，这种情况必须解析不出来
	if got := parseSums([]byte("<html>not a sums file</html>"), "goproxy-linux-amd64.tar.gz"); got != "" {
		t.Errorf("HTML 页面不该被解析成校验和：%q", got)
	}
	if got := parseSums(raw, "goproxy-linux-arm64.tar.gz"); got != "" {
		t.Errorf("没有的文件名应当返回空，得到 %q", got)
	}
}

// ---------------------------------------------------------------------------
// 环境判断
// ---------------------------------------------------------------------------

func TestDetectUpgradeEnvSupportsNormalPath(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "goproxy")
	writeFileStr(t, exe, "old")
	env := detectUpgradeEnv(exe)
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
	env := detectUpgradeEnv(exe)
	if env.supported() {
		t.Fatalf("go-build 临时目录不该被支持")
	}
	if !strings.Contains(env.Reason, "go run") {
		t.Errorf("原因里应当提到 go run：%s", env.Reason)
	}
}

func TestDetectUpgradeEnvRejectsMissingExe(t *testing.T) {
	env := detectUpgradeEnv("")
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
// 发布源（用 httptest 假装成 GitHub Releases）
// ---------------------------------------------------------------------------

func TestFetchReleaseOverHTTP(t *testing.T) {
	binary := []byte("fake-binary-bytes")
	srv, sum := fakeReleaseServer(t, "v9.9.9", binary)
	src := newTestSource(srv)

	info, err := src.latestRelease(context.Background(), "")
	if err != nil {
		t.Fatalf("latestRelease: %v", err)
	}
	if info.Tag != "v9.9.9" {
		t.Fatalf("解析出的版本是 %q，期望 v9.9.9", info.Tag)
	}

	dest := filepath.Join(t.TempDir(), "goproxy.staged")
	res, err := src.fetchRelease(context.Background(), info, dest, 1<<20)
	if err != nil {
		t.Fatalf("fetchRelease: %v", err)
	}
	if !res.SumsVerified || res.ArchiveSHA256 != sum {
		t.Errorf("校验信息不对：%+v", res)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, binary) {
		t.Errorf("解出来的二进制是 %q，期望 %q", got, binary)
	}
	if _, err := os.Stat(dest + ".tar.gz"); !os.IsNotExist(err) {
		t.Errorf("下载的 tar.gz 临时文件应当被清掉")
	}
}

func TestFetchReleaseRejectsSumsMismatch(t *testing.T) {
	srv, _ := fakeReleaseServer(t, "v9.9.9", []byte("payload"))
	// 把校验和换成另一个值的服务端：模拟镜像缓存了旧版本
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "SHA256SUMS") {
			assetName, _ := platformAssetNames()
			fmt.Fprintf(w, "%s  %s\n", strings.Repeat("a", 64), assetName)
			return
		}
		srv.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(bad.Close)

	src := newTestSource(bad)
	info := releaseInfo{Tag: "v9.9.9"}
	dest := filepath.Join(t.TempDir(), "goproxy.staged")
	_, err := src.fetchRelease(context.Background(), info, dest, 1<<20)
	if err == nil {
		t.Fatal("校验和对不上时必须拒绝安装")
	}
	var ae *apiError
	if !errors.As(err, &ae) || ae.code != "upgrade_sha256_mismatch" {
		t.Fatalf("错误码不对：%v", err)
	}
}

func TestLatestReleaseAcceptsPinnedVersion(t *testing.T) {
	srv, _ := fakeReleaseServer(t, "v9.9.9", []byte("x"))
	src := newTestSource(srv)
	// 指定版本时不该联网解析（这里甚至不需要服务端活着）
	info, err := src.latestRelease(context.Background(), "0.8.0")
	if err != nil {
		t.Fatalf("latestRelease(指定版本): %v", err)
	}
	if info.Tag != "v0.8.0" {
		t.Errorf("指定版本应当被补上 v 前缀，得到 %q", info.Tag)
	}
	if !strings.HasSuffix(info.HTMLURL, "/releases/tag/v0.8.0") {
		t.Errorf("release 地址不对：%q", info.HTMLURL)
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

func TestHandleUpgradeCheckStoresResult(t *testing.T) {
	um, _ := testManager(t)
	srv, sum := fakeReleaseServer(t, "v9.9.9", []byte("x"))
	um.source = newTestSource(srv)
	app := &App{upgrade: um}

	rec := httptest.NewRecorder()
	app.handleUpgradeCheck(rec, httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/check", strings.NewReader("{}")))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d：%s", rec.Code, rec.Body.String())
	}
	var got upgradeCheckResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Latest != "v9.9.9" || !got.SumsVerified || got.Asset.SHA256 != sum {
		t.Errorf("检查结果不对：%+v", got)
	}
	// 测试进程的 version 是 dev，不是发布版本，所以「比不了」并且按有更新处理
	if got.CurrentComparable {
		t.Errorf("dev 版本不该被当成可比较版本")
	}
	if !got.UpdateAvailable {
		t.Errorf("dev 版本应当报告有可用更新")
	}
	if um.lastCheck() == nil {
		t.Errorf("检查结果应当被记住，供状态接口复用")
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
		strings.NewReader(`{"source":"upload"}`)))
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

func TestInstallFromGitHubSourceFlow(t *testing.T) {
	um, exe := testManager(t)
	srv, sum := fakeReleaseServer(t, "v9.9.9", []byte("FROM-GITHUB"))
	um.source = newTestSource(srv)
	app := &App{upgrade: um}

	rec := httptest.NewRecorder()
	app.handleUpgradeInstall(rec, httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/install",
		strings.NewReader(`{"source":"github"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("安装失败 %d：%s", rec.Code, rec.Body.String())
	}
	var got upgradeInstallResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.SumsVerified || got.SHA256 == "" || got.To != "v9.9.9" {
		t.Errorf("安装结果不对：%+v", got)
	}
	if got.ArchiveSHA256 != sum {
		t.Errorf("archive_sha256 应当是发布包（tar.gz）的校验和，得到 %q 期望 %q", got.ArchiveSHA256, sum)
	}
	if want := sha256Hex([]byte("FROM-GITHUB")); got.SHA256 != want {
		t.Errorf("sha256 应当是最终装上去那个二进制的哈希，得到 %q 期望 %q", got.SHA256, want)
	}
	assertContent(t, exe, "FROM-GITHUB")
	assertContent(t, exe+".old", "OLD-BINARY")
}

func TestInstallRefusesNothingStaged(t *testing.T) {
	um, _ := testManager(t)
	app := &App{upgrade: um}
	rec := httptest.NewRecorder()
	app.handleUpgradeInstall(rec, httptest.NewRequest(http.MethodPost, "/_goproxy/upgrade/install",
		strings.NewReader(`{"source":"upload"}`)))
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
	um := newUpgradeManagerFor(filepath.Join(t.TempDir(), "goproxy"))
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
	um := newUpgradeManagerFor(exe)
	um.verify = func(string) (buildVersion, string, error) {
		return parseBuildVersion("v9.9.9"), "deadbee", nil
	}
	um.restart = func(upgradeEnv) error { return nil }
	um.restartDelay = 0
	return um, exe
}

// fakeReleaseServer 造一个最小的「GitHub Releases」：/releases/latest 会 302 到
// 指定 tag，校验和文件与 tar.gz 都按真实发布的命名提供。
func fakeReleaseServer(t *testing.T, tag string, binary []byte) (*httptest.Server, string) {
	t.Helper()
	archive := buildTarGz(t, map[string][]byte{
		"./goproxy":   binary,
		"./README.md": []byte("docs"),
		"./LICENSE":   []byte("license"),
	})
	assetName, sumsName := platformAssetNames()
	sum := sha256Hex(archive)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			http.Redirect(w, r, "/owner/repo/releases/tag/"+tag, http.StatusFound)
		case strings.Contains(r.URL.Path, "/releases/tag/"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, "<html>release "+tag+"</html>")
		case strings.HasSuffix(r.URL.Path, "/"+sumsName):
			fmt.Fprintf(w, "%s  %s\n", sum, assetName)
		case strings.HasSuffix(r.URL.Path, "/"+assetName):
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, sum
}

// newTestSource 把发布源指到一个 httptest 服务上。apiBase 指到同一个服务的
// /api 前缀（会 404）：这样「API 富化」那条路会安静地失败，测试不碰外网。
func newTestSource(srv *httptest.Server) *releaseSource {
	return &releaseSource{
		githubBase: srv.URL,
		apiBase:    srv.URL + "/api",
		repo:       "owner/repo",
		mode:       "direct",
		client:     srv.Client(),
	}
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
