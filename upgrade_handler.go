package main

// 管理接口的升级相关 handler 与视图结构（handleUpgradeState / Install / Rollback 等）。
// 从 upgrade.go 拆出，纯机械移动，逻辑未动。

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// HTTP 视图
// ---------------------------------------------------------------------------

type upgradeRuntimeView struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	GOOS       string `json:"goos"`
	GOARCH     string `json:"goarch"`
	Exe        string `json:"exe"`
	ExeDir     string `json:"exe_dir"`
	Service    string `json:"service"`
	Strategy   string `json:"restart_strategy"`
	Comparable bool   `json:"version_comparable"`
}

// upgradeStagedView 是「有一份等着被装上去的文件」的对外表示。
type upgradeStagedView struct {
	Present  bool   `json:"present"`
	Path     string `json:"path,omitempty"`
	Size     int64  `json:"size,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Version  string `json:"version,omitempty"`
	Commit   string `json:"commit,omitempty"`
	MTime    string `json:"mtime,omitempty"`
	Verified bool   `json:"verified"`
	Source   string `json:"source,omitempty"`
}

type upgradeBackupView struct {
	Present bool   `json:"present"`
	Path    string `json:"path,omitempty"`
	Size    int64  `json:"size,omitempty"`
	Version string `json:"version,omitempty"`
	Commit  string `json:"commit,omitempty"`
	MTime   string `json:"mtime,omitempty"`
}

type upgradeStateResponse struct {
	Runtime   upgradeRuntimeView `json:"runtime"`
	Supported bool               `json:"supported"`
	Reason    string             `json:"reason,omitempty"`
	Writable  bool               `json:"writable"`
	// ReleasePage 是发布页地址：这台机器可能连不上 GitHub（升级要走「上传文件」），
	// 但**你的浏览器**通常能打开它 —— 界面把它给出，省得人去猜去哪下 tar.gz。
	ReleasePage string            `json:"release_page"`
	Staged      upgradeStagedView `json:"staged"`
	Backup      upgradeBackupView `json:"backup"`
	Busy        bool              `json:"busy"`
	// NeedsRoot 表示升级 / 回退的最后一步必须由 root 做：进程能校验、能跑
	// -version 验证，但写不进二进制目录（install.sh 装出来的实例就是这种）。
	// 这时 StageDir 是暂存位置，ApplyCommand / RollbackCommand 是给人复制的命令。
	NeedsRoot       bool   `json:"needs_root"`
	StageDir        string `json:"stage_dir,omitempty"`
	ApplyCommand    string `json:"apply_command,omitempty"`
	RollbackCommand string `json:"rollback_command,omitempty"`
}

// upgradeInstallResult 是安装 / 回退成功后回给控制台的东西。
// 注意它是在**进程被替换之前**写出去的，所以里面的 restart 字段描述的是
// 接下来会发生什么，而不是已经发生了什么。
type upgradeInstallResult struct {
	OK       bool   `json:"ok"`
	From     string `json:"from"`
	To       string `json:"to"`
	SHA256   string `json:"sha256"`
	Backup   string `json:"backup"`
	Restart  string `json:"restart"`
	Service  string `json:"service"`
	Source   string `json:"source"`
	Verified bool   `json:"verified"`
	// NeedsRoot 为 true 时这次「安装」只是把新版本暂存好了，还没换上去：
	// ApplyCommand 是下一步要在服务器上执行的 root 命令，StagedPath / StagedSHA256
	// 是那份待应用文件的落点与哈希，方便人工核对。
	NeedsRoot    bool   `json:"needs_root"`
	ApplyCommand string `json:"apply_command,omitempty"`
	StagedPath   string `json:"staged_path,omitempty"`
	StagedSHA256 string `json:"staged_sha256,omitempty"`
}

// ---------------------------------------------------------------------------
// 处理器
// ---------------------------------------------------------------------------

func upgradeConflict(code, msg string) *apiError {
	return &apiError{http.StatusConflict, code, msg}
}

// readOptionalJSON 读一个可选的 JSON 请求体：空 body 当作「没有参数」。
//
// 管理接口的 readBody 把空 body 当错误（对写配置的接口来说是对的：静默接受
// 一个空 PATCH 会让人以为改成功了）。升级这几个接口不一样
// `curl -X POST /_goproxy/upgrade/install` 不带 body 是完全合理的用法。
func readOptionalJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return badRequest("body_read_failed", "读取请求体失败: %v", err)
	}
	if len(raw) > maxBodyBytes {
		return &apiError{http.StatusRequestEntityTooLarge, "body_too_large", "请求体超过 1MiB"}
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return badRequest("bad_json", "请求体不是合法 JSON：%v", err)
	}
	return nil
}

// actorLabel 给审计日志一个「谁干的」。
//
// adminGuard 只判断「能不能进」，不往 request 里塞身份；升级是这台机器上
// 后果最大的一个动作，日志里必须留下是谁触发的。
func actorLabel(user string, via authVia) string {
	if user != "" {
		return user
	}
	switch via {
	case viaBearer:
		return "(bearer token)"
	case viaSession:
		return "(session)"
	}
	return "(unknown)"
}

// upgradeReleasePage 是发布页地址。
//
// 升级本身已经不向 GitHub 发请求了（跑反代的服务器经常连不上），但**使用者的
// 浏览器**通常能打开它 —— 界面把地址摆出来，人就知道该去哪儿下 tar.gz 再上传。
const upgradeReleasePage = "https://github.com/Janson-Fang/goproxy_test1/releases"

func (a *App) handleUpgradeState(w http.ResponseWriter, r *http.Request) {
	um := a.upgrade
	env := um.env()
	cur := parseBuildVersion(version)

	resp := upgradeStateResponse{
		Runtime: upgradeRuntimeView{
			Version:    version,
			Commit:     commit,
			GOOS:       runtime.GOOS,
			GOARCH:     runtime.GOARCH,
			Exe:        env.Exe,
			ExeDir:     env.Dir,
			Service:    env.Service,
			Strategy:   string(env.Strategy),
			Comparable: cur.OK,
		},
		Supported:   env.supported(),
		Reason:      env.Reason,
		Writable:    env.Writable,
		ReleasePage: upgradeReleasePage,
		Staged:      um.stagedView(),
		Backup:      um.backupView(),
		Busy:        um.isBusy(),
	}
	if env.Delegated {
		// 能校验、能验证，但写不进二进制目录：把「以 root 应用」的命令给出来。
		resp.NeedsRoot = true
		resp.StageDir = env.StageDir
		resp.ApplyCommand = um.applyCommand(false)
		resp.RollbackCommand = um.applyCommand(true)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) handleUpgradeUpload(w http.ResponseWriter, r *http.Request) {
	um := a.upgrade
	env := um.env()
	if !env.supported() {
		writeErr(w, upgradeConflict("upgrade_unsupported", env.Reason))
		return
	}
	if !um.begin() {
		writeErr(w, upgradeConflict("upgrade_busy", "已经有一个升级动作在进行中，等它结束再来。"))
		return
	}
	defer um.end()

	actor := actorLabel(a.identifyAdminRequest(r, sessionHandleFrom(r)))
	src, name, err := openUploadedBinary(r)
	if err != nil {
		writeErr(w, err)
		return
	}

	// 落点由 stagePath 决定：二进制目录可写时就在它旁边（最后那一步 rename 才能
	// 落在同一个文件系统内）；写不进去时退到状态目录，由 root 用 -upgrade-apply 应用。
	stagePath := um.stagePath()
	if stagePath == "" {
		writeErr(w, upgradeConflict("upgrade_unsupported", "没有可写的暂存位置，无法接收上传。"))
		return
	}
	f, err := os.OpenFile(stagePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		writeErr(w, err)
		return
	}
	written, err := io.Copy(f, io.LimitReader(src, upgradeMaxStagedBytes+1))
	if err != nil {
		f.Close()
		_ = os.Remove(stagePath)
		writeErr(w, badRequest("upload_failed", "接收上传数据失败：%v", err))
		return
	}
	if written > upgradeMaxStagedBytes {
		f.Close()
		_ = os.Remove(stagePath)
		writeErr(w, &apiError{http.StatusRequestEntityTooLarge, "upload_too_large",
			fmt.Sprintf("文件超过上限 %d MiB", upgradeMaxStagedBytes>>20)})
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(stagePath)
		writeErr(w, err)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(stagePath)
		writeErr(w, err)
		return
	}

	// 上传的可能是原始二进制，也可能是发布用的 tar.gz（发布页上给人下载的那个包）。
	// 按魔数认，别让人先手动解包一遍。
	if isGzipFile(stagePath) {
		archive := stagePath + ".tar.gz"
		if err := os.Rename(stagePath, archive); err != nil {
			_ = os.Remove(stagePath)
			writeErr(w, err)
			return
		}
		if err := extractBinaryFromArchive(archive, stagePath, upgradeMaxStagedBytes); err != nil {
			_ = os.Remove(archive)
			_ = os.Remove(stagePath)
			writeErr(w, badRequest("bad_archive", "解包上传的 tar.gz 失败：%v", err))
			return
		}
		_ = os.Remove(archive)
	}

	st, err := um.stageFromDisk("")
	if err != nil {
		_ = os.Remove(stagePath)
		writeErr(w, err)
		return
	}
	slog.Info("升级：已接收上传的二进制", "actor", actor, "file", filepath.Base(name),
		"size", st.Size, "sha256", st.SHA256, "version", st.Version)
	writeJSON(w, http.StatusOK, um.stagedView())
}

// handleUpgradeInstall 把「已经暂存好的文件」装上去。
//
// 只有上传这一个来源。下载式升级（向 GitHub Releases 取包）在这台机器上常常
// 连不通 —— 跑反代的服务器多半在受限网络里 —— 与其让一段总是失败的网络逻辑
// 留在升级这条关键路径上，不如把「取更新包」交给使用者的浏览器去做。
func (a *App) handleUpgradeInstall(w http.ResponseWriter, r *http.Request) {
	um := a.upgrade
	env := um.env()
	if !env.supported() {
		writeErr(w, upgradeConflict("upgrade_unsupported", env.Reason))
		return
	}

	var req struct {
		// Source 是 v0.11.0 之前的字段（github | upload）。这里**只为了报错**才留着：
		// 静默忽略一个「选下载源」的字段，会让旧页面提交的 "github" 变成一个含义
		// 完全不同的请求（去装服务端手上那份暂存文件）—— 宁可明确拒绝。
		Source string `json:"source"`
		// SHA256 可选：填了就要求暂存文件和它对得上（防的是「上传之后、
		// 安装之前」这段窗口里文件被换掉）。
		SHA256 string `json:"sha256"`
	}
	if err := readOptionalJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if req.Source != "" {
		writeErr(w, badRequest("upgrade_source_removed",
			"升级源已下线：v0.11.0 起控制台只支持「上传文件升级」。"+
				"如果你看到的是旧的页面，刷新一下控制台再试。"))
		return
	}
	if !um.begin() {
		writeErr(w, upgradeConflict("upgrade_busy", "已经有一个升级动作在进行中，等它结束再来。"))
		return
	}
	defer um.end()

	actor := actorLabel(a.identifyAdminRequest(r, sessionHandleFrom(r)))
	from := version

	st, err := um.stageFromDisk(req.SHA256)
	if err != nil {
		writeErr(w, err)
		return
	}

	// 托管：校验与 -version 验证都已经做完了，但进程写不进去二进制目录，
	// 最后那一步（写文件 + 重启服务）得由 root 来。这不是失败，所以回 200，
	// 把该执行的命令一并给出去；界面据此显示「等待 root 应用」。
	if !env.canSwap() {
		slog.Info("升级：已暂存，等待 root 应用", "actor", actor,
			"from", from, "to", st.Version, "staged", st.Path, "sha256", st.SHA256)
		writeJSON(w, http.StatusOK, upgradeInstallResult{
			OK: true, From: from, To: st.Version, SHA256: st.SHA256,
			Backup: filepath.Base(um.backupPath()), Restart: string(env.Strategy),
			Service: env.Service, Source: st.Source, Verified: true,
			NeedsRoot: true, ApplyCommand: um.applyCommand(false),
			StagedPath: st.Path, StagedSHA256: st.SHA256,
		})
		return
	}

	slog.Info("升级：开始安装", "actor", actor,
		"from", from, "to", st.Version, "sha256", st.SHA256)
	if err := um.install(env, st); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, upgradeInstallResult{
		OK: true, From: from, To: st.Version, SHA256: st.SHA256,
		Backup: filepath.Base(um.backupPath()), Restart: string(env.Strategy),
		Service: env.Service, Source: st.Source, Verified: true,
	})

	// 最后一步：把当前进程换成新二进制。放在响应之后，因为 syscall.Exec
	// 会把进程镜像整个换掉，响应必须已经发出去。
	go um.restartSoon(env, from, st.Version)
}

func (a *App) handleUpgradeRollback(w http.ResponseWriter, r *http.Request) {
	um := a.upgrade
	env := um.env()
	if !env.supported() {
		writeErr(w, upgradeConflict("upgrade_unsupported", env.Reason))
		return
	}
	if !um.begin() {
		writeErr(w, upgradeConflict("upgrade_busy", "已经有一个升级动作在进行中，等它结束再来。"))
		return
	}
	defer um.end()

	actor := actorLabel(a.identifyAdminRequest(r, sessionHandleFrom(r)))
	backupPath := um.backupPath()
	if _, err := os.Stat(backupPath); err != nil {
		writeErr(w, upgradeConflict("upgrade_no_backup",
			"没有可回退的备份（"+filepath.Base(backupPath)+" 不存在）：只有在本机做过一次升级之后才会有备份。"))
		return
	}

	// 托管：进程写不进去二进制目录，回退同样得由 root 应用。这里只把命令给出，
	// 因为回退走的是和升级完全相同的替换路径（同一份 <exe>.old）。
	if !env.canSwap() {
		slog.Info("升级：回退需要 root 应用", "actor", actor, "from", version)
		writeJSON(w, http.StatusOK, upgradeInstallResult{
			OK: true, From: version, To: um.backupView().Version,
			Backup: filepath.Base(backupPath), Restart: string(env.Strategy),
			Service: env.Service, Source: "rollback", Verified: true,
			NeedsRoot: true, ApplyCommand: um.applyCommand(true),
		})
		return
	}

	// 先把备份复制成一份暂存，再走和正常升级完全相同的替换流程。
	// 不直接拿备份文件去 rename 的两个理由：备份要留着（否则回退一次就没了，
	// 想再切回去还得重下），以及「暂存」这条路径上的验证逻辑可以复用。
	stagedPath := um.stagePath()
	if err := copyFile(backupPath, stagedPath, 0o755); err != nil {
		writeErr(w, err)
		return
	}
	st, err := um.stageFromDisk("")
	if err != nil {
		_ = os.Remove(stagedPath)
		writeErr(w, err)
		return
	}

	slog.Info("升级：回退到上一版", "actor", actor, "from", version, "to", st.Version, "sha256", st.SHA256)
	if err := um.install(env, st); err != nil {
		writeErr(w, err)
		return
	}

	writeJSON(w, http.StatusOK, upgradeInstallResult{
		OK: true, From: version, To: st.Version, SHA256: st.SHA256,
		Backup: filepath.Base(backupPath), Restart: string(env.Strategy),
		Service: env.Service, Source: "rollback", Verified: true,
	})
	go um.restartSoon(env, version, st.Version)
}

// openUploadedBinary 从请求里取出要安装的字节流。
//
// 两种提交方式都支持，都是为了「用 curl 也能升级」：
//   - multipart/form-data，字段名 file（浏览器表单，也是控制台在用的）
//   - 请求体就是文件本身（curl --data-binary @goproxy-linux-amd64.tar.gz）
func openUploadedBinary(r *http.Request) (io.Reader, string, error) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		mr, err := r.MultipartReader()
		if err != nil {
			return nil, "", badRequest("bad_multipart", "解析 multipart 请求失败：%v", err)
		}
		for {
			part, err := mr.NextPart()
			if errors.Is(err, io.EOF) {
				return nil, "", badRequest("no_file_part", "multipart 请求里没有找到文件字段（字段名用 file）")
			}
			if err != nil {
				return nil, "", badRequest("bad_multipart", "读取上传数据失败：%v", err)
			}
			if part.FormName() == "file" && part.FileName() != "" {
				return part, part.FileName(), nil
			}
			_ = part.Close()
		}
	}
	if r.ContentLength == 0 {
		return nil, "", badRequest("empty_body",
			"请求体为空：请用 multipart 的 file 字段，或直接把二进制放在请求体里")
	}
	return r.Body, "", nil
}

// isGzipFile 看文件头是不是 gzip 魔数（1f 8b）。用来区分「原始二进制」和
// 「发布用的 tar.gz」，省掉「先自己解包再上传」这一步。
func isGzipFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return magic[0] == 0x1f && magic[1] == 0x8b
}
