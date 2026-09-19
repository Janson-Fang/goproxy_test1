package main

// ============================================================================
// 发布源：GitHub Releases
//
// 这套下载逻辑和 install.sh 是**同一套约定**，刻意保持一致：
//
//资源名        goproxy-linux-<arch>.tar.gz / SHA256SUMS-<arch>.txt
//版本发现      走 /releases/latest 的 302 拿 tag，而不是 GitHub API
//通道          直连优先，不通再逐个试加速镜像（镜像有缓存，刚发的版本可能拉不到）
//完整性        SHA256SUMS 对不上就拒绝安装
//
// 保持一致不是为了好看：运维在命令行里按 install.sh 的提示排障、在界面上点升级，
// 看到的行为必须是同一个，否则「界面装的到底是不是那个包」就没人说得清了。
//
// 也不引第三方依赖（GitHub API 客户端、semver 库之类）：这套东西的判断全在
// 上面这几行约定里，多一层库反而看不清它到底请求了什么、信了什么。
// ============================================================================

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

const (
	upgradeDefaultRepo = "Janson-Fang/goproxy_test1"

	// 与 install.sh 的 MIRROR_LIST 同一份清单（顺序也一样，按实测速度排）。
	upgradeDefaultMirrors = "https://gh-proxy.com/ https://ghfast.top/ https://ghproxy.net/"

	upgradeCheckTimeout = 25 * time.Second

	// resolve / 校验和文件这类小请求的超时。校验和文件只有几十字节，
	// 8 秒拿不到就说明这条通道不行。
	upgradeResolveTimeout = 15 * time.Second
	upgradeSumsTimeout    = 8 * time.Second
	upgradeMaxSumsBytes   = 1 << 20

	// upgradeStallTimeout 是「连续多久没有新字节就放弃这条通道」。
	// 对应 install.sh 里 curl 的 --speed-limit 2048 --speed-time 20。
	upgradeStallTimeout = 20 * time.Second
)

// releaseAsset 是发布产物里的一项（名字、大小、以及 API 给的 sha256 摘要）。
type releaseAsset struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
}

type releaseInfo struct {
	Tag     string
	HTMLURL string
	Notes   string
	Assets  []releaseAsset
}

type releaseSource struct {
	githubBase string
	apiBase    string
	repo       string
	mode       string
	mirrors    []string
	client     *http.Client
}

func newReleaseSource() *releaseSource {
	mirrors := strings.Fields(envOr("GOPROXY_UPGRADE_MIRRORS", upgradeDefaultMirrors))
	for i, m := range mirrors {
		// 统一补成「以 / 结尾」，拼接时就不用到处判断了
		if !strings.HasSuffix(m, "/") {
			mirrors[i] = m + "/"
		}
	}
	repo := strings.Trim(envOr("GOPROXY_UPGRADE_REPO", upgradeDefaultRepo), "/")
	if repo == "" {
		repo = upgradeDefaultRepo
	}
	return &releaseSource{
		githubBase: strings.TrimRight(envOr("GOPROXY_UPGRADE_GITHUB", "https://github.com"), "/"),
		apiBase:    strings.TrimRight(envOr("GOPROXY_UPGRADE_API", "https://api.github.com"), "/"),
		repo:       repo,
		mode:       strings.TrimSpace(envOr("GOPROXY_UPGRADE_MIRROR", "auto")),
		mirrors:    mirrors,
		client:     newUpgradeHTTPClient(),
	}
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// channels 返回按优先级排好的下载通道前缀，空串表示直连。
//
// 直连永远排第一：加速镜像有缓存，刚发布的版本很可能还拉不到，
// 先走镜像会静默装成旧版本（install.sh 里那条警告就是这个坑）。
func (s *releaseSource) channels() []string {
	out := []string{""}
	switch strings.ToLower(s.mode) {
	case "auto":
		out = append(out, s.mirrors...)
	case "", "direct", "none", "off":
	// 只走直连
	default:
		prefix := s.mode
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		out = append(out, prefix)
	}
	return out
}

// orderChannels 把 preferred 排到最前面，其余保持原顺序。
func (s *releaseSource) orderChannels(preferred string) []string {
	out := []string{preferred}
	for _, ch := range s.channels() {
		if ch != preferred {
			out = append(out, ch)
		}
	}
	return out
}

func channelLabel(ch string) string {
	if ch == "" {
		return "direct"
	}
	return ch
}

func channelLabels(chs []string) []string {
	out := make([]string, 0, len(chs))
	for _, ch := range chs {
		out = append(out, channelLabel(ch))
	}
	return out
}

// platformAssetNames 返回当前平台要下载的两个文件名。
//
// 命名与 .github/workflows/ci.yml 里打包的那两行严格对应；macOS 之类
// 没有预编译产物的平台会在这里取到一个不存在的名字，下载时会明确报 404
// 比「悄悄装了个别的架构的包」好得多。
func platformAssetNames() (pkg, sums string) {
	return fmt.Sprintf("goproxy-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH),
		fmt.Sprintf("SHA256SUMS-%s.txt", runtime.GOARCH)
}

func (s *releaseSource) releaseURL(tag string) string {
	return fmt.Sprintf("%s/%s/releases/tag/%s", s.githubBase, s.repo, url.PathEscape(tag))
}

func (s *releaseSource) downloadURL(prefix, tag, name string) string {
	return fmt.Sprintf("%s%s/%s/releases/download/%s/%s",
		prefix, s.githubBase, s.repo, url.PathEscape(tag), url.PathEscape(name))
}

func newUpgradeHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			MaxIdleConns:          4,
		},
		// 刻意不设 Client.Timeout：下载靠请求级 context 控制（直连 35s / 镜像 90s
		// 加龟速放弃），一个全局超时会把「文件大但一直在动」的正常情况也砍掉。
	}
}

func upgradeUserAgent() string {
	return fmt.Sprintf("goproxy/%s (%s/%s) self-upgrade", version, runtime.GOOS, runtime.GOARCH)
}

// ---------------------------------------------------------------------------
// 版本发现
// ---------------------------------------------------------------------------

// latestRelease 返回要安装的版本信息。want 非空时用指定版本，不联网解析。
func (s *releaseSource) latestRelease(ctx context.Context, want string) (releaseInfo, error) {
	if w := strings.TrimSpace(want); w != "" {
		tag := w
		if !strings.HasPrefix(tag, "v") {
			tag = "v" + tag // 宽容一点：填 0.9.2 也认
		}
		return releaseInfo{Tag: tag, HTMLURL: s.releaseURL(tag)}, nil
	}

	tag, _, err := s.resolveLatest(ctx)
	if err != nil {
		return releaseInfo{}, err
	}
	info := releaseInfo{Tag: tag, HTMLURL: s.releaseURL(tag)}
	// release 说明与资产清单只是锦上添花：拿不到也照样能下载（资源名是按约定
	// 拼出来的），所以这里失败不算错误。
	if meta, err := s.latestViaAPI(ctx); err == nil && meta.Tag == tag {
		if meta.HTMLURL != "" {
			info.HTMLURL = meta.HTMLURL
		}
		info.Notes = meta.Notes
		info.Assets = meta.Assets
	}
	return info, nil
}

// resolveLatest 取最新版本的 tag。
//
// 走 /releases/latest 的 302 跳转拿 tag，而不是 GitHub API：这是 install.sh
// 的做法，理由也一样：未认证 API 每小时只有 60 次额度，而且加速镜像普遍转发
// 不了 api.github.com（install.sh 的注释里记着实测结果：ghfast.top 转发 API
// 返回 Invalid input）。API 只作为直连通道的兜底。
func (s *releaseSource) resolveLatest(ctx context.Context) (tag, channel string, err error) {
	var lastErr error
	for _, ch := range s.channels() {
		u := fmt.Sprintf("%s%s/%s/releases/latest", ch, s.githubBase, s.repo)
		reqCtx, cancel := context.WithTimeout(ctx, upgradeResolveTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
		if err != nil {
			cancel()
			return "", "", err
		}
		req.Header.Set("User-Agent", upgradeUserAgent())
		resp, err := s.client.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
		final := ""
		if resp.Request != nil && resp.Request.URL != nil {
			final = resp.Request.URL.Path
		}
		cancel()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		if t := tagFromReleaseURL(final); t != "" {
			return t, ch, nil
		}
		lastErr = fmt.Errorf("响应里没有 /tag/ 路径（%s）", final)
	}
	if info, apiErr := s.latestViaAPI(ctx); apiErr == nil && info.Tag != "" {
		return info.Tag, "", nil
	} else if apiErr != nil {
		lastErr = apiErr
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的下载通道")
	}
	return "", "", lastErr
}

// tagFromReleaseURL 从 /owner/repo/releases/tag/v0.9.1 里取出 v0.9.1。
func tagFromReleaseURL(p string) string {
	i := strings.Index(p, "/tag/")
	if i < 0 {
		return ""
	}
	tag := p[i+len("/tag/"):]
	if unescaped, err := url.PathUnescape(tag); err == nil {
		tag = unescaped
	}
	return strings.Trim(tag, "/")
}

func (s *releaseSource) latestViaAPI(ctx context.Context) (releaseInfo, error) {
	reqCtx, cancel := context.WithTimeout(ctx, upgradeResolveTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, s.apiBase+"/repos/"+s.repo+"/releases/latest", nil)
	if err != nil {
		return releaseInfo{}, err
	}
	req.Header.Set("User-Agent", upgradeUserAgent())
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := s.client.Do(req)
	if err != nil {
		return releaseInfo{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return releaseInfo{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return releaseInfo{}, fmt.Errorf("%s 返回 HTTP %d", s.apiBase, resp.StatusCode)
	}

	var body struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Body    string `json:"body"`
		Assets  []struct {
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return releaseInfo{}, err
	}
	info := releaseInfo{
		Tag:     strings.TrimSpace(body.TagName),
		HTMLURL: strings.TrimSpace(body.HTMLURL),
		Notes:   body.Body,
	}
	for _, a := range body.Assets {
		sum := strings.TrimPrefix(strings.TrimSpace(a.Digest), "sha256:")
		info.Assets = append(info.Assets, releaseAsset{Name: a.Name, Size: a.Size, SHA256: sum})
	}
	return info, nil
}

// ---------------------------------------------------------------------------
// 下载与校验
// ---------------------------------------------------------------------------

// fetchSums 取 SHA256SUMS-<arch>.txt 并解析出 pkg 的 sha256，同时返回
// 「哪个通道成功」 调用方据此把接下来的大体量下载优先排在同一个通道上。
//
// 用这个文件当通道探针是 install.sh 的做法：它只有几十字节，几秒就能判断
// 一条通道到底通不通，不用拿 12MB 的包去试。
func (s *releaseSource) fetchSums(ctx context.Context, tag, pkg, sumsName string) (sum, channel string, err error) {
	var lastErr error
	for _, ch := range s.channels() {
		raw, err := s.getSmall(ctx, s.downloadURL(ch, tag, sumsName), upgradeMaxSumsBytes)
		if err != nil {
			lastErr = err
			continue
		}
		if got := parseSums(raw, pkg); got != "" {
			return got, ch, nil
		}
		// 镜像站经常回一个状态码 200 的 HTML 错误页，所以这里必须校验内容，
		// 不能只看返回码（install.sh 的 dl() 注释里写了同一件事）。
		lastErr = fmt.Errorf("校验和文件里没有 %s 这一行（内容可能不是校验和文件）", pkg)
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的下载通道")
	}
	return "", "", lastErr
}

var sumLineRe = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// parseSums 从 `sha256sum` 风格的文本里取出目标文件的校验和。
func parseSums(raw []byte, pkg string) string {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !sumLineRe.MatchString(fields[0]) {
			continue
		}
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if name == pkg || filepath.Base(name) == pkg {
			return strings.ToLower(fields[0])
		}
	}
	return ""
}

func (s *releaseSource) getSmall(ctx context.Context, u string, limit int64) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, upgradeSumsTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", upgradeUserAgent())
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("响应超过 %d 字节", limit)
	}
	return raw, nil
}

// assetSize 尽力拿到资源大小：先看 API 给的清单（准，且不用额外请求），
// 再退回 HEAD。两个都拿不到就返回 0，界面显示「大小未知」
// 显示一个猜出来的数字比不显示更坏。
func (s *releaseSource) assetSize(ctx context.Context, info releaseInfo, name, channel string) int64 {
	for _, a := range info.Assets {
		if a.Name == name && a.Size > 0 {
			return a.Size
		}
	}
	for _, ch := range s.orderChannels(channel) {
		reqCtx, cancel := context.WithTimeout(ctx, upgradeSumsTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodHead, s.downloadURL(ch, info.Tag, name), nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", upgradeUserAgent())
		resp, err := s.client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		size := resp.ContentLength
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode == http.StatusOK && size > 0 {
			return size
		}
	}
	return 0
}

type fetchResult struct {
	Tag           string
	Channel       string
	SumsVerified  bool
	ArchiveSHA256 string
	ArchiveSize   int64
	BinarySize    int64
}

// fetchRelease 下载并解开指定版本的发布包，把二进制写到 dest。
func (s *releaseSource) fetchRelease(ctx context.Context, info releaseInfo, dest string, maxBinary int64) (*fetchResult, error) {
	pkg, sumsName := platformAssetNames()
	sum, ch, sumsErr := s.fetchSums(ctx, info.Tag, pkg, sumsName)
	res := &fetchResult{Tag: info.Tag, Channel: ch, SumsVerified: sum != ""}
	if sumsErr != nil {
		// 与 install.sh 一致：拿不到校验和文件就退化成「无校验安装」。
		// 但一定要在日志和响应里留痕（SumsVerified=false 会回到界面上），
		// 静默跳过完整性校验才是真正危险的那种做法。
		slog.Warn("升级：拿不到校验和文件，本次安装不做完整性校验", "tag", info.Tag, "err", sumsErr)
	}

	archivePath := dest + ".tar.gz"
	size, sha, usedCh, err := s.downloadAsset(ctx, info.Tag, pkg, archivePath, s.orderChannels(ch))
	if err != nil {
		return nil, err
	}
	res.Channel, res.ArchiveSize, res.ArchiveSHA256 = usedCh, size, sha

	if sum != "" && !strings.EqualFold(sum, sha) {
		_ = os.Remove(archivePath)
		return nil, &apiError{http.StatusBadGateway, "upgrade_sha256_mismatch",
			fmt.Sprintf("发布包的 sha256 与发布方的校验和对不上（下载到 %s，应为 %s）。"+
				"如果正在走加速镜像，多半是它缓存着另一个版本的文件；换直连重试一次。", sha, sum)}
	}
	if err := extractBinaryFromArchive(archivePath, dest, maxBinary); err != nil {
		_ = os.Remove(archivePath)
		return nil, &apiError{http.StatusBadGateway, "upgrade_bad_archive", err.Error()}
	}
	_ = os.Remove(archivePath)
	if fi, err := os.Stat(dest); err == nil {
		res.BinarySize = fi.Size()
	}
	return res, nil
}

// downloadAsset 沿通道依次尝试，返回大小、sha256 和真正成功的通道。
func (s *releaseSource) downloadAsset(ctx context.Context, tag, name, dest string, order []string) (int64, string, string, error) {
	var lastErr error
	for _, ch := range order {
		size, sha, err := s.downloadOne(ctx, ch, tag, name, dest)
		if err == nil {
			return size, sha, ch, nil
		}
		lastErr = err
		slog.Warn("升级：下载失败，换下一个通道", "channel", channelLabel(ch), "asset", name, "err", err)
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的下载通道")
	}
	return 0, "", "", fmt.Errorf("所有通道都下载失败：%w", lastErr)
}

func (s *releaseSource) downloadOne(ctx context.Context, ch, tag, name, dest string) (int64, string, error) {
	// 直连给短超时：几十字节的校验和能秒下，不代表 12MB 的包也下得动，
	// 与其让人干等一分半再回退镜像，不如 35 秒就切过去（install.sh 的经验值）。
	timeout := 35 * time.Second
	if ch != "" {
		timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var seen atomic.Int64
	ctx, cancelStall := watchStall(ctx, &seen, upgradeStallTimeout)
	defer cancelStall()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.downloadURL(ch, tag, name), nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", upgradeUserAgent())
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, "", err
	}
	hasher := sha256.New()
	body := io.LimitReader(&countingReader{r: resp.Body, n: &seen}, upgradeMaxStagedBytes+1)
	written, err := io.Copy(io.MultiWriter(f, hasher), body)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(dest)
		return 0, "", err
	}
	if written > upgradeMaxStagedBytes {
		_ = f.Close()
		_ = os.Remove(dest)
		return 0, "", fmt.Errorf("文件超过上限 %d MiB", upgradeMaxStagedBytes>>20)
	}
	if written == 0 {
		_ = f.Close()
		_ = os.Remove(dest)
		return 0, "", errors.New("下载到 0 字节（多半是镜像返回了空响应）")
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return 0, "", err
	}
	if err := f.Close(); err != nil {
		return 0, "", err
	}
	return written, hex.EncodeToString(hasher.Sum(nil)), nil
}

// watchStall 在「连得上但龟速」的通道上主动放弃。
//
// install.sh 用 curl 的 --speed-limit/--speed-time 做同一件事，理由一样：
// 没有它，碰到一条每秒几十字节的通道只能一直等到 90 秒超时。
// 这里退化成「连续 upgradeStallTimeout 一个字节都没读到就取消」，够用，
// 而且不依赖传输层的任何指标。
func watchStall(ctx context.Context, n *atomic.Int64, stall time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(stall / 4)
		defer t.Stop()
		last := n.Load()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cur := n.Load()
				if cur == last {
					cancel()
					return
				}
				last = cur
			}
		}
	}()
	return ctx, cancel
}

type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

// extractBinaryFromArchive 从发布用的 tar.gz 里取出 goproxy 二进制。
//
// 归档是 `tar -czf ... -C dist .` 打出来的（见 .github/workflows/ci.yml），
// 条目名形如 ./goproxy，所以用 path.Base 比对：tar 里的分隔符永远是 /，
// 用 filepath.Base 在 Windows 上反而会被 \ 的语义带偏。
func extractBinaryFromArchive(archivePath, destPath string, maxBytes int64) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("不是合法的 gzip：%w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("读归档失败：%w", err)
		}
		if h.Typeflag != tar.TypeReg || path.Base(h.Name) != "goproxy" {
			continue
		}
		if h.Size > maxBytes {
			return fmt.Errorf("归档里的 goproxy 有 %d 字节，超过上限 %d", h.Size, maxBytes)
		}
		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}
		n, err := io.Copy(out, io.LimitReader(tr, maxBytes+1))
		if err != nil {
			_ = out.Close()
			_ = os.Remove(destPath)
			return err
		}
		if n > maxBytes {
			_ = out.Close()
			_ = os.Remove(destPath)
			return fmt.Errorf("解包出来的文件超过上限 %d 字节", maxBytes)
		}
		if err := out.Sync(); err != nil {
			_ = out.Close()
			return err
		}
		return out.Close()
	}
	return errors.New("归档里没有 goproxy 二进制")
}
