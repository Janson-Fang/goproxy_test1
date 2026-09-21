package main

// 发布包（tar.gz）解包。
//
// 上传接口接收的文件可能是原始二进制，也可能是发布用的 tar.gz（按魔数识别），
// 所以在 upload 这条路径上需要一个解包器 —— 它就是本文件唯一的内容。
//
// 归档是 `tar -czf ... -C dist .` 打出来的（见 .github/workflows/ci.yml）。

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
)

// extractBinaryFromArchive 从发布用的 tar.gz 里取出 goproxy 二进制。
//
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
