package main

// 配置目录的「可写性探针」。
//
// 管理接口改配置走原子写（写 config.json.tmp 再 rename 覆盖）。目录不可写时
// 增删改路由会全部失败，但失败只在用户真正点下去那一刻才暴露 —— 报的是
// 「创建临时配置文件失败: ... read-only file system」，看起来像接口 bug，
// 实际是部署配置问题。启动时探一次并打日志，能把这两件事区分开。

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigWriteProbeDetectsUnwritableDir(t *testing.T) {
	dir := t.TempDir()

	t.Run("可写目录应通过", func(t *testing.T) {
		a := &App{cfgPath: filepath.Join(dir, "config.json")}
		if err := a.configWriteProbe(); err != nil {
			t.Fatalf("可写目录探针不该报错，实际：%v", err)
		}
	})

	// 探针每次启动都跑，要是把临时文件留在 /etc/goproxy 里没人清，
	// 时间长了就是一堆垃圾 —— 这条专门守住「探完就删」。
	t.Run("不留残留文件", func(t *testing.T) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Errorf("探针留下了残留文件：%v", names)
		}
	})

	// 目录不存在 → 建不出 .tmp，与「目录只读」在效果上等价
	t.Run("目录不存在应报错", func(t *testing.T) {
		a := &App{cfgPath: filepath.Join(dir, "missing-dir", "config.json")}
		if err := a.configWriteProbe(); err == nil {
			t.Error("配置目录不存在时探针应报错，否则等于没探")
		}
	})
}
