package main

// 测试里造配置的统一入口。
//
// v0.9.0 之前，测试造配置就是「把 JSON 写到临时文件，再 loadConfig 它」。
// 换成 SQLite 之后多了一步「建库 + 导入」，而这个动作在四个测试文件里都要用，
// 所以集中在这里 —— 分散实现的话，将来 schema 一变就得满仓库找。
//
// 顺带一个容易踩的坑：连接池持有数据库文件句柄，不关就删不掉临时目录。
// Windows 上会报「另一个程序正在使用此文件」，从报错看不出跟数据库有关。
// 所以下面每个 helper 都注册了 t.Cleanup 关连接。
//
// 注册顺序也是对的：helper 都在被测对象之前调用，而 t.Cleanup 是后注册先执行，
// 于是关连接发生在「停监听器」之后 —— 顺序反了的话，还没停的服务会拿着
// 一个已经关掉的库继续收尾，报出来的错跟真实原因毫无关系。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// tempConfigDB 返回一个临时配置库路径（此时还没有这个文件）。
func tempConfigDB(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "goproxy.db")
}

// seedRawConfig 把一份 JSON 配置导入 dbPath 指向的配置库（库不存在则创建）。
//
// 走 importJSON 而不是「直接写表」：这样测试造出来的配置与真实导入路径完全一致
// （默认值补齐、旧写法拦截、校验都在里面），不会出现「测试里能过、真机上导不进去」。
func seedRawConfig(t *testing.T, dbPath string, raw []byte) {
	t.Helper()
	st, err := storeFor(dbPath)
	if err != nil {
		t.Fatalf("打开配置库 %s 失败: %v", dbPath, err)
	}
	// 先注册清理再导入：导入失败时 t.Fatalf 会把后面这些注册全跳过，
	// 于是连接留着不放，TempDir 清理时报「文件正被另一个程序使用」——
	// 一个把人往「文件权限」方向带的假线索。
	t.Cleanup(func() { _ = closeStore(dbPath) })
	if _, err := st.importJSON(raw); err != nil {
		t.Fatalf("导入配置失败: %v", err)
	}
}

// seedConfig 是 seedRawConfig 的结构体版本。
func seedConfig(t *testing.T, dbPath string, cfg *Config) {
	t.Helper()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("序列化配置失败: %v", err)
	}
	seedRawConfig(t, dbPath, b)
}

// seedLegacyConfigFile 为「老部署升级」场景造一个 config.json：
// 它**不是**数据库，而是一份 JSON 文件，用来验证启动时的一次性导入。
func seedLegacyConfigFile(t *testing.T, dir string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("写 config.json 失败: %v", err)
	}
	return path
}
