package main

// 配置持久化层（SQLite）的测试。
//
// 这一层替换掉的是「一份 config.json + 手工拼出来的原子写」。所以这里要验的
// 东西也跟着换了：不再是「有没有生成 .bak」「临时文件有没有 rename 上去」，
// 而是「交给数据库的那几件事真的成立吗」——
//
//   · 写失败时有没有真的全回滚（不能留下半份配置）
//   · 外键有没有真的拦住「删掉还被引用的名单」、有没有真的把改名级联到引用
//   · 每次写入前是不是真的留了一版历史
//   · 写进去的和读出来的是不是同一份（这条直接决定 ETag 稳不稳）
//
// 这些性质都是「换成数据库」这件事的全部理由。它们要是失效了，配置源换得就没有
// 意义 —— 还不如原来那份看得见摸得着的 JSON。

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- 建库 / 版本 ----------

// 全新的库必须是「还没有配置」，而不是「配置是空的」。
//
// 这两者的区别是升级通道的分水岭：前者会去导入同目录的 config.json，
// 后者不会。判错的后果是「老部署升级后配置全丢」。
func TestConfigStoreNewDBIsNoConfig(t *testing.T) {
	path := tempConfigDB(t)

	st, err := openConfigStore(path)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	defer st.Close()

	empty, err := st.isEmpty()
	if err != nil {
		t.Fatalf("isEmpty 失败: %v", err)
	}
	if !empty {
		t.Fatal("新建的库应当是空的")
	}
	if _, _, err := st.read(); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("空库读取应当返回 ErrNoConfig，实际 %v", err)
	}

	// 空库在别的地方可能被当成「读失败」，所以再确认一次它是可重入的：
	// 连续问两次答案必须一样（说明第一次没有顺手把库写成「已初始化」）。
	if empty, err = st.isEmpty(); err != nil || !empty {
		t.Fatalf("再问一次仍应为空，实际 empty=%v err=%v", empty, err)
	}
}

// 库比程序新时必须直接失败。
//
// 让旧二进制打开新库，最坏的结果是「保存一次配置就把新版本加的字段整列抹掉」，
// 而且全程没有任何提示 —— 数据库里也看不出是程序把它删了。宁可起不来。
func TestConfigStoreRejectsNewerSchema(t *testing.T) {
	path := tempConfigDB(t)

	st, err := openConfigStore(path)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	if _, err := st.db.Exec(
		`UPDATE meta SET value = ? WHERE key = 'schema_version'`,
		fmt.Sprint(configSchemaVersion+1)); err != nil {
		t.Fatalf("改版本号失败: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("关库失败: %v", err)
	}

	_, err = openConfigStore(path)
	if err == nil {
		t.Fatal("打开比程序新的库应当失败，实际成功了 —— 新字段会被静默抹掉")
	}
	if !strings.Contains(err.Error(), "库比程序新") {
		t.Fatalf("报错应当说清是「库比程序新」，实际: %v", err)
	}
}

// ---------- 全字段往返 ----------

// fullConfigJSON 是一份「所有能配的都配上」的配置，专门用来验往返。
//
// 不直接写 Config 结构体再序列化，而是手写 JSON：手写的那份是**用户视角**的
// 写法（字符串简写的 IP 规则、省略的字段），能顺带验出「省略的字段会不会
// 在读回来时变成某个非零值」这类只有真读一遍才看得见的问题。
const fullConfigJSON = `{
  "default_ports": [18080, 18081],
  "admin_addr": "127.0.0.1:18082",
  "admin_token": "tok-round-trip",
  "access_log": true,
  "trusted_proxies": ["10.0.0.1", "172.16.0.0/12"],
  "global_ip_deny": ["203.0.113.0/24", {"cidr": "198.51.100.7", "note": "按地址封"}],
  "admin_users": [{"username": "alice", "password": "pw"}],
  "ip_lists": [
    {"name": "办公网", "kind": "allow", "rules": ["10.0.0.0/8", {"cidr": "10.1.2.3", "note": "临时接入"}]},
    {"name": "爬虫", "kind": "deny", "rules": [{"cidr": "203.0.113.66", "note": "扫目录"}]}
  ],
  "tls": {"enabled": false},
  "routes": [
    {
      "id": "web", "name": "主站", "enabled": true, "listen_port": 18083, "host": "example.com",
      "path_prefix": "/app", "target": "http://127.0.0.1:9000",
      "strip_prefix": true, "preserve_host": true, "timeout_ms": 5000,
      "rate_limit": {"rps": 5, "burst": 10, "scope": "ip"},
      "circuit_breaker": {"min_calls": 3, "error_rate": 0.5, "window_secs": 10, "open_secs": 30},
      "auth": {"mode": "basic", "realm": "内部", "basic": [{"username": "u", "password": "p"}]},
      "acl": {"lists": ["办公网", "爬虫"]}
    },
    {
      "id": "off", "enabled": false, "listen_port": 18084,
      "path_prefix": "/", "target": "http://127.0.0.1:9001", "redirect_http": false
    }
  ]
}`

func TestConfigStoreFullRoundTrip(t *testing.T) {
	path := tempConfigDB(t)
	seedRawConfig(t, path, []byte(fullConfigJSON))

	_, cfg, err := readConfigFile(path)
	if err != nil {
		t.Fatalf("读回配置失败: %v", err)
	}

	// ---- 顶层 ----
	if len(cfg.DefaultPorts) != 2 || cfg.DefaultPorts[0] != 18080 || cfg.DefaultPorts[1] != 18081 {
		t.Errorf("default_ports 不对: %v", cfg.DefaultPorts)
	}
	if cfg.AdminAddr != "127.0.0.1:18082" || cfg.AdminToken != "tok-round-trip" || !cfg.AccessLog {
		t.Errorf("顶层标量不对: addr=%q token=%q access_log=%v",
			cfg.AdminAddr, cfg.AdminToken, cfg.AccessLog)
	}
	if len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[1] != "172.16.0.0/12" {
		t.Errorf("trusted_proxies 不对: %v", cfg.TrustedProxies)
	}
	if len(cfg.GlobalIPDeny) != 2 || cfg.GlobalIPDeny[1].Note != "按地址封" {
		t.Errorf("global_ip_deny 不对: %+v", cfg.GlobalIPDeny)
	}
	if len(cfg.AdminUsers) != 1 || cfg.AdminUsers[0].Username != "alice" {
		t.Errorf("admin_users 不对: %+v", cfg.AdminUsers)
	}

	// ---- 名单库：条目顺序与备注都要原样回来 ----
	if len(cfg.IPLists) != 2 {
		t.Fatalf("名单数不对: %+v", cfg.IPLists)
	}
	if cfg.IPLists[0].Name != "办公网" || cfg.IPLists[0].Kind != IPListKindAllow {
		t.Errorf("第一份名单不对: %+v", cfg.IPLists[0])
	}
	if len(cfg.IPLists[0].Rules) != 2 || cfg.IPLists[0].Rules[1].Note != "临时接入" {
		t.Errorf("名单规则（含顺序与备注）没有原样回来: %+v", cfg.IPLists[0].Rules)
	}
	if cfg.IPLists[1].Kind != IPListKindDeny || cfg.IPLists[1].Rules[0].Note != "扫目录" {
		t.Errorf("第二份名单不对: %+v", cfg.IPLists[1])
	}

	// ---- 路由 ----
	if len(cfg.Routes) != 2 {
		t.Fatalf("路由数不对: %+v", cfg.Routes)
	}
	web := cfg.Routes[0]
	if web.ID != "web" || web.Name != "主站" || web.ListenPort != 18083 ||
		web.Host != "example.com" || web.PathPrefix != "/app" ||
		web.Target != "http://127.0.0.1:9000" || !web.StripPrefix || !web.PreserveHost ||
		web.TimeoutMs != 5000 {
		t.Errorf("路由标量字段不对: %+v", web)
	}
	if web.Enabled == nil || !*web.Enabled {
		t.Errorf("显式写的 enabled=true 应当是明确的 true: %+v", web.Enabled)
	}
	if web.RateLimit == nil || web.RateLimit.RPS != 5 || web.RateLimit.Burst != 10 ||
		web.RateLimit.Scope != "ip" {
		t.Errorf("rate_limit 不对: %+v", web.RateLimit)
	}
	if web.CircuitBreaker == nil || web.CircuitBreaker.MinCalls != 3 ||
		web.CircuitBreaker.WindowSecs != 10 || web.CircuitBreaker.OpenSecs != 30 {
		t.Errorf("circuit_breaker 不对: %+v", web.CircuitBreaker)
	}
	if web.Auth == nil || web.Auth.Mode != "basic" || web.Auth.Realm != "内部" ||
		len(web.Auth.Basic) != 1 {
		t.Errorf("auth 不对: %+v", web.Auth)
	}
	if web.ACL == nil || len(web.ACL.Lists) != 2 ||
		web.ACL.Lists[0] != "办公网" || web.ACL.Lists[1] != "爬虫" {
		t.Errorf("acl.lists 引用（含顺序）没有原样回来: %+v", web.ACL)
	}

	// off 这条没写 acl / 限流 / 熔断 / 认证，读回来就必须还是「没配」。
	//
	// 这条断言是**回归测试**：写入侧曾经把 nil 子结构存成字符串 "null"，
	// 而 json 解 "null" 到结构体是不报错也不改值的，于是每条路由都凭空多出
	// 一个零值的熔断器和认证配置 —— 界面上会显示成「已配置但全是 0」，
	// 而且统计接口会把这条没配熔断的路由计成 closed 熔断器。
	off := cfg.Routes[1]
	if off.Enabled == nil || *off.Enabled {
		t.Errorf("enabled=false 没存住: %+v", off.Enabled)
	}
	if off.RedirectHTTP == nil || *off.RedirectHTTP {
		t.Errorf("显式写的 redirect_http=false 没存住: %+v", off.RedirectHTTP)
	}
	if off.RateLimit != nil || off.CircuitBreaker != nil || off.Auth != nil || off.ACL != nil {
		t.Errorf("没配的子结构读回来应当是 nil，而不是零值：rl=%+v cb=%+v auth=%+v acl=%+v",
			off.RateLimit, off.CircuitBreaker, off.Auth, off.ACL)
	}
}

// 同一份配置反复读写，产出的字节必须完全一致。
//
// 这条直接决定 ETag 稳不稳：管理接口的 ETag 是「规范化 JSON 字节的 sha256」，
// 而客户端拿到 ETag 之后会用 If-Match 提交回来。如果「写进去的」和「读出来的」
// 有任何一处不一致（字段顺序变了、空数组被规范化掉了、省略的键被补上了），
// 客户端刚拿到的新 ETag 会在自己下一次提交时立刻撞上 409，而且怎么重试都一样。
//
// 另外这条也顺带锁住「导出成人能读的 JSON」这件事：每次导出都把路由顺序打乱
// 会让人以为配置被改过。
func TestConfigStoreRoundTripIsByteStable(t *testing.T) {
	path := tempConfigDB(t)
	seedRawConfig(t, path, []byte(fullConfigJSON))

	first, _, err := parseConfigFile(path)
	if err != nil {
		t.Fatalf("第一次读失败: %v", err)
	}
	// 把读出来的字节原样再导一遍
	seedRawConfig(t, path, first)
	second, _, err := parseConfigFile(path)
	if err != nil {
		t.Fatalf("第二次读失败: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("同一份配置两次往返的字节不一致：\n第一次:\n%s\n第二次:\n%s", first, second)
	}

	// 第三遍：确认不是「第二次恰好收敛」而是真的幂等
	seedRawConfig(t, path, second)
	third, _, err := parseConfigFile(path)
	if err != nil {
		t.Fatalf("第三次读失败: %v", err)
	}
	if string(second) != string(third) {
		t.Fatalf("往返不幂等：\n第二次:\n%s\n第三次:\n%s", second, third)
	}
}

// 没配的顶层字段不能被固化成默认值。
//
// 这里要防的是一个很具体的场景：admin_addr 留空的意思是「用默认值」，
// 一旦某次保存把它写死成 127.0.0.1:8080，用户就再也没法用留空表达意图了，
// 而且原本关着的管理端口会因此被打开。所以「写入」这条路绝不能补顶层默认值。
func TestConfigStoreDoesNotPersistTopDefaults(t *testing.T) {
	path := tempConfigDB(t)
	// 只写必要的东西，admin_addr / admin_token / access_log 全部省略
	seedRawConfig(t, path, []byte(
		`{"default_ports":[18090],"routes":[{"id":"r","path_prefix":"/","target":"http://127.0.0.1:9000"}]}`))

	raw, _, err := parseConfigFile(path)
	if err != nil {
		t.Fatalf("读回配置失败: %v", err)
	}
	if strings.Contains(string(raw), defaultAdminAddr) {
		t.Fatalf("留空的 admin_addr 被固化成默认值了:\n%s", raw)
	}
	var back Config
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("读回的配置不是合法 JSON: %v", err)
	}
	if back.AdminAddr != "" {
		t.Fatalf("admin_addr 应保持「未指定」，实际 %q", back.AdminAddr)
	}
	// 对照：路由级的兜底值是**期望**落库的（界面按 ID 增删改要靠它稳定）
	if back.Routes[0].PathPrefix != "/" {
		t.Fatalf("路由级默认值应当落库，实际 path_prefix=%q", back.Routes[0].PathPrefix)
	}
}

// ---------- 外键 ----------

// route_acl_lists 上的两个外键，是本次「换成关系表」最实在的收益：
// 两件以前靠代码保证的事（删不掉被引用的名单、改名要同步改引用）交给了数据库。
//
// 这里直接对着数据库做单条 SQL，而不是走管理接口 —— 管理接口有自己的前置检查
// （guardListInUse），会把这两条路先挡下来，于是外键到底有没有生效就验不出来了。
// 外键的价值恰恰是「前置检查漏了、或者有人直接动库」时兜住。
func TestRouteACLListForeignKeys(t *testing.T) {
	path := tempConfigDB(t)
	seedRawConfig(t, path, []byte(`{
	  "default_ports": [18095],
	  "admin_addr": "127.0.0.1:18096",
	  "ip_lists": [{"name": "办公网", "kind": "allow", "rules": ["10.0.0.0/8"]}],
	  "routes": [{"id": "r", "path_prefix": "/", "target": "http://127.0.0.1:9000",
	              "acl": {"lists": ["办公网"]}}]
	}`))

	st, err := storeFor(path)
	if err != nil {
		t.Fatalf("打开配置库失败: %v", err)
	}
	t.Cleanup(func() { _ = closeStore(path) })

	// 1) 还被引用的名单删不掉（ON DELETE RESTRICT）。
	//    对应原来的 listUsage 扫描 + 409：以前是「每次现算引用」，现在由约束保证。
	err = st.withTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM ip_lists WHERE name = '办公网'`)
		return err
	})
	if err == nil {
		t.Fatal("还被路由引用的名单应当删不掉（ON DELETE RESTRICT 没生效）")
	}
	if !strings.Contains(strings.ToUpper(err.Error()), "FOREIGN KEY") {
		t.Fatalf("删除失败的原因应当是外键约束，实际: %v", err)
	}

	// 2) 改名会把引用一起改掉（ON UPDATE CASCADE）。
	//    对应原来的 renameListRefs：以前靠调用方声明「我改了什么名」，
	//    现在库里自己就把引用改完了，不存在「改了名但引用悬空」的中间态。
	if err := st.withTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE ip_lists SET name = '新名字' WHERE name = '办公网'`)
		return err
	}); err != nil {
		t.Fatalf("改名失败: %v", err)
	}
	_, cfg, err := readConfigFile(path)
	if err != nil {
		t.Fatalf("改名后读配置失败: %v", err)
	}
	if len(cfg.IPLists) != 1 || cfg.IPLists[0].Name != "新名字" {
		t.Fatalf("名单名没改成: %+v", cfg.IPLists)
	}
	if cfg.IPLists[0].Rules[0].CIDR != "10.0.0.0/8" {
		t.Errorf("改名没级联到规则表: %+v", cfg.IPLists[0].Rules)
	}
	if cfg.Routes[0].ACL == nil || len(cfg.Routes[0].ACL.Lists) != 1 ||
		cfg.Routes[0].ACL.Lists[0] != "新名字" {
		t.Fatalf("改名没级联到路由引用（引用悬空了）: %+v", cfg.Routes[0].ACL)
	}

	// 3) 反过来：没有任何引用的名单可以正常删掉。
	//    外键不能把「删除」这件正常操作也一起挡住。
	if err := st.withTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM route_acl_lists`)
		return err
	}); err != nil {
		t.Fatalf("解除引用失败: %v", err)
	}
	if err := st.withTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM ip_lists WHERE name = '新名字'`)
		return err
	}); err != nil {
		t.Fatalf("解除引用后应当能删掉名单，实际: %v", err)
	}
}

// 写配置失败时必须整笔回滚，不能留下半份。
//
// 全量替换的写法是「先删光所有表再插」，如果中间某一步失败而没有事务包着，
// 库就停在「删干净了、新内容没进去」的状态 —— 一次失败就把配置清空了。
// 这正是当初那份 JSON 实现要手工拼「tmp + rename」才换来的东西。
func TestConfigStoreWriteFailureRollsBackWholeConfig(t *testing.T) {
	path := tempConfigDB(t)
	seedRawConfig(t, path, []byte(`{
	  "default_ports": [18097],
	  "admin_addr": "127.0.0.1:18098",
	  "ip_lists": [{"name": "办公网", "kind": "allow", "rules": ["10.0.0.0/8"]}],
	  "routes": [{"id": "r", "path_prefix": "/", "target": "http://127.0.0.1:9000"}]
	}`))

	before, _, err := parseConfigFile(path)
	if err != nil {
		t.Fatalf("读取初始配置失败: %v", err)
	}

	st, err := storeFor(path)
	if err != nil {
		t.Fatalf("打开配置库失败: %v", err)
	}
	t.Cleanup(func() { _ = closeStore(path) })

	// 故意在事务中间失败：清空表已经执行过了，后面的写入抛错。
	want := errors.New("模拟写入中途失败")
	err = st.withTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM routes`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM ip_lists`); err != nil {
			return err
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("事务应当把内部错误原样返回，实际: %v", err)
	}

	after, _, err := parseConfigFile(path)
	if err != nil {
		t.Fatalf("回滚后读配置失败: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("写入失败后配置被改动了：\n之前:\n%s\n之后:\n%s", before, after)
	}
}

// ---------- 历史 ----------

// 每次写入前留一版历史，这是「改错了还能回去」的唯一退路。
// 它替代了原来那份 config.json.bak —— 只留一版的话，改错两次就回不去了。
//
// 顺带覆盖一条容易漏的性质：**同一份内容重复保存不会反复堆历史**。
// 这条一开始是错的，根因还挺隐蔽：往内存里的配置追加一条新路由时，这条路由
// 还没有补齐 tls_mode / redirect_http 这些路由级默认值，于是「第一次保存」
// 存下的是半成品，而「第二次保存」会把补好的版本存进去 —— 两次内容并不相同。
// 修法是把补默认值这件事下移到存储层（见 configstore.go 的 write）。
func TestConfigStoreArchivesPreviousRevision(t *testing.T) {
	path := tempConfigDB(t)
	seedRawConfig(t, path, []byte(`{"default_ports":[18099],"admin_addr":"127.0.0.1:18100","routes":[]}`))

	st, err := storeFor(path)
	if err != nil {
		t.Fatalf("打开配置库失败: %v", err)
	}
	t.Cleanup(func() { _ = closeStore(path) })

	// 空库导入时没有「上一版」可存
	if n, err := st.historyCount(); err != nil {
		t.Fatalf("读历史条数失败: %v", err)
	} else if n != 0 {
		t.Fatalf("往空库里导入不该产生历史，实际 %d 条", n)
	}

	// 每次保存都把「保存前的那一份」存进去
	for i, id := range []string{"a", "b", "c"} {
		cfg, err := loadConfig(path)
		if err != nil {
			t.Fatalf("加载配置失败: %v", err)
		}
		cfg.Routes = append(cfg.Routes, RouteConfig{
			ID: id, PathPrefix: "/", Target: "http://127.0.0.1:9000"})
		if _, _, err := saveConfig(path, cfg); err != nil {
			t.Fatalf("第 %d 次保存失败: %v", i+1, err)
		}
	}
	n, err := st.historyCount()
	if err != nil {
		t.Fatalf("读历史条数失败: %v", err)
	}
	if n != 3 {
		t.Fatalf("三次保存应当留下三版历史，实际 %d 条", n)
	}

	// 内容没变再存一次，不该多出一条。
	// 一条与「现在」完全相同的记录只会在回滚清单里添噪音，而窗口只有
	// historyKeep 条 —— 让它去挤掉真正有用的版本就更亏了。
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	if _, _, err := saveConfig(path, cfg); err != nil {
		t.Fatalf("重复保存失败: %v", err)
	}
	if n2, err := st.historyCount(); err != nil {
		t.Fatalf("读历史条数失败: %v", err)
	} else if n2 != n {
		t.Fatalf("内容没变不应多出历史，实际从 %d 变成 %d", n, n2)
	}
}

// 历史只保留最近若干版，不能无限增长。
//
// 这一条不只是「省空间」：历史表里存的是整份配置的原始字节，而配置里带着
// admin_token 和密码哈希。无上限地留着，等于把一批早已轮换掉的凭据
// 永久留在磁盘上。
func TestConfigStoreHistoryIsCapped(t *testing.T) {
	path := tempConfigDB(t)
	seedRawConfig(t, path, []byte(`{"default_ports":[18101],"admin_addr":"127.0.0.1:18102","routes":[]}`))

	st, err := storeFor(path)
	if err != nil {
		t.Fatalf("打开配置库失败: %v", err)
	}
	t.Cleanup(func() { _ = closeStore(path) })

	// 造出 historyKeep + 5 个互不相同的版本
	for i := 0; i < historyKeep+5; i++ {
		cfg, err := loadConfig(path)
		if err != nil {
			t.Fatalf("加载配置失败: %v", err)
		}
		cfg.Routes = append(cfg.Routes, RouteConfig{
			ID: fmt.Sprintf("r%d", i), PathPrefix: "/", Target: "http://127.0.0.1:9000"})
		if _, _, err := saveConfig(path, cfg); err != nil {
			t.Fatalf("第 %d 次保存失败: %v", i+1, err)
		}
	}
	n, err := st.historyCount()
	if err != nil {
		t.Fatalf("读历史条数失败: %v", err)
	}
	if n > historyKeep {
		t.Fatalf("历史应当只留最近 %d 版，实际 %d 版", historyKeep, n)
	}
	if n < historyKeep {
		t.Fatalf("历史被削得比上限还少（草稿杀过头了）：%d < %d", n, historyKeep)
	}
}

// ---------- 导入 / 导出 ----------

// 导出的 JSON 必须能原样导回来，并且导入走的是**完整校验**这条真实路径。
//
// 这条是「命令行救急」的可行性保证：控制台被自己封在门外时，唯一的退路就是
// 导出 → 改 → 导入。它要是错了，那条退路就是纸面上的。
func TestConfigStoreExportImportRoundTrip(t *testing.T) {
	src := tempConfigDB(t)
	seedRawConfig(t, src, []byte(fullConfigJSON))

	st, err := storeFor(src)
	if err != nil {
		t.Fatalf("打开源库失败: %v", err)
	}
	exported, err := st.exportJSON()
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	_ = closeStore(src)

	dst := tempConfigDB(t)
	seedRawConfig(t, dst, exported)

	got, _, err := parseConfigFile(dst)
	if err != nil {
		t.Fatalf("导入后读取失败: %v", err)
	}
	if string(got) != string(exported) {
		t.Fatalf("导出再导入应当逐字节一致：\n导出:\n%s\n导入后:\n%s", exported, got)
	}
}

// 导入是非法的配置时，库里原有的配置必须一点不动。
//
// 命令行导入没有「回滚」这一步，用户按的是同一条命令；如果导入失败还把库
// 改了一半，那用户手上就没有任何一份正确配置了。
func TestConfigStoreImportRejectsInvalidWithoutTouchingDB(t *testing.T) {
	path := tempConfigDB(t)
	seedRawConfig(t, path, []byte(fullConfigJSON))

	before, _, err := parseConfigFile(path)
	if err != nil {
		t.Fatalf("读取初始配置失败: %v", err)
	}

	st, err := storeFor(path)
	if err != nil {
		t.Fatalf("打开配置库失败: %v", err)
	}
	t.Cleanup(func() { _ = closeStore(path) })

	bad := [][]byte{
		// 引用了不存在的名单 —— 悬空引用是硬错误，必须拦住
		[]byte(`{"routes":[{"id":"r","path_prefix":"/","target":"http://127.0.0.1:9000",
		        "acl":{"lists":["不存在的名单"]}}]}`),
		// v0.7.x 的内联写法，必须带迁移映射报错，而不是静默忽略
		[]byte(`{"routes":[{"id":"r","path_prefix":"/","target":"http://127.0.0.1:9000",
		        "acl":{"allow":["10.0.0.0/8"]}}]}`),
		// 白名单不许是空的（引用它的路由会拒绝所有请求）
		[]byte(`{"ip_lists":[{"name":"空名单","kind":"allow","rules":[]}]}`),
	}
	for i, raw := range bad {
		if _, err := st.importJSON(raw); err == nil {
			t.Errorf("第 %d 份非法配置应当被拒绝", i+1)
		}
	}

	after, _, err := parseConfigFile(path)
	if err != nil {
		t.Fatalf("回滚后读配置失败: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("导入失败后库里的配置被改动了：\n之前:\n%s\n之后:\n%s", before, after)
	}
}

// ---------- 老部署升级通道 ----------

// 库是空的、旁边躺着一份 config.json → 启动时导入一次。
//
// 这是「已经跑着 config.json 的老部署」唯一的迁移通道。注意它**只导一次**：
// 之后 config.json 就不再被读取了。每次都导的话，用户哪天把配置清空
// （删光所有路由）重启后，旧文件里的内容会突然复活 —— 那比不导入更难排查。
func TestPrepareConfigStoreImportsLegacyJSONOnce(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "goproxy.db")

	seedLegacyConfigFile(t, dir, []byte(
		`{"default_ports":[18110],"admin_addr":"127.0.0.1:18111",`+
			`"routes":[{"id":"from-file","path_prefix":"/","target":"http://127.0.0.1:9000"}]}`))

	if err := prepareConfigStore(db); err != nil {
		t.Fatalf("首次启动应当导入同目录的 config.json: %v", err)
	}
	t.Cleanup(func() { _ = closeStore(db) })

	_, cfg, err := readConfigFile(db)
	if err != nil {
		t.Fatalf("读回配置失败: %v", err)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].ID != "from-file" {
		t.Fatalf("config.json 没有被导入: %+v", cfg.Routes)
	}

	// 把源文件改掉（模拟「用户后来手工编辑过那份文件」），再启动一次。
	// 库已经不为空，所以这次不该再被读进来。
	seedLegacyConfigFile(t, dir, []byte(
		`{"default_ports":[18110],"admin_addr":"127.0.0.1:18111",`+
			`"routes":[{"id":"改了也不该生效","path_prefix":"/","target":"http://127.0.0.1:9000"}]}`))

	if err := prepareConfigStore(db); err != nil {
		t.Fatalf("第二次启动失败: %v", err)
	}
	_, cfg, err = readConfigFile(db)
	if err != nil {
		t.Fatalf("读回配置失败: %v", err)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].ID != "from-file" {
		t.Fatalf("config.json 只应导入一次，后来又生效了: %+v", cfg.Routes)
	}
}

// -c 还指在旧的那份 config.json 上，必须明确报错。
//
// 不拦的话会安静地在旁边建一个新库，而用户的配置还留在原文件里没人读 ——
// 现象是「升级完配置全没了」，但文件明明还在，非常难查。
func TestPrepareConfigStoreRejectsLegacyConfigPath(t *testing.T) {
	dir := t.TempDir()
	legacy := seedLegacyConfigFile(t, dir, []byte(`{"routes":[]}`))

	err := prepareConfigStore(legacy)
	if err == nil {
		t.Fatal("-c 指向旧版 config.json 时应当直接报错，实际成功了")
	}
	if !strings.Contains(err.Error(), "不是 SQLite 数据库") {
		t.Errorf("报错应当说清「这不再是配置文件」: %v", err)
	}
	// 报错必须给出退路，否则用户只知道「不让我启动」
	if !strings.Contains(err.Error(), "-config-import") {
		t.Errorf("报错里应当给出导入命令: %v", err)
	}
	// 而且不能顺手在旁边建出一个新库来
	if _, statErr := os.Stat(filepath.Join(dir, "goproxy.db")); statErr == nil {
		t.Error("被拒绝时不该创建任何数据库文件")
	}
}

// 已经存在的合法数据库不会被旁边那份 config.json 覆盖。
//
// 这条与 TestPrepareConfigStoreImportsLegacyJSONOnce 是一对：那条保证「空的要导」，
// 这条保证「非空的不导」。少了后者，老文件会永远压在真实配置上面。
func TestPrepareConfigStoreKeepsExistingDBNotLegacyFile(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "goproxy.db")

	seedRawConfig(t, db, []byte(
		`{"default_ports":[18112],"admin_addr":"127.0.0.1:18113",`+
			`"routes":[{"id":"in-db","path_prefix":"/","target":"http://127.0.0.1:9000"}]}`))
	seedLegacyConfigFile(t, dir, []byte(
		`{"default_ports":[18112],"admin_addr":"127.0.0.1:18113",`+
			`"routes":[{"id":"in-file","path_prefix":"/","target":"http://127.0.0.1:9000"}]}`))

	if err := prepareConfigStore(db); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	t.Cleanup(func() { _ = closeStore(db) })

	_, cfg, err := readConfigFile(db)
	if err != nil {
		t.Fatalf("读回配置失败: %v", err)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].ID != "in-db" {
		t.Fatalf("库非空时不应再用 config.json 覆盖: %+v", cfg.Routes)
	}
}
