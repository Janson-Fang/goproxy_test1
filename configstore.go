package main

// 配置的持久化层：SQLite。
//
// 为什么要有这个文件：v0.8.0 之前配置就是一份 config.json，读它、改它、
// 靠轮询 mtime 热重载。那份实现的每一处都依赖「配置是一个可以被别人随手
// 编辑的文本文件」—— 而实际上唯一会改它的只有本进程的管理接口。
// 于是它同时承受了三种代价：
//
//	· 写盘不是事务 —— 「先备份、再写临时文件、再 rename」是靠代码手工拼出来的
//	  原子性，多一个需要同步修改的表就得多写一遍这套流程；
//	· 引用完整性靠内存里扫一遍 —— 「这份名单还被哪几条路由引用着」是每次
//	  现算的（listUsage），删不删得掉取决于那次扫描写得对不对；
//	· 改名要靠调用方声明 —— 控制台提交 ip_list_renames，服务端再逐条改写引用，
//	  因为没人能保证「改了名」和「改了引用」之间不出岔子。
//
// 换到 SQLite 之后这三件事都交给数据库：写入在一个事务里、引用交给外键
// （route_acl_lists.list_name 上的 ON DELETE RESTRICT 就是「还被引用的名单
// 删不掉」）、改名交给 ON UPDATE CASCADE。
//
// 对外一个字节都没变：Config 结构、HTTP 接口的 JSON 形状、ETag / If-Match
// 语义全部保持原样，前端不需要知道底下换了存储。
//
// 表结构刻意**没有**把 RouteConfig 拆到底（rate_limit / circuit_breaker /
// auth 三段仍然是一列 JSON）。理由是那三段是「要么整块配、要么整块不配」的
// 叶子配置，从来不会被单独查询或按字段过滤，拆成列只会让每加一个字段都要
// 写一次迁移。真正需要关系的是「谁引用了谁」—— 那部分一张表都不省。

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // 纯 Go 实现：CI 用 CGO_ENABLED=0 交叉编译，不能要 cgo
)

// configSchemaVersion 是当前 schema 版本。改表结构时 +1，并在 migrate 里补一段升级。
//
// 存这个值是为了让「用新二进制打开了旧库」这件事有一个明确的报错位置，
// 而不是等到某条 SELECT 报 no such column 才被发现。
const configSchemaVersion = 1

// historyKeep 是配置历史保留的条数。它替代了原来那份 config.json.bak ——
// 只留一版备份的话，「改错了两次」就回不去了。
const historyKeep = 20

// configSchema 是建表语句。全部 IF NOT EXISTS，可重复执行。
const configSchema = `
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- 顶层标量设置。严格单行：id 上有 CHECK (id = 1)，
-- 少写一个 WHERE 也不会把配置写成两行。
CREATE TABLE IF NOT EXISTS settings (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  admin_addr  TEXT    NOT NULL DEFAULT '',
  admin_token TEXT    NOT NULL DEFAULT '',
  access_log  INTEGER NOT NULL DEFAULT 0
);

-- 下面三张是「有序多值」的顶层列表。seq 保留配置里的书写顺序：
-- 顺序对行为没有影响，但对人读 config 有影响，导出时不该被打乱。
CREATE TABLE IF NOT EXISTS default_ports (
  seq  INTEGER PRIMARY KEY,
  port INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS trusted_proxies (
  seq   INTEGER PRIMARY KEY,
  value TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS global_ip_deny (
  seq  INTEGER PRIMARY KEY,
  cidr TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS admin_users (
  seq           INTEGER PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password      TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ip_lists (
  name TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('allow','deny')),
  seq  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_list_rules (
  list_name TEXT    NOT NULL REFERENCES ip_lists(name) ON DELETE CASCADE ON UPDATE CASCADE,
  seq       INTEGER NOT NULL,
  cidr      TEXT    NOT NULL,
  note      TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (list_name, seq)
);

-- 路由。标量字段成列；三段叶子配置（限流 / 熔断 / 认证）整体存 JSON。
CREATE TABLE IF NOT EXISTS routes (
  id              TEXT PRIMARY KEY,
  seq             INTEGER NOT NULL,
  name            TEXT    NOT NULL DEFAULT '',
  enabled         INTEGER,          -- NULL = 没写，按默认 true 处理
  listen_port     INTEGER NOT NULL DEFAULT 0,
  host            TEXT    NOT NULL DEFAULT '',
  path_prefix     TEXT    NOT NULL DEFAULT '',
  target          TEXT    NOT NULL DEFAULT '',
  strip_prefix    INTEGER NOT NULL DEFAULT 0,
  preserve_host   INTEGER NOT NULL DEFAULT 0,
  tls_mode        TEXT    NOT NULL DEFAULT '',
  cert_file       TEXT    NOT NULL DEFAULT '',
  key_file        TEXT    NOT NULL DEFAULT '',
  redirect_http   INTEGER,          -- NULL = 没写，按默认 true 处理
  timeout_ms      INTEGER NOT NULL DEFAULT 0,
  rate_limit      TEXT,
  circuit_breaker TEXT,
  auth            TEXT
);

-- 路由对命名地址列表的引用。
--
-- 这张表是本次改造最实在的一处：两个外键把两件以前靠代码保证的事情
-- 交给了数据库。
--   ON DELETE RESTRICT —— 还被引用的名单删不掉（对应原来的 listUsage 扫描 + 409）
--   ON UPDATE CASCADE  —— 改名自动改写所有引用（对应原来的 renameListRefs）
-- 两者都是「忘了写就出错」的逻辑，放在约束里就不会忘。
CREATE TABLE IF NOT EXISTS route_acl_lists (
  route_id  TEXT    NOT NULL REFERENCES routes(id)     ON DELETE CASCADE  ON UPDATE CASCADE,
  seq       INTEGER NOT NULL,
  list_name TEXT    NOT NULL REFERENCES ip_lists(name) ON DELETE RESTRICT ON UPDATE CASCADE,
  PRIMARY KEY (route_id, seq)
);

CREATE TABLE IF NOT EXISTS tls_settings (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),
  enabled            INTEGER NOT NULL DEFAULT 0,
  cert_dir           TEXT    NOT NULL DEFAULT '',
  http_port          INTEGER NOT NULL DEFAULT 0,
  https_port         INTEGER NOT NULL DEFAULT 0,
  acme_email         TEXT    NOT NULL DEFAULT '',
  acme_directory_url TEXT    NOT NULL DEFAULT '',
  acme_staging       INTEGER NOT NULL DEFAULT 0,
  acme_cache_dir     TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS acme_hosts (
  seq  INTEGER PRIMARY KEY,
  host TEXT NOT NULL
);

-- 每次写入前把上一版存一份。revision 直接当主键去重：
-- 同一份配置被连续保存两次（内容没变）不会占两条。
CREATE TABLE IF NOT EXISTS config_history (
  revision   TEXT PRIMARY KEY,
  raw        BLOB NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_route_acl_list_name ON route_acl_lists(list_name);
CREATE INDEX IF NOT EXISTS idx_ip_list_rules_list  ON ip_list_rules(list_name);

-- 下面三张表是**运行态**，不属于 Config，因此刻意不写进 writeConfigTx 的
-- 清空清单：改配置（含 -config-import 覆盖）不该顺手抹掉封禁和蜜罐设置。
--
-- 也刻意**不 bump configSchemaVersion**。migrate() 在版本不一致时是硬失败
-- （"库比程序新，请升级"），bump 上去会让「升级后回滚到旧二进制」直接起不来。
-- 而这几张表是纯增量的：旧二进制既不读它们、也不删它们（它的清空清单里没有），
-- 所以新旧二进制都能正常跑同一个库。只有**给已有表加列**才必须先 bump。

-- 蜜罐端口：这些端口上不该有任何真实服务，任何访问都视为扫描。
CREATE TABLE IF NOT EXISTS honeypot_ports (
  seq   INTEGER PRIMARY KEY,
  port  INTEGER NOT NULL,
  proto TEXT    NOT NULL CHECK (proto IN ('tcp','udp')),
  note  TEXT    NOT NULL DEFAULT ''
);

-- 蜜罐的开关与处置策略。严格单行，同 settings / tls_settings。
CREATE TABLE IF NOT EXISTS honeypot_settings (
  id       INTEGER PRIMARY KEY CHECK (id = 1),
  enabled  INTEGER NOT NULL DEFAULT 0,
  -- observe = 只记录不封禁；enforce = 命中即封禁。
  -- 默认 observe：这个功能的判定依据很硬（没人该访问那些端口），但
  -- 「哪些端口算没人访问」是你说了算的，先用真实流量看一轮再开更稳。
  mode     TEXT    NOT NULL DEFAULT 'observe',
  -- 第 1 级封禁时长（秒），阶梯按 banLadderRatios 放大。
  ban_secs INTEGER NOT NULL DEFAULT 3600,
  -- JSON 数组：额外豁免的 CIDR（内网与可信代理已经在代码里硬豁免了）。
  exempt   TEXT    NOT NULL DEFAULT '[]'
);

-- 自动封禁条目。运行态，不进 Config、不进 revision、不进 config_history、
-- 不出现在 -config-export。唯一目的是重启后封禁还在 ——
-- 否则「打崩进程」就等于免费解封，而那是攻击者能做到的事。
CREATE TABLE IF NOT EXISTS ban_entries (
  ip         TEXT PRIMARY KEY,
  reason     TEXT    NOT NULL DEFAULT '',
  source     TEXT    NOT NULL DEFAULT '',
  level      INTEGER NOT NULL DEFAULT 1,
  hits       INTEGER NOT NULL DEFAULT 0,
  created_at TEXT    NOT NULL DEFAULT '',
  expires_at TEXT    NOT NULL DEFAULT '',
  last_at    TEXT    NOT NULL DEFAULT '',
  samples    TEXT    NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_ban_last_at ON ban_entries(last_at);
`

// configStore 是配置的持久化层。
//
// 连接数固定为 1：SQLite 是单写者，而配置的写入频率是「人手点一次保存」级别，
// 完全没有并发的必要。把连接数压到 1 换来的是一整类并发问题消失 ——
// 不会有 SQLITE_BUSY，也不会有「两个连接各拿一个快照、互相覆盖」。
// 代价是事务里绝对不能再走 s.db（那条路会等这把唯一的连接，直接死锁），
// 必须一律用传进来的 tx —— 下面所有 *Tx 函数都是为这个约束存在的。
type configStore struct {
	db   *sql.DB
	path string
}

// openConfigStore 打开（必要时创建）配置数据库。
//
// foreign_keys 和 busy_timeout 走 DSN 而不是开库后 PRAGMA：这两个都是
// **连接级**设置，用 db.Exec 设只对当次那条连接生效，换一条连接就恢复了默认。
// 用 Exec 设置它们是最典型的「看起来生效了、其实只生效一次」。
func openConfigStore(path string) (*configStore, error) {
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=foreign_keys(1)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开配置数据库失败: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("连接配置数据库失败: %w", err)
	}

	s := &configStore{db: db, path: path}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *configStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// migrate 建表并把 schema 版本对齐。
func (s *configStore) migrate() error {
	if _, err := s.db.Exec(configSchema); err != nil {
		return fmt.Errorf("建立配置表失败: %w", err)
	}

	row := s.db.QueryRow(`SELECT value FROM meta WHERE key = 'schema_version'`)
	var cur string
	switch err := row.Scan(&cur); {
	case errors.Is(err, sql.ErrNoRows):
		// 全新的库
		_, err := s.db.Exec(
			`INSERT INTO meta (key, value) VALUES ('schema_version', ?)`,
			fmt.Sprint(configSchemaVersion))
		if err != nil {
			return fmt.Errorf("写入 schema 版本失败: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("读取 schema 版本失败: %w", err)
	}

	if cur == fmt.Sprint(configSchemaVersion) {
		return nil
	}

	// 目前只有 v1，所以走到这里只可能是「库比二进制新」。
	// 让它明确失败，而不是带着一张看不懂的表继续跑：
	// 用旧二进制打开新库，最坏的结果是保存时把新字段整列抹掉。
	return fmt.Errorf(
		"配置数据库的 schema 版本是 %s，本二进制支持的是 %d：库比程序新，请升级 goproxy 后再启动",
		cur, configSchemaVersion)
}

// withTx 跑一个事务。所有数据库操作都经过它，保证「要么全成、要么全不成」。
func (s *configStore) withTx(fn func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}
	return nil
}

// ---------- 映射：Config → 表 ----------

// writeTx 把整份配置写进表里（全量替换）。
//
// 为什么是「删光再插」而不是逐条 upsert：配置只有几十条，全量替换的开销可以
// 忽略，但它把「顺序」「删除」「新增」三件事一次性处理掉了 —— 逐条 upsert
// 还要额外维护「哪些没出现在新配置里 = 该删」，那才是容易漏的地方。
//
// 全部在一个事务里，所以外部看到的要么是旧配置、要么是新配置。
func writeConfigTx(tx *sql.Tx, cfg *Config) error {
	for _, t := range []string{
		"route_acl_lists", "routes", // 先删引用再删路由（外键方向）
		"ip_list_rules", "ip_lists", // 同上
		"acme_hosts", "tls_settings",
		"admin_users", "default_ports", "trusted_proxies", "global_ip_deny",
		"settings",
	} {
		if _, err := tx.Exec("DELETE FROM " + t); err != nil {
			return fmt.Errorf("清空表 %s 失败: %w", t, err)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO settings (id, admin_addr, admin_token, access_log) VALUES (1, ?, ?, ?)`,
		cfg.AdminAddr, cfg.AdminToken, boolToInt(cfg.AccessLog)); err != nil {
		return fmt.Errorf("写入顶层设置失败: %w", err)
	}

	for i, p := range cfg.DefaultPorts {
		if _, err := tx.Exec(`INSERT INTO default_ports (seq, port) VALUES (?, ?)`, i, p); err != nil {
			return fmt.Errorf("写入 default_ports 失败: %w", err)
		}
	}
	for i, v := range cfg.TrustedProxies {
		if _, err := tx.Exec(`INSERT INTO trusted_proxies (seq, value) VALUES (?, ?)`, i, v); err != nil {
			return fmt.Errorf("写入 trusted_proxies 失败: %w", err)
		}
	}
	for i, r := range cfg.GlobalIPDeny {
		if _, err := tx.Exec(
			`INSERT INTO global_ip_deny (seq, cidr, note) VALUES (?, ?, ?)`,
			i, r.CIDR, r.Note); err != nil {
			return fmt.Errorf("写入 global_ip_deny 失败: %w", err)
		}
	}
	for i, u := range cfg.AdminUsers {
		if _, err := tx.Exec(
			`INSERT INTO admin_users (seq, username, password, password_hash) VALUES (?, ?, ?, ?)`,
			i, u.Username, u.Password, u.PasswordHash); err != nil {
			return fmt.Errorf("写入 admin_users 失败: %w", err)
		}
	}

	// 名单必须在路由之前写：route_acl_lists 的外键指着它。
	for i, l := range cfg.IPLists {
		if _, err := tx.Exec(
			`INSERT INTO ip_lists (name, kind, seq) VALUES (?, ?, ?)`,
			l.Name, l.Kind, i); err != nil {
			return fmt.Errorf("写入 ip_lists（%s）失败: %w", l.Name, err)
		}
		for j, r := range l.Rules {
			if _, err := tx.Exec(
				`INSERT INTO ip_list_rules (list_name, seq, cidr, note) VALUES (?, ?, ?, ?)`,
				l.Name, j, r.CIDR, r.Note); err != nil {
				return fmt.Errorf("写入 ip_lists（%s）的规则失败: %w", l.Name, err)
			}
		}
	}

	for i, r := range cfg.Routes {
		rl, err := marshalNullable(r.RateLimit)
		if err != nil {
			return fmt.Errorf("序列化路由 %s 的 rate_limit 失败: %w", r.ID, err)
		}
		cb, err := marshalNullable(r.CircuitBreaker)
		if err != nil {
			return fmt.Errorf("序列化路由 %s 的 circuit_breaker 失败: %w", r.ID, err)
		}
		auth, err := marshalNullable(r.Auth)
		if err != nil {
			return fmt.Errorf("序列化路由 %s 的 auth 失败: %w", r.ID, err)
		}
		if _, err := tx.Exec(`
INSERT INTO routes (
  id, seq, name, enabled, listen_port, host, path_prefix, target,
  strip_prefix, preserve_host, tls_mode, cert_file, key_file, redirect_http,
  timeout_ms, rate_limit, circuit_breaker, auth
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.ID, i, r.Name, r.Enabled, r.ListenPort, r.Host, r.PathPrefix, r.Target,
			boolToInt(r.StripPrefix), boolToInt(r.PreserveHost), r.TLSMode, r.CertFile,
			r.KeyFile, r.RedirectHTTP, r.TimeoutMs, rl, cb, auth); err != nil {
			return fmt.Errorf("写入路由 %s 失败: %w", r.ID, err)
		}

		if r.ACL != nil {
			for j, name := range r.ACL.Lists {
				// 这里不做「名字是否存在」的校验：validate 已经在更靠前的地方
				// 报过更完整的错（含可用名字提示）。但外键会兜住漏网的情况，
				// 报出来的是 constraint failed，属于「不该发生但发生了也要拦住」。
				if _, err := tx.Exec(
					`INSERT INTO route_acl_lists (route_id, seq, list_name) VALUES (?, ?, ?)`,
					r.ID, j, name); err != nil {
					return fmt.Errorf("写入路由 %s 的名单引用（%s）失败: %w", r.ID, name, err)
				}
			}
		}
	}

	if _, err := tx.Exec(`
INSERT INTO tls_settings (
  id, enabled, cert_dir, http_port, https_port,
  acme_email, acme_directory_url, acme_staging, acme_cache_dir
) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)`,
		boolToInt(cfg.TLS.Enabled), cfg.TLS.CertDir, cfg.TLS.HTTPPort, cfg.TLS.HTTPSPort,
		acmeField(cfg.TLS.ACME, func(a *ACMEConfig) string { return a.Email }),
		acmeField(cfg.TLS.ACME, func(a *ACMEConfig) string { return a.DirectoryURL }),
		acmeField(cfg.TLS.ACME, func(a *ACMEConfig) bool { return a.Staging }),
		acmeField(cfg.TLS.ACME, func(a *ACMEConfig) string { return a.CacheDir }),
	); err != nil {
		return fmt.Errorf("写入 tls_settings 失败: %w", err)
	}
	if cfg.TLS.ACME != nil {
		for i, h := range cfg.TLS.ACME.Hosts {
			if _, err := tx.Exec(`INSERT INTO acme_hosts (seq, host) VALUES (?, ?)`, i, h); err != nil {
				return fmt.Errorf("写入 acme_hosts 失败: %w", err)
			}
		}
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// marshalNullable 把可空子结构序列化成 JSON 列的值：nil 存 NULL，不是 "null"。
//
// 存 "null" 和存 NULL 在读回来时都是 nil，但前者会让 `WHERE rate_limit IS NULL`
// 这种查询对不上 —— 而且从配置里看不出「到底配了没有」。
//
// 签名收成 *T 而不是 any 是**必须**的，不是为了好看：参数声明成 any 时，
// 传一个 nil 的 *RateLimitConfig 进去，接口值本身并不等于 nil（它有类型、有
// 具体值 nil），`v == nil` 判断为假，于是每一段没配的配置都会被存成字符串
// "null"。读回来时 json 解 "null" 到结构体不报错、也不改值，得到一个
// 「零值但非 nil」的指针 —— 表现是每条路由都凭空多出一个熔断器、
// 一个空白的认证配置和一个 0 限流，而且表面上完全看不出来。
// 参数是 *T 时 T 被推断为结构体类型，`v == nil` 才是真的在最外层判空。
func marshalNullable[T any](v *T) (any, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// acmeField 取 ACME 配置里的一个字段，ACME 为 nil 时返回零值。
func acmeField[T any](a *ACMEConfig, get func(*ACMEConfig) T) T {
	var zero T
	if a == nil {
		return zero
	}
	return get(a)
}

// ---------- 映射：表 → Config ----------

// ErrNoConfig 表示「库里还没有配置」——不是读取失败，是从来没写过。
//
// 必须和「读到了但内容为空」区分开：前者要触发 config.json 导入或给出
// 首次使用的指引，后者是一份合法（虽然空）的配置。
var ErrNoConfig = errors.New("配置数据库里还没有配置")

func nullIntToBoolPtr(n sql.NullInt64) *bool {
	if !n.Valid {
		return nil
	}
	b := n.Int64 != 0
	return &b
}

// readConfigTx 从表里组装出一份 Config。
//
// 顺序一律按 seq：配置数组的顺序对行为没有影响，但对「导出成人能读的 JSON」
// 有影响 —— 每次导出都把路由顺序打乱会让人以为配置被改过。
func readConfigTx(tx *sql.Tx) (*Config, error) {
	cfg := &Config{}

	// 顶层标量。这一行同时也当作「库是否已初始化」的标志。
	var accessLog int
	err := tx.QueryRow(`SELECT admin_addr, admin_token, access_log FROM settings WHERE id = 1`).
		Scan(&cfg.AdminAddr, &cfg.AdminToken, &accessLog)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrNoConfig
	case err != nil:
		return nil, fmt.Errorf("读取顶层设置失败: %w", err)
	}
	cfg.AccessLog = accessLog != 0

	if err := scanInts(tx, `SELECT port FROM default_ports ORDER BY seq`, &cfg.DefaultPorts); err != nil {
		return nil, err
	}
	if err := scanStrings(tx, `SELECT value FROM trusted_proxies ORDER BY seq`, &cfg.TrustedProxies); err != nil {
		return nil, err
	}

	rows, err := tx.Query(`SELECT cidr, note FROM global_ip_deny ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("读取 global_ip_deny 失败: %w", err)
	}
	for rows.Next() {
		var r IPRule
		if err := rows.Scan(&r.CIDR, &r.Note); err != nil {
			rows.Close()
			return nil, fmt.Errorf("读取 global_ip_deny 失败: %w", err)
		}
		cfg.GlobalIPDeny = append(cfg.GlobalIPDeny, r)
	}
	if err := closeRows(rows, "global_ip_deny"); err != nil {
		return nil, err
	}

	urows, err := tx.Query(`SELECT username, password, password_hash FROM admin_users ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("读取 admin_users 失败: %w", err)
	}
	for urows.Next() {
		var u AdminUser
		if err := urows.Scan(&u.Username, &u.Password, &u.PasswordHash); err != nil {
			urows.Close()
			return nil, fmt.Errorf("读取 admin_users 失败: %w", err)
		}
		cfg.AdminUsers = append(cfg.AdminUsers, u)
	}
	if err := closeRows(urows, "admin_users"); err != nil {
		return nil, err
	}

	// 命名地址列表
	lrows, err := tx.Query(`SELECT name, kind FROM ip_lists ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("读取 ip_lists 失败: %w", err)
	}
	for lrows.Next() {
		var l IPListDef
		if err := lrows.Scan(&l.Name, &l.Kind); err != nil {
			lrows.Close()
			return nil, fmt.Errorf("读取 ip_lists 失败: %w", err)
		}
		cfg.IPLists = append(cfg.IPLists, l)
	}
	if err := closeRows(lrows, "ip_lists"); err != nil {
		return nil, err
	}

	rrows, err := tx.Query(`SELECT list_name, cidr, note FROM ip_list_rules ORDER BY list_name, seq`)
	if err != nil {
		return nil, fmt.Errorf("读取 ip_list_rules 失败: %w", err)
	}
	rules := map[string][]IPRule{}
	for rrows.Next() {
		var name string
		var r IPRule
		if err := rrows.Scan(&name, &r.CIDR, &r.Note); err != nil {
			rrows.Close()
			return nil, fmt.Errorf("读取 ip_list_rules 失败: %w", err)
		}
		rules[name] = append(rules[name], r)
	}
	if err := closeRows(rrows, "ip_list_rules"); err != nil {
		return nil, err
	}
	for i := range cfg.IPLists {
		cfg.IPLists[i].Rules = rules[cfg.IPLists[i].Name]
	}

	// 路由的名单引用先收成 map，避免每读一条路由都查一次库
	aclRows, err := tx.Query(`SELECT route_id, list_name FROM route_acl_lists ORDER BY route_id, seq`)
	if err != nil {
		return nil, fmt.Errorf("读取 route_acl_lists 失败: %w", err)
	}
	refs := map[string][]string{}
	for aclRows.Next() {
		var rid, name string
		if err := aclRows.Scan(&rid, &name); err != nil {
			aclRows.Close()
			return nil, fmt.Errorf("读取 route_acl_lists 失败: %w", err)
		}
		refs[rid] = append(refs[rid], name)
	}
	if err := closeRows(aclRows, "route_acl_lists"); err != nil {
		return nil, err
	}

	trows, err := tx.Query(`
SELECT id, name, enabled, listen_port, host, path_prefix, target,
       strip_prefix, preserve_host, tls_mode, cert_file, key_file, redirect_http,
       timeout_ms, rate_limit, circuit_breaker, auth
FROM routes ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("读取 routes 失败: %w", err)
	}
	for trows.Next() {
		var (
			r            RouteConfig
			enabled      sql.NullInt64
			redirectHTTP sql.NullInt64
			strip, pres  int
			rl, cb, auth sql.NullString
		)
		if err := trows.Scan(
			&r.ID, &r.Name, &enabled, &r.ListenPort, &r.Host, &r.PathPrefix, &r.Target,
			&strip, &pres, &r.TLSMode, &r.CertFile, &r.KeyFile, &redirectHTTP,
			&r.TimeoutMs, &rl, &cb, &auth); err != nil {
			trows.Close()
			return nil, fmt.Errorf("读取 routes 失败: %w", err)
		}
		r.Enabled = nullIntToBoolPtr(enabled)
		r.RedirectHTTP = nullIntToBoolPtr(redirectHTTP)
		r.StripPrefix = strip != 0
		r.PreserveHost = pres != 0

		if r.RateLimit, err = unmarshalNullable[RateLimitConfig](rl); err != nil {
			trows.Close()
			return nil, fmt.Errorf("解析路由 %s 的 rate_limit 失败: %w", r.ID, err)
		}
		if r.CircuitBreaker, err = unmarshalNullable[CBConfig](cb); err != nil {
			trows.Close()
			return nil, fmt.Errorf("解析路由 %s 的 circuit_breaker 失败: %w", r.ID, err)
		}
		if r.Auth, err = unmarshalNullable[RouteAuthConfig](auth); err != nil {
			trows.Close()
			return nil, fmt.Errorf("解析路由 %s 的 auth 失败: %w", r.ID, err)
		}
		if names := refs[r.ID]; len(names) > 0 {
			r.ACL = &RouteACLConfig{Lists: names}
		}
		cfg.Routes = append(cfg.Routes, r)
	}
	if err := closeRows(trows, "routes"); err != nil {
		return nil, err
	}

	// 顶层 TLS。单行，一次查完。
	var (
		tls          TLSConfig
		tlsEnabled   int
		acmeStaging  int
		acmeEmail    string
		acmeDirURL   string
		acmeCacheDir string
	)
	err = tx.QueryRow(`
SELECT enabled, cert_dir, http_port, https_port,
       acme_email, acme_directory_url, acme_staging, acme_cache_dir
FROM tls_settings WHERE id = 1`).
		Scan(&tlsEnabled, &tls.CertDir, &tls.HTTPPort, &tls.HTTPSPort,
			&acmeEmail, &acmeDirURL, &acmeStaging, &acmeCacheDir)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// 这一行缺失等价于「TLS 全默认」。不当成错误：老库、以及刚建好还没写过
		// 的库都可能没有它，而这两种情况都该能正常起来。
	case err != nil:
		return nil, fmt.Errorf("读取 tls_settings 失败: %w", err)
	default:
		tls.Enabled = tlsEnabled != 0
		var hosts []string
		if err := scanStrings(tx, `SELECT host FROM acme_hosts ORDER BY seq`, &hosts); err != nil {
			return nil, err
		}
		// 一个字段都没配、也没有域名时不留一个空的 ACME 块：
		// 空块会被序列化成 "acme": {}，与「没配过」不是一回事。
		if acmeEmail != "" || acmeDirURL != "" || acmeCacheDir != "" || acmeStaging != 0 || len(hosts) > 0 {
			tls.ACME = &ACMEConfig{
				Email:        acmeEmail,
				DirectoryURL: acmeDirURL,
				Staging:      acmeStaging != 0,
				CacheDir:     acmeCacheDir,
				Hosts:        hosts,
			}
		}
	}
	cfg.TLS = tls
	return cfg, nil
}

// unmarshalNullable 是 marshalNullable 的逆操作：NULL（或空串）→ nil。
//
// 解到 *T 而不是 T，是为了让字面量 "null" 也落在「没配」这一侧：解 null 到
// 结构体是不报错、也不改值，于是会凭空得到一个零值指针 —— 一旦库里存在
// 这种行（早期版本的写入就有这个毛病，见 marshalNullable 的注释），
// 每条路由都会多出一个「配了但全是零值」的熔断器 / 认证配置。
func unmarshalNullable[T any](n sql.NullString) (*T, error) {
	if !n.Valid || n.String == "" {
		return nil, nil
	}
	var v *T
	if err := json.Unmarshal([]byte(n.String), &v); err != nil {
		return nil, err
	}
	return v, nil
}

func scanInts(tx *sql.Tx, q string, dst *[]int) error {
	rows, err := tx.Query(q)
	if err != nil {
		return fmt.Errorf("查询失败: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("读取失败: %w", err)
		}
		*dst = append(*dst, v)
	}
	return closeRows(rows, q)
}

func scanStrings(tx *sql.Tx, q string, dst *[]string) error {
	rows, err := tx.Query(q)
	if err != nil {
		return fmt.Errorf("查询失败: %w", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("读取失败: %w", err)
		}
		*dst = append(*dst, v)
	}
	return closeRows(rows, q)
}

// closeRows 把 rows.Err() 也检查掉。只 Close 不查 Err 会漏掉「读到一半出错」，
// 那是查询类代码里最容易被忽略、也最难在测试里复现的一种静默丢数据。
func closeRows(rows *sql.Rows, what string) error {
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("遍历 %s 失败: %w", what, err)
	}
	return rows.Close()
}

// marshalConfig 把配置序列化成规范化的 JSON 字节，并补上末尾换行。
func marshalConfig(cfg *Config) ([]byte, error) {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("序列化配置失败: %w", err)
	}
	return append(b, '\n'), nil
}

// ---------- 对外接口 ----------

// read 读出当前配置，同时返回它的规范化 JSON 字节与版本号。
func (s *configStore) read() (raw []byte, cfg *Config, err error) {
	err = s.withTx(func(tx *sql.Tx) error {
		var e error
		cfg, e = readConfigTx(tx)
		if e != nil {
			return e
		}
		raw, e = marshalConfig(cfg)
		return e
	})
	if err != nil {
		return nil, nil, err
	}
	cfg.baseDir = filepath.Dir(s.path)
	return raw, cfg, nil
}

// write 把整份配置写进库，返回写入后的规范化字节与版本号。
//
// 返回的 raw 是**写完之后从表里读回来重新序列化**的那一份，而不是入参 cfg
// 序列化的结果。差别在于：写进去的内容和读出来的内容如果有一丝不一致
// （比如 acl.lists 为空数组被规范化成「没有 acl」），那么入参算出的 revision
// 就和下一次 GET 算出的 revision 不同 —— 客户端刚拿到的新 ETag 会在自己下一次
// 提交时立刻撞上 409 revision_mismatch，而且怎么重试都一样。
// 走「写后读回」这条路，两者必然一致。
func (s *configStore) write(cfg *Config) (raw []byte, rev string, err error) {
	err = s.withTx(func(tx *sql.Tx) error {
		// 先留一版历史，这是回滚与事故排查的退路。
		//
		// 注意这里取的是**覆盖之前那一刻**的库内容，而不是「入参 cfg 减去本次
		// 修改」—— 后者需要调用方保证自己没在别处动过手脚，而前者是库里事实上的
		// 上一版。取不到不算错（空库没什么可备份的），读失败也不该拦下保存本身：
		// 和历史表写不进去相比，保存配置成功更重要，但要留痕到日志。
		before, berr := readRawTx(tx)
		if berr != nil && !errors.Is(berr, ErrNoConfig) {
			slog.Warn("保存前读取当前配置失败，本次不留历史", "err", berr)
			before = nil
		}

		// 最后兜一道路由级默认值。调用方（mutate / importJSON）本来就会补，
		// 但存储层不该依赖调用方记得这件事：库里一旦出现一条没有 ID 或没有
		// path_prefix 的路由，界面按 ID 增删改就全乱了，而从数据本身看不出
		// 哪里不对。这个函数是幂等的，补过再补不会有副作用。
		cfg.applyRouteDefaults()

		if err := writeConfigTx(tx, cfg); err != nil {
			return err
		}
		back, err := readConfigTx(tx)
		if err != nil {
			return err
		}
		raw, err = marshalConfig(back)
		if err != nil {
			return err
		}
		// 内容一模一样就不必留历史了 —— 历史里出现一条和「现在」完全相同的记录，
		// 只会在回滚清单里添噪音。判断放在写入之后、用读回的字节比，是因为
		// 入参 cfg 带着内存里补的顶层默认值（admin_addr 之类），直接拿它序列化
		// 出来的字节和库里的规范形态本来就不同，比了必然「有变化」。
		if before != nil && bytes.Equal(before, raw) {
			return nil
		}
		return archiveRawTx(tx, before)
	})
	if err != nil {
		return nil, "", err
	}
	return raw, revisionOf(raw), nil
}

// readRawTx 读出当前配置的规范化字节。库为空时返回 ErrNoConfig。
func readRawTx(tx *sql.Tx) ([]byte, error) {
	cfg, err := readConfigTx(tx)
	if err != nil {
		return nil, err
	}
	return marshalConfig(cfg)
}

// archiveRawTx 把一份配置快照存进历史表。raw 为空表示没有上一版可存（空库）。
func archiveRawTx(tx *sql.Tx, raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	rev := revisionOf(raw)

	// 同一份内容不再记一条：连续两次保存出同样的历史没有意义，
	// 而历史窗口只有 historyKeep 条，重复项会把真正有用的版本挤出去。
	var exists int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM config_history WHERE revision = ?`, rev).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}
	if _, err := tx.Exec(
		`INSERT INTO config_history (revision, raw, created_at) VALUES (?, ?, ?)`,
		rev, raw, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	// 只留最近 historyKeep 条。删的时候按插入顺序 —— created_at 可能同秒。
	_, err := tx.Exec(`
DELETE FROM config_history WHERE revision NOT IN (
  SELECT revision FROM config_history ORDER BY created_at DESC, rowid DESC LIMIT ?
)`, historyKeep)
	return err
}

// isEmpty 报告库里是否还没有配置。
func (s *configStore) isEmpty() (bool, error) {
	empty := false
	err := s.withTx(func(tx *sql.Tx) error {
		_, err := readConfigTx(tx)
		if errors.Is(err, ErrNoConfig) {
			empty = true
			return nil
		}
		return err
	})
	return empty, err
}

// importJSON 用一份 JSON 覆盖当前配置（首次导入与命令行导入都走它）。
func (s *configStore) importJSON(raw []byte) (rev string, err error) {
	cfg := &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return "", fmt.Errorf("解析配置 JSON 失败: %w", err)
	}
	if err := rejectLegacyACL(raw); err != nil {
		return "", err
	}
	// baseDir 必须在 validate 之前设好：证书的相对路径就是相对它解析的，
	// 留空的话会退化成「相对进程工作目录」，同一个配置在不同启动方式下
	// 校验结果不同 —— 命令行导入时工作目录是用户随手所在的目录，必然对不上。
	cfg.baseDir = filepath.Dir(s.path)
	// 只固化路由级默认值（ID / path_prefix），**不固化**顶层默认值 ——
	// applyTopDefaults 会把留空的 admin_addr 变成默认地址，一旦写进库就再也
	// 回不到「留空 = 用默认」这个语义了，下次改配置还会顺带把管理端口打开。
	// 校验按运行时语义来做，所以用 validateWithDefaults（在副本上补默认值）。
	cfg.applyRouteDefaults()
	if err := cfg.validateWithDefaults(); err != nil {
		return "", err
	}
	_, rev, err = s.write(cfg)
	return rev, err
}

// exportJSON 导出当前配置为 JSON 字节（给控制台的备份按钮和命令行用）。
func (s *configStore) exportJSON() ([]byte, error) {
	raw, _, err := s.read()
	return raw, err
}

// historyCount 返回配置历史里存了几版。
//
// 它是「每次写入前都留了一版退路」这条承诺的可验证形式 —— 换成 SQLite 之前
// 这件事靠的是 config.json.bak 存不存在，现在靠这张表有没有长。
func (s *configStore) historyCount() (int, error) {
	var n int
	err := s.withTx(func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT COUNT(1) FROM config_history`).Scan(&n)
	})
	return n, err
}

// restoreConfig 把一份配置写回数据库（写接口在重载失败时用它回滚）。
//
// 走完整校验：回滚的是一份曾经成功加载过的配置，理论上必然合法，
// 但如果它现在不合法了（比如表被外力改坏），宁可让回滚失败并报出来，
// 也不要写进去一份连自己都加载不了的配置。
func restoreConfig(path string, raw []byte) error {
	st, err := storeFor(path)
	if err != nil {
		return err
	}
	_, err = st.importJSON(raw)
	return err
}

// ---------- 首次初始化 ----------

// seedFromJSONFile 在库还是空的时候，用一份 JSON 文件初始化配置。
//
// 这是给「已经跑着 config.json 的老部署」准备的升级通道：换上新二进制后
// 第一次启动，配置从原来的文件里搬进来，之后文件就不再被读取了。
// 文件不存在不算错误 —— 全新安装本来就没有这个文件。
func (s *configStore) seedFromJSONFile(path string) (bool, error) {
	empty, err := s.isEmpty()
	if err != nil {
		return false, err
	}
	if !empty {
		return false, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("读取初始配置文件失败: %w", err)
	}
	if _, err := s.importJSON(raw); err != nil {
		return false, fmt.Errorf("导入 %s 失败: %w", path, err)
	}
	return true, nil
}

// isSQLiteFile 判断一个文件是不是 SQLite 库（按文件头魔数）。
//
// 用途是让「-c 指向了一个老的 config.json」这种最常见的升级误操作有一句
// 人话报错，而不是让它安静地建一个同名的新库、把用户的配置留在原地没人读。
func isSQLiteFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 16)
	n, _ := io.ReadFull(f, head)
	return n >= 16 && strings.HasPrefix(string(head), "SQLite format 3")
}

// ---------- 进程级连接复用 ----------

var (
	storeMu    sync.Mutex
	storeByKey = map[string]*configStore{}
)

// storeFor 返回 path 对应的配置库连接，同一个路径复用同一个连接。
//
// 为什么要缓存而不是每次都 openConfigStore：那四个读写函数
// （loadConfig / readConfigFile / parseConfigFile / saveConfig）的调用点遍布
// 管理接口、统计接口和测试，每次调用都开一个新连接池会泄漏文件句柄，
// 每次还要重跑一遍建表语句。缓存之后这些调用点一行都不用改。
//
// key 用绝对路径归一：同一个库经由相对路径和绝对路径进来必须命中同一个连接池。
// 两个连接池同时写一个 SQLite 文件，正是单写者模型下最容易出问题的地方。
func storeFor(path string) (*configStore, error) {
	if path == "" {
		return nil, errors.New("配置数据库路径为空")
	}
	key, err := filepath.Abs(path)
	if err != nil {
		key = path
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	if s, ok := storeByKey[key]; ok {
		return s, nil
	}
	s, err := openConfigStore(key)
	if err != nil {
		return nil, err
	}
	storeByKey[key] = s
	return s, nil
}

// closeStore 关闭并移除某个路径的连接。
//
// 测试里必须调：Windows 上文件被打开着就删不掉，临时目录清理会直接失败，
// 报的是「另一个程序正在使用此文件」，看不出和数据库有关。
func closeStore(path string) error {
	key, err := filepath.Abs(path)
	if err != nil {
		key = path
	}
	storeMu.Lock()
	s := storeByKey[key]
	delete(storeByKey, key)
	storeMu.Unlock()
	if s == nil {
		return nil
	}
	return s.Close()
}

// closeAllStores 关闭全部连接，进程退出前收尾用。
func closeAllStores() {
	storeMu.Lock()
	all := make([]*configStore, 0, len(storeByKey))
	for _, s := range storeByKey {
		all = append(all, s)
	}
	storeByKey = map[string]*configStore{}
	storeMu.Unlock()
	for _, s := range all {
		_ = s.Close()
	}
}
