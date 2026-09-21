package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

/*
蜜罐与封禁的存储读写。

单独一个文件而不是并进 configstore.go，是因为两者的性质不同：
configstore.go 管的是**配置**（进 revision、进 config_history、进 -config-export），
这里管的是**运行态**。混在一起最容易出的事，就是某天顺手把封禁条目也算进
revision —— 那会让每次自动封禁都让控制台里的编辑者撞一次 409。
*/

const (
	honeypotModeObserve = "observe"
	honeypotModeEnforce = "enforce"

	honeypotMinBanSecs = 60
	honeypotMaxBanSecs = 30 * 24 * 3600
)

// honeypotConfig 是蜜罐与自动封禁的全部可调项。
type honeypotConfig struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
	BanSecs int    `json:"ban_secs"`
	// Exempt 是额外豁免的 CIDR。内网、可信代理、白名单、控制台来源
	// 已经在代码里硬豁免了，这里留的是「运营知道但代码不知道」的那些。
	Exempt []string       `json:"exempt"`
	Ports  []honeypotPort `json:"ports"`
}

func defaultHoneypotConfig() honeypotConfig {
	return honeypotConfig{
		Enabled: false,
		Mode:    honeypotModeObserve,
		BanSecs: int(time.Hour / time.Second),
	}
}

// normalize 补齐默认值并校验，返回规范化后的配置。
//
// 校验按 fail-closed 来：不认识的 mode、解析不了的 CIDR、越界的时长一律报错，
// 不静默纠正。理由和配置里其它地方一样 —— 静默纠正的结果是「界面上显示 A、
// 实际行为是 B」，排查时最费时间。
func (c *honeypotConfig) normalize() error {
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case "", honeypotModeObserve:
		c.Mode = honeypotModeObserve
	case honeypotModeEnforce:
		c.Mode = honeypotModeEnforce
	default:
		return fmt.Errorf("mode 只能是 %s | %s，收到 %q", honeypotModeObserve, honeypotModeEnforce, c.Mode)
	}
	if c.BanSecs == 0 {
		c.BanSecs = int(time.Hour / time.Second)
	}
	if c.BanSecs < honeypotMinBanSecs || c.BanSecs > honeypotMaxBanSecs {
		return fmt.Errorf("ban_secs 必须在 %d-%d 之间，收到 %d", honeypotMinBanSecs, honeypotMaxBanSecs, c.BanSecs)
	}
	for i, raw := range c.Exempt {
		s := strings.TrimSpace(raw)
		if s == "" {
			return fmt.Errorf("exempt[%d] 为空", i)
		}
		if _, _, err := net.ParseCIDR(s); err != nil {
			if net.ParseIP(s) == nil {
				return fmt.Errorf("exempt[%d] (%s) 既不是 CIDR 也不是 IP", i, s)
			}
		}
		c.Exempt[i] = s
	}
	for i := range c.Ports {
		p := &c.Ports[i]
		p.Proto = strings.ToLower(strings.TrimSpace(p.Proto))
		if p.Proto == "" {
			p.Proto = "tcp"
		}
		if p.Proto != "tcp" && p.Proto != "udp" {
			return fmt.Errorf("ports[%d] (%d)：proto 只能是 tcp|udp，收到 %q", i, p.Port, p.Proto)
		}
		if p.Port < 1 || p.Port > 65535 {
			return fmt.Errorf("ports[%d]：端口号 %d 超出 1-65535", i, p.Port)
		}
		p.Note = normalizeSample(p.Note)
	}
	return nil
}

// readHoneypot 读出蜜罐配置。库里没有就返回默认（关闭）。
func (s *configStore) readHoneypot() (honeypotConfig, error) {
	cfg := defaultHoneypotConfig()
	if s == nil {
		return cfg, nil
	}
	err := s.withTx(func(tx *sql.Tx) error {
		var (
			enabled int
			banSecs int
			mode    string
			exempt  string
		)
		err := tx.QueryRow(
			`SELECT enabled, mode, ban_secs, exempt FROM honeypot_settings WHERE id = 1`).
			Scan(&enabled, &mode, &banSecs, &exempt)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// 还没配过：保持默认（关闭）
		case err != nil:
			return err
		default:
			cfg.Enabled = enabled != 0
			cfg.Mode = mode
			cfg.BanSecs = banSecs
			if strings.TrimSpace(exempt) != "" {
				_ = json.Unmarshal([]byte(exempt), &cfg.Exempt)
			}
		}

		rows, err := tx.Query(`SELECT port, proto, note FROM honeypot_ports ORDER BY seq`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p honeypotPort
			if err := rows.Scan(&p.Port, &p.Proto, &p.Note); err != nil {
				return err
			}
			cfg.Ports = append(cfg.Ports, p)
		}
		return rows.Err()
	})
	if err != nil {
		return defaultHoneypotConfig(), fmt.Errorf("读取蜜罐配置失败: %w", err)
	}
	return cfg, nil
}

// readBans 读出全部封禁行（含已过期、但仍在记忆窗口内的那些）。
//
// 放在 store 上而不是 banList 里，是为了让命令行那条路复用同一段 SQL ——
// 两处各写一遍查询，早晚会有一处漏掉新加的列。
func (s *configStore) readBans() ([]banEntry, error) {
	if s == nil {
		return nil, nil
	}
	var out []banEntry
	err := s.withTx(func(tx *sql.Tx) error {
		rows, err := tx.Query(
			`SELECT ip, reason, source, level, hits, created_at, expires_at, last_at, samples
			   FROM ban_entries`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				e                banEntry
				created, expires string
				lastAt, samples  string
			)
			if err := rows.Scan(&e.IP, &e.Reason, &e.Source, &e.Level, &e.Hits,
				&created, &expires, &lastAt, &samples); err != nil {
				return err
			}
			e.CreatedAt = parseLogTime(created)
			e.ExpiresAt = parseLogTime(expires)
			e.LastAt = parseLogTime(lastAt)
			if strings.TrimSpace(samples) != "" {
				_ = json.Unmarshal([]byte(samples), &e.Samples)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("读取封禁表失败: %w", err)
	}
	return out, nil
}

// writeHoneypot 全量替换蜜罐配置。
//
// 与 writeConfigTx 同一个取舍：条数很少（端口通常个位数），
// 「删光再插」一次性处理了顺序、新增、删除三件事，比逐条 upsert 少一处必漏的逻辑。
func (s *configStore) writeHoneypot(cfg honeypotConfig) error {
	if err := cfg.normalize(); err != nil {
		return badRequest("bad_honeypot_config", "%v", err)
	}
	if s == nil {
		return errors.New("没有配置库")
	}
	exempt, err := json.Marshal(cfg.Exempt)
	if err != nil {
		exempt = []byte("[]")
	}
	return s.withTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM honeypot_ports`); err != nil {
			return err
		}
		for i, p := range cfg.Ports {
			if _, err := tx.Exec(
				`INSERT INTO honeypot_ports (seq, port, proto, note) VALUES (?, ?, ?, ?)`,
				i, p.Port, p.Proto, p.Note); err != nil {
				return err
			}
		}
		_, err := tx.Exec(`
INSERT INTO honeypot_settings (id, enabled, mode, ban_secs, exempt)
VALUES (1, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  enabled = excluded.enabled, mode = excluded.mode,
  ban_secs = excluded.ban_secs, exempt = excluded.exempt`,
			boolToInt(cfg.Enabled), cfg.Mode, cfg.BanSecs, string(exempt))
		return err
	})
}
