package main

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ---------- 管理端账号 ----------

// adminAccounts 是控制台管理员账号的运行时视图。
//
// 它与路由的 BasicAuthenticator 有两点关键差别，所以没有直接复用：
//
//  1. **不做结果缓存**。Basic 认证器缓存 60 秒的验证结果，因为每个请求都要过一遍；
//     管理端登录是低频且已经被限流的操作，缓存反而会让「改密码」不能立刻生效。
//  2. 需要支持「按用户名精确失效会话」，所以对外暴露的是**每个账号的指纹**。
//
// 至于「未知用户名怎么办」这种容易被忽略的点，见 verify() 的注释。
type adminAccounts struct {
	accounts map[string]string // username -> bcrypt hash

	mu sync.RWMutex
}

// errAdminUserNotFound 表示用户名不存在。
var errAdminUserNotFound = errors.New("用户名或密码错误")

// newAdminAccounts 构建账号表。
//
// 明文 password 会被转成 bcrypt（配置文件里写明文是允许的，但会打警告），
// 与路由 Basic 认证的行为保持一致 —— 同样的取舍不该有两个答案。
func newAdminAccounts(users []AdminUser) (*adminAccounts, error) {
	a := &adminAccounts{accounts: make(map[string]string, len(users))}
	for _, u := range users {
		name := strings.TrimSpace(u.Username)
		if name == "" {
			return nil, errors.New("admin_users 里存在空的 username")
		}
		hash := u.PasswordHash
		if hash == "" {
			if u.Password == "" {
				return nil, fmt.Errorf("管理员 %s 既没有 password 也没有 password_hash", name)
			}
			h, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			hash = string(h)
			slog.Warn("管理端配置了明文密码，建议改用 password_hash（下面这行就是生成好的 hash）",
				"username", name, "password_hash", hash)
		}
		a.accounts[name] = hash
	}
	return a, nil
}

// count 返回账号数量。
func (a *adminAccounts) count() int {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.accounts)
}

// usernames 返回已排序的用户名列表，用于启动日志。
func (a *adminAccounts) usernames() []string {
	if a == nil {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.accounts))
	for k := range a.accounts {
		out = append(out, k)
	}
	// 固定顺序，避免每次启动日志里的顺序都不一样
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// verify 校验用户名与密码，成功时返回该账号的**指纹**。
//
// 指纹用于把会话绑定到「具体某个账号的当前密码」上：改密码即该账号所有会话失效。
// 见 sessionFingerprintForUser 的注释。
//
// 关于**未知用户名**：这里刻意也跑一次 bcrypt 比对（fakeHash），
// 而不是立即返回错误。否则「用户名不存在」会立刻返回、而「密码错误」要等
// 几十毫秒的 bcrypt，攻击者用响应时间就能枚举出哪些用户名是真的。
// 登录接口本身有恒定 ~400ms 的兜底延时，但那是**总时长**的兜底，
// 挡不住「先返回 vs 后返回」这种更细的差异，所以这一层必须自己做。
func (a *adminAccounts) verify(username, password string) (fingerprint string, err error) {
	if a == nil {
		// 没配任何账号：也要走完假哈希，否则「配了账号」和「没配账号」
		// 两种状态的响应时间会不一样。
		bcrypt.CompareHashAndPassword([]byte(fakeBcryptHash), []byte(password))
		return "", errAdminUserNotFound
	}

	a.mu.RLock()
	hash, ok := a.accounts[username]
	a.mu.RUnlock()

	if !ok {
		// 用固定假哈希消耗与真实校验相当的时间。这个哈希对应一个不可能被输入的
		// 密码，且它本身是合法的 bcrypt（cost 与 DefaultCost 一致），
		// 所以耗时与真实比对同量级。
		bcrypt.CompareHashAndPassword([]byte(fakeBcryptHash), []byte(password))
		return "", errAdminUserNotFound
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return "", errAdminUserNotFound
	}
	return sessionFingerprintForUser(username, hash), nil
}

// fingerprintFor 返回某个账号的当前指纹（不校验密码）。
//
// 会话每次请求都要拿它和会话里存的指纹比对 —— 用**当前配置**算，
// 所以改密码、删账号、改用户名都会让旧指纹对不上，会话自然失效。
// 账号不存在时返回空串，调用方据此直接拒绝。
func (a *adminAccounts) fingerprintFor(username string) string {
	if a == nil || username == "" {
		return ""
	}
	a.mu.RLock()
	hash, ok := a.accounts[username]
	a.mu.RUnlock()
	if !ok {
		return ""
	}
	return sessionFingerprintForUser(username, hash)
}

// sessionFingerprintForUser 算出「这个账号在当前密码下」的会话指纹。
//
// 为什么指纹要含用户名：只绑密码哈希的话，两个账号碰巧用同一个密码、
// 或者管理员把 A 的 hash 复制给 B，就会互相能续用对方的会话。
// 带上用户名就没有这个歧义。
//
// 为什么含密码哈希而不是明文密码：密码哈希本来就存在内存里，
// 不需要再引入一份明文；而且改密码时它必变，正好实现「改密即下线」。
func sessionFingerprintForUser(username, passwordHash string) string {
	return hashHandle("admin-user\x00" + username + "\x00" + passwordHash)
}

// fakeBcryptHash 是给「用户名不存在」路径用的占位哈希。
//
// 它必须是一个**合法的 bcrypt**：如果格式非法，CompareHashAndPassword 会
// 立刻报错返回，耗时几乎为零，那就等于把「用户不存在」暴露给了计时攻击。
// 这里的值是启动时对一个随机密码算出来的固定串，任何真实输入都不可能匹配。
//
// 用 init 生成而不是硬编码一串字面量：硬编码的话读代码的人无法确认它 cost 多少、
// 是否真的合法；现算一次（约几十毫秒，只在进程启动时发生）则自证。
var fakeBcryptHash string

func init() {
	h, err := bcrypt.GenerateFromPassword([]byte("goproxy-admin-fake-password-do-not-use"), bcrypt.DefaultCost)
	if err != nil {
		// 理论上不会失败（失败只可能是 cost 非法）。真失败了也不能让进程起来后
		// 悄悄退化成「瞬间返回」——那正是要防的计时泄漏。
		panic("无法生成占位 bcrypt 哈希: " + err.Error())
	}
	fakeBcryptHash = string(h)
}

// adminSessionTTLFor 目前所有账号共用同一套会话时长。
// 抽成函数是为了让「将来要按账号配置不同时长」有个明确的落点，
// 而不是散落在各处的时间常量。
func adminSessionTTLFor() (idle, absolute time.Duration) {
	return sessionIdleTimeout, sessionAbsoluteTimeout
}
