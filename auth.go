package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Authenticator 统一 Basic / JWT 两种认证方式。
// Authenticate 返回的 claims 只在认证成功时有值，由 handler 决定怎么用。
type Authenticator interface {
	Authenticate(r *http.Request) (claims map[string]any, ok bool, reason string)
	OnSuccess(r *http.Request, claims map[string]any)
	WriteChallenge(w http.ResponseWriter)
	Kind() string
}

// ---------- Basic ----------

type BasicAuthEntry struct {
	Username     string `json:"username"`
	Password     string `json:"password"`      // 明文，仅测试用，启动会打警告
	PasswordHash string `json:"password_hash"` // bcrypt，推荐
}

type basicCacheEntry struct {
	ok  bool
	exp time.Time
}

type BasicAuthenticator struct {
	accounts map[string]string // username -> bcrypt hash
	realm    string

	mu    sync.Mutex
	cache map[string]basicCacheEntry
}

var (
	errNoAccounts    = errors.New("basic 认证至少需要配置一个账号")
	errEmptyUsername = errors.New("basic 账号的 username 不能为空")
)

// NewBasicAuthenticator 构建 Basic 认证器。
// 明文密码会被自动转成 bcrypt —— 配置文件里最好直接存 hash。
func NewBasicAuthenticator(entries []BasicAuthEntry, realm string) (*BasicAuthenticator, error) {
	if realm == "" {
		realm = "goproxy"
	}
	if len(entries) == 0 {
		return nil, errNoAccounts
	}
	a := &BasicAuthenticator{
		accounts: make(map[string]string, len(entries)),
		cache:    make(map[string]basicCacheEntry),
		realm:    realm,
	}
	for _, e := range entries {
		if e.Username == "" {
			return nil, errEmptyUsername
		}
		hash := e.PasswordHash
		if hash == "" {
			if e.Password == "" {
				return nil, fmt.Errorf("账号 %s 既没有 password 也没有 password_hash", e.Username)
			}
			h, err := bcrypt.GenerateFromPassword([]byte(e.Password), bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			hash = string(h)
			slog.Warn("Basic 认证配置了明文密码，建议改用 password_hash（下面这行就是生成好的 hash）",
				"username", e.Username, "password_hash", hash)
		}
		// 顺带校验一下 hash 是不是合法 bcrypt，避免配错了还以为在生效
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("probe")); err != nil &&
			!errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return nil, fmt.Errorf("账号 %s 的 password_hash 不是合法的 bcrypt: %w", e.Username, err)
		}
		a.accounts[e.Username] = hash
	}
	return a, nil
}

func (b *BasicAuthenticator) Kind() string { return "basic" }

func (b *BasicAuthenticator) Authenticate(r *http.Request) (map[string]any, bool, string) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return nil, false, "missing_credentials"
	}
	hash, exists := b.accounts[user]
	if !exists {
		return nil, false, "unknown_user"
	}

	// bcrypt 单次几十毫秒，缓存结果避免每个请求都算一遍
	key := user + "\x00" + pass
	now := time.Now()
	b.mu.Lock()
	if c, hit := b.cache[key]; hit && now.Before(c.exp) {
		b.mu.Unlock()
		if !c.ok {
			return nil, false, "bad_password"
		}
		return nil, true, ""
	}
	b.mu.Unlock()

	ok = bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil

	b.mu.Lock()
	if len(b.cache) > 10000 {
		for k, v := range b.cache {
			if now.After(v.exp) {
				delete(b.cache, k)
			}
		}
		if len(b.cache) > 10000 {
			b.cache = make(map[string]basicCacheEntry)
		}
	}
	b.cache[key] = basicCacheEntry{ok: ok, exp: now.Add(60 * time.Second)}
	b.mu.Unlock()

	if !ok {
		return nil, false, "bad_password"
	}
	return nil, true, ""
}

func (b *BasicAuthenticator) OnSuccess(r *http.Request, claims map[string]any) {}

func (b *BasicAuthenticator) WriteChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+b.realm+`", charset="UTF-8"`)
}

// ---------- JWT ----------

type JWTAuthenticator struct {
	verifier *JWTVerifier
	forward  map[string]string // claim -> 转发给后端的 header
}

func NewJWTAuthenticator(cfg JWTConfig) (*JWTAuthenticator, error) {
	v, err := NewJWTVerifier(cfg)
	if err != nil {
		return nil, err
	}
	return &JWTAuthenticator{verifier: v, forward: cfg.ForwardClaims}, nil
}

func (j *JWTAuthenticator) Kind() string { return "jwt" }

func (j *JWTAuthenticator) Authenticate(r *http.Request) (map[string]any, bool, string) {
	token := extractBearer(r)
	if token == "" {
		return nil, false, "missing_token"
	}
	claims, err := j.verifier.Verify(token)
	if err != nil {
		switch {
		case errors.Is(err, ErrTokenExpired):
			return nil, false, "token_expired"
		case errors.Is(err, ErrTokenSignature):
			return nil, false, "bad_signature"
		case errors.Is(err, ErrTokenAlgNotAllowed):
			return nil, false, "alg_not_allowed"
		default:
			return nil, false, "invalid_token"
		}
	}
	return claims, true, ""
}

// OnSuccess 按 forward_claims 配置把 claim 注入请求头，后端就能直接拿到用户身份。
func (j *JWTAuthenticator) OnSuccess(r *http.Request, claims map[string]any) {
	if len(j.forward) == 0 || len(claims) == 0 {
		return
	}
	for claim, header := range j.forward {
		v, ok := claims[claim]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" {
				r.Header.Set(header, t)
			}
		case float64, bool:
			r.Header.Set(header, fmt.Sprintf("%v", t))
		}
	}
}

func (j *JWTAuthenticator) WriteChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="goproxy", error="invalid_token"`)
}

// extractBearer 从 Authorization: Bearer <token> 取 token。
// 也接受 ?access_token= 查询参数（部分客户端依赖它），但优先级低于 Header。
func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth != "" {
		const prefix = "Bearer "
		if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
			return strings.TrimSpace(auth[len(prefix):])
		}
	}
	if q := r.URL.Query().Get("access_token"); q != "" {
		return q
	}
	return ""
}
