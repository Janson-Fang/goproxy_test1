package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

// 自研的 JWT 校验（只做验证，不签发）。
// 依赖只有标准库，避免为了一个 HS256 校验引入整个 jwt 库。

var (
	ErrTokenMalformed     = errors.New("token 格式错误")
	ErrTokenAlgNotAllowed = errors.New("token 算法不在白名单")
	ErrTokenSignature     = errors.New("token 签名校验失败")
	ErrTokenExpired       = errors.New("token 已过期")
	ErrTokenNotYet        = errors.New("token 尚未生效")
	ErrTokenClaims        = errors.New("token 声明校验失败")
)

type JWTConfig struct {
	// Secret 用于 HS256/384/512
	Secret string `json:"secret"`
	// PublicKeyPEM 用于 RS256（PEM 格式的 PKIX 公钥）
	PublicKeyPEM string `json:"public_key_pem"`

	// Algs 允许的算法白名单。不填按 Secret/PublicKeyPEM 推断。
	// 必须显式限制，否则会留下 alg=none 和算法混淆的漏洞。
	Algs []string `json:"algs"`

	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`

	// LeewaySecs 时钟偏移容忍（秒），默认 60
	LeewaySecs int `json:"leeway_secs"`

	// ForwardClaims 把 claim 透传给后端，如 {"sub": "X-User-Id"}
	ForwardClaims map[string]string `json:"forward_claims"`
}

type JWTVerifier struct {
	cfg    JWTConfig
	algs   map[string]bool
	secret []byte
	rsaKey *rsa.PublicKey
	leeway time.Duration
}

func NewJWTVerifier(cfg JWTConfig) (*JWTVerifier, error) {
	v := &JWTVerifier{
		cfg:    cfg,
		algs:   make(map[string]bool),
		secret: []byte(cfg.Secret),
		leeway: time.Duration(cfg.LeewaySecs) * time.Second,
	}
	if v.leeway <= 0 {
		v.leeway = 60 * time.Second
	}

	if cfg.PublicKeyPEM != "" {
		key, err := parsePublicKeyPEM(cfg.PublicKeyPEM)
		if err != nil {
			return nil, err
		}
		v.rsaKey = key
	}

	if len(cfg.Algs) == 0 {
		// 按凭据推断：给了 RSA 公钥就只认 RS256，否则只认 HS256
		if v.rsaKey != nil {
			v.algs["RS256"] = true
		} else {
			v.algs["HS256"] = true
		}
	} else {
		for _, a := range cfg.Algs {
			switch strings.ToUpper(strings.TrimSpace(a)) {
			case "HS256", "HS384", "HS512":
				if len(v.secret) == 0 {
					return nil, fmt.Errorf("jwt 算法 %s 需要配置 secret", a)
				}
			case "RS256":
				if v.rsaKey == nil {
					return nil, fmt.Errorf("jwt 算法 RS256 需要配置 public_key_pem")
				}
			default:
				return nil, fmt.Errorf("不支持的 jwt 算法 %q（且 alg=none 永远被拒绝）", a)
			}
			v.algs[strings.ToUpper(strings.TrimSpace(a))] = true
		}
	}

	if len(v.secret) == 0 && v.rsaKey == nil {
		return nil, errors.New("jwt 需要 secret 或 public_key_pem 之一")
	}
	return v, nil
}

func parsePublicKeyPEM(s string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("public_key_pem 不是合法的 PEM 格式")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// 也兼容证书形式（CERTIFICATE 块）
		cert, cerr := x509.ParseCertificate(block.Bytes)
		if cerr != nil {
			return nil, fmt.Errorf("解析公钥失败: %w", err)
		}
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("证书中的公钥不是 RSA")
		}
		return key, nil
	}
	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("公钥不是 RSA 公钥（仅支持 RS256）")
	}
	return key, nil
}

// Verify 校验 token，返回 claims。
func (v *JWTVerifier) Verify(tokenString string) (map[string]any, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrTokenMalformed
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrTokenMalformed
	}
	alg := strings.ToUpper(header.Alg)
	if !v.algs[alg] {
		return nil, ErrTokenAlgNotAllowed
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	if err := v.verifySig(alg, parts[0]+"."+parts[1], sig); err != nil {
		return nil, err
	}

	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	claims := map[string]any{}
	if err := json.Unmarshal(claimBytes, &claims); err != nil {
		return nil, ErrTokenClaims
	}
	if err := v.validateClaims(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *JWTVerifier) verifySig(alg, signingInput string, sig []byte) error {
	switch alg {
	case "HS256", "HS384", "HS512":
		var h hash.Hash
		switch alg {
		case "HS256":
			h = hmac.New(sha256.New, v.secret)
		case "HS384":
			h = hmac.New(sha512.New384, v.secret)
		case "HS512":
			h = hmac.New(sha512.New, v.secret)
		}
		h.Write([]byte(signingInput))
		// 用 hmac.Equal 而不是 bytes.Equal，避免时序攻击
		if !hmac.Equal(h.Sum(nil), sig) {
			return ErrTokenSignature
		}
		return nil

	case "RS256":
		hashed := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(v.rsaKey, crypto.SHA256, hashed[:], sig); err != nil {
			return ErrTokenSignature
		}
		return nil
	}
	return ErrTokenAlgNotAllowed
}

func (v *JWTVerifier) validateClaims(claims map[string]any) error {
	now := time.Now()

	if exp, ok := numClaim(claims, "exp"); ok {
		if now.After(time.Unix(int64(exp), 0).Add(v.leeway)) {
			return ErrTokenExpired
		}
	}
	if nbf, ok := numClaim(claims, "nbf"); ok {
		if now.Before(time.Unix(int64(nbf), 0).Add(-v.leeway)) {
			return ErrTokenNotYet
		}
	}
	if v.cfg.Issuer != "" {
		if iss, _ := claims["iss"].(string); iss != v.cfg.Issuer {
			return fmt.Errorf("%w: issuer 不匹配", ErrTokenClaims)
		}
	}
	if v.cfg.Audience != "" {
		if !audienceMatches(claims["aud"], v.cfg.Audience) {
			return fmt.Errorf("%w: audience 不匹配", ErrTokenClaims)
		}
	}
	return nil
}

func numClaim(claims map[string]any, key string) (float64, bool) {
	switch v := claims[key].(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	}
	return 0, false
}

func audienceMatches(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
