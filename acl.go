package main

import (
	"fmt"
	"net"
	"strings"
)

type ACLMode string

const (
	ACLNone  ACLMode = ""
	ACLAllow ACLMode = "allow"
	ACLDeny  ACLMode = "deny"
)

// ACL 是 IP 白名单 / 黑名单。
type ACL struct {
	Mode ACLMode
	nets []*net.IPNet
}

func NewACL(mode string, cidrs []string) (*ACL, error) {
	m := ACLMode(strings.ToLower(mode))
	switch m {
	case ACLNone, ACLAllow, ACLDeny:
	default:
		return nil, fmt.Errorf("acl.mode 必须是 allow 或 deny，当前 %q", mode)
	}
	a := &ACL{Mode: m}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			// 也允许直接写单个 IP，自动补成 /32 或 /128
			ip := net.ParseIP(c)
			if ip == nil {
				return nil, fmt.Errorf("acl 项 %q 既不是 IP 也不是 CIDR", c)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		a.nets = append(a.nets, n)
	}
	if m != ACLNone && len(a.nets) == 0 {
		return nil, fmt.Errorf("acl.mode=%s 但 cidrs 为空，会拒绝/放行所有请求，请检查配置", m)
	}
	return a, nil
}

// Allowed 判断是否放行该 IP。
//   - allow 模式：命中列表才放行
//   - deny 模式：命中列表则拒绝
func (a *ACL) Allowed(ipStr string) bool {
	if a == nil || a.Mode == ACLNone {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// 解析不出 IP（比如 Unix socket 场景）时，白名单模式一律拒绝
		return a.Mode == ACLDeny
	}
	hit := false
	for _, n := range a.nets {
		if n.Contains(ip) {
			hit = true
			break
		}
	}
	if a.Mode == ACLAllow {
		return hit
	}
	return !hit
}
