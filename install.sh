#!/usr/bin/env bash
# goproxy 一键安装脚本（Linux）
#
# 最简用法（装 systemd 服务）：
#   curl -fsSL https://cdn.jsdelivr.net/gh/Janson-Fang/goproxy_test1@main/install.sh | sudo bash
#
# 指定版本：
#   curl -fsSL .../install.sh | sudo VERSION=v0.3.0 bash
#
# 只装二进制、不装 systemd（容器里用这个）：
#   curl -fsSL .../install.sh | sudo bash -s -- --no-service
#
# 不想用 root（装到家目录）：
#   curl -fsSL .../install.sh | BIN_DIR=$HOME/.local/bin CONFIG_DIR=$HOME/.goproxy bash -s -- --no-service
#
# 下载慢 / 连不上 GitHub 时（国内常见）：
#   MIRROR=auto   默认值，先试直连，不通自动切加速镜像
#   MIRROR=direct 强制直连，不走镜像
#   MIRROR=https://ghfast.top/  指定自己的镜像前缀

set -euo pipefail

REPO="${REPO:-Janson-Fang/goproxy_test1}"
VERSION="${VERSION:-latest}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/goproxy}"
MIRROR="${MIRROR:-auto}"
# 实测（2026-09，国内直连 GitHub 下不动 7MB 包的环境）：
#   gh-proxy.com  4.7s  ✓   ghfast.top  12.0s  ✓   ghproxy.net  大文件不可用
# 顺序按实测速度排，全部只做传输加速，内容仍以官方 sha256 校验为准。
MIRROR_LIST="${MIRROR_LIST:-https://gh-proxy.com/ https://ghfast.top/ https://ghproxy.net/}"
WITH_SERVICE=1

usage() {
    sed -n '2,24p' "${BASH_SOURCE[0]:-}" 2>/dev/null || echo "用法: install.sh [--no-service] [--version vX.Y.Z]"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-service) WITH_SERVICE=0 ;;
        --version)    VERSION="${2:?--version 后面要跟版本号}"; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "未知参数: $1（--help 看用法）" >&2; exit 1 ;;
    esac
    shift
done

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m OK\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mfail\033[0m %s\n' "$*" >&2; exit 1; }

# ---------- 1. 环境检查 ----------
[ "$(uname -s)" = "Linux" ] || die "这个脚本只支持 Linux；其它系统请用 Docker 镜像"

case "$(uname -m)" in
    x86_64|amd64)   ARCH=amd64 ;;
    aarch64|arm64)  ARCH=arm64 ;;
    *) die "不支持的 CPU 架构: $(uname -m)（目前只提供 amd64 / arm64 的预编译包）" ;;
esac

command -v tar >/dev/null || die "缺少 tar"
DL=""
for c in curl wget; do
    if command -v "$c" >/dev/null 2>&1; then DL=$c; break; fi
done
[ -n "$DL" ] || die "需要 curl 或 wget"

# 统一的下载函数：镜像站经常返回一个好看的 HTML 错误页但状态码 200，
# 所以调用方还要自己检查内容，不能只看返回码。
dl() { # dl <url> <输出文件> [超时秒]
    local url="$1" out="$2" t="${3:-30}"
    rm -f "$out"
    if [ "$DL" = "curl" ]; then
        # --speed-limit/--speed-time：20 秒内平均速度低于 2KB/s 就放弃。
        # 没有这个，碰到「连得上但龟速」的通道要干等到 --max-time 才失败。
        curl -fsSL --connect-timeout 5 --max-time "$t" \
            --speed-limit 2048 --speed-time 20 -o "$out" "$url" 2>/dev/null
    else
        wget -q -T "$t" --read-timeout=20 -O "$out" "$url" 2>/dev/null
    fi
}

# 只有确实写不进去时才要求 sudo —— 装到自家目录的场景不该被拦
SUDO=""
if [ "$(id -u)" -ne 0 ] && [ ! -w "$BIN_DIR" ]; then
    command -v sudo >/dev/null 2>&1 ||
        die "没有写 $BIN_DIR 的权限，且系统里没有 sudo。改用 BIN_DIR=\$HOME/.local/bin CONFIG_DIR=\$HOME/.goproxy"
    SUDO=sudo
fi

# ---------- 2. 下载通道：直连优先，不通再走加速镜像 ----------
# 空串代表直连。之所以直连优先，是因为镜像有缓存，
# 刚发布的版本可能还拉不到，会静默装成旧的。
CANDIDATES=("")
case "$MIRROR" in
    auto)            for m in $MIRROR_LIST; do CANDIDATES+=("$m"); done ;;
    direct|none|off) ;;
    *)               CANDIDATES+=("$MIRROR") ;;
esac

# ---------- 3. 解析版本号 ----------
# 走 /releases/latest 的 302 跳转拿 tag，而不是 GitHub API：
#   · 不占未认证 API 的 60 次/小时额度
#   · 镜像对 github.com 路径的支持比 api.github.com 好得多
#     （实测 ghfast.top 能加速 Release 下载，但转发 API 会返回 Invalid input.）
# 两种方式都遍历所有通道，任一成功即可。
resolve_latest() {
    local m out
    for m in "${CANDIDATES[@]}"; do
        if [ "$DL" = "curl" ]; then
            out=$(curl -fsSLI -o /dev/null --max-time 15 -w '%{url_effective}' \
                "${m}https://github.com/$REPO/releases/latest" 2>/dev/null || true)
            out=$(printf '%s' "$out" | sed -n 's|.*/tag/||p' | head -1)
        else
            out=$(wget -qS --spider --max-redirect=10 \
                "${m}https://github.com/$REPO/releases/latest" 2>&1 |
                sed -n 's|.*[Ll]ocation: .*/tag/\([^[:space:]]*\).*|\1|p' | tail -1 || true)
        fi
        if [ -n "$out" ]; then printf '%s' "$out"; return 0; fi
    done
    # 退回 API（有些环境 HEAD 被拦，但 GET 正常）
    for m in "${CANDIDATES[@]}"; do
        if dl "${m}https://api.github.com/repos/$REPO/releases/latest" "$TMPTAG/rel" 15; then
            out=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$TMPTAG/rel" | head -1)
            if [ -n "$out" ]; then printf '%s' "$out"; return 0; fi
        fi
    done
    return 1
}

if [ "$VERSION" = "latest" ]; then
    TMPTAG=$(mktemp -d)
    trap 'rm -rf "$TMPTAG"' EXIT
    V=$(resolve_latest || true)
    rm -rf "$TMPTAG"; trap - EXIT
    [ -n "$V" ] || die "取不到最新版本号（可能还没发过 Release），请用 VERSION=v0.3.0 手动指定"
    VERSION="$V"
fi
info "安装 goproxy $VERSION（linux/$ARCH）"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

BASE="https://github.com/$REPO/releases/download/$VERSION"
PKG="goproxy-linux-$ARCH.tar.gz"
SUMS="SHA256SUMS-$ARCH.txt"

# ---------- 4. 探测可用通道 ----------
# 拿校验和文件做探针：只有几十字节，秒级就能判断这条路通不通。
CH=""
for m in "${CANDIDATES[@]}"; do
    if dl "${m}${BASE}/${SUMS}" "$TMP/SHA256SUMS.txt" 8 \
        && grep -qE '^[0-9a-f]{64}' "$TMP/SHA256SUMS.txt" 2>/dev/null; then
        CH="$m"
        if [ -z "$m" ]; then ok "下载通道：直连 GitHub"
        else ok "下载通道：加速镜像 $m"; fi
        break
    fi
done
if [ -z "$CH" ]; then
    warn "直连和镜像都没拿到校验和文件，跳过完整性校验"
fi

# ---------- 5. 下载主包 ----------
# 直连给短超时：93 字节的校验和能秒下，不代表 7MB 的包也下得动。
# 与其让用户干等一分半再回退镜像，不如 35 秒就切过去。
pkg_timeout() { if [ -z "$1" ]; then echo 35; else echo 90; fi; }

info "下载 $PKG（通道：${CH:-直连}）"
if [ -n "$CH" ] && dl "${CH}${BASE}/${PKG}" "$TMP/$PKG" "$(pkg_timeout "$CH")" && [ -s "$TMP/$PKG" ]; then
    :
else
    warn "通道 ${CH:-直连} 下载失败或过慢，换下一个通道重试"
    GOT=0
    for m in "${CANDIDATES[@]}"; do
        [ "$m" = "$CH" ] && continue
        label="${m:-直连}"
        if dl "${m}${BASE}/${PKG}" "$TMP/$PKG" "$(pkg_timeout "$m")" && [ -s "$TMP/$PKG" ]; then
            CH="$m"; GOT=1; ok "改用 $label 成功"; break
        fi
    done
    [ "$GOT" = "1" ] || die "所有通道都下载失败。检查版本号是否存在，或手动指定 MIRROR=..."
fi
ok "下载完成（$(du -h "$TMP/$PKG" 2>/dev/null | cut -f1)）"

# ---------- 6. 校验 ----------
if [ -n "$CH" ] && [ -f "$TMP/SHA256SUMS.txt" ] && command -v sha256sum >/dev/null 2>&1; then
    if (cd "$TMP" && sha256sum -c --ignore-missing SHA256SUMS.txt) >/dev/null 2>&1; then
        ok "校验和匹配"
    else
        # 镜像缓存了旧版本时哈希会对不上，这是最容易被误判成「文件损坏」的情况
        if [ -n "$CH" ]; then
            die "校验和不匹配。当前走的是加速镜像 ${CH}，多半是它还缓存着旧版本（或下载被截断）：
     换直连重试：curl -fsSL .../install.sh | sudo MIRROR=direct bash
     换个镜像：  curl -fsSL .../install.sh | sudo MIRROR=https://gh-proxy.com/ bash
     指定版本：  curl -fsSL .../install.sh | sudo VERSION=$VERSION bash"
        fi
        die "校验和不匹配，文件可能已被替换，已中止安装"
    fi
else
    warn "没有校验和文件，跳过完整性校验"
fi

tar -xzf "$TMP/$PKG" -C "$TMP" || die "解压失败"
[ -f "$TMP/goproxy" ] || die "包里没有 goproxy 二进制"

# ---------- 7. 装二进制 ----------
$SUDO install -d "$BIN_DIR"
$SUDO install -m 0755 "$TMP/goproxy" "$BIN_DIR/goproxy"
ok "已安装到 $BIN_DIR/goproxy"
"$BIN_DIR/goproxy" -version

# ---------- 8. 配置文件 ----------
$SUDO install -d "$CONFIG_DIR"
if [ -f "$CONFIG_DIR/config.json" ]; then
    warn "$CONFIG_DIR/config.json 已存在，保持不动（新版本示例放在 config.json.example）"
    $SUDO install -m 0644 "$TMP/config.example.json" "$CONFIG_DIR/config.json.example"
else
    $SUDO install -m 0644 "$TMP/config.example.json" "$CONFIG_DIR/config.json"
    ok "已生成配置 $CONFIG_DIR/config.json"
    warn "这是示例配置，后端指向 127.0.0.1:9001 等本机端口，先改成你自己的后端"
fi

# ---------- 9. systemd 服务 ----------
if [ "$WITH_SERVICE" = "1" ] && command -v systemctl >/dev/null 2>&1; then
    if ! id -u goproxy >/dev/null 2>&1; then
        $SUDO useradd --system --no-create-home --shell /usr/sbin/nologin goproxy 2>/dev/null || true
    fi
    $SUDO install -d /var/lib/goproxy
    $SUDO chown goproxy:goproxy /var/lib/goproxy 2>/dev/null || true

    $SUDO tee /etc/systemd/system/goproxy.service >/dev/null <<EOF
[Unit]
Description=goproxy reverse proxy
After=network.target

[Service]
Type=simple
User=goproxy
ExecStart=$BIN_DIR/goproxy -c $CONFIG_DIR/config.json
WorkingDirectory=/var/lib/goproxy
Restart=always
RestartSec=3

# 不加这个，绑定 80/443 会 permission denied
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/goproxy

[Install]
WantedBy=multi-user.target
EOF
    $SUDO systemctl daemon-reload
    ok "已写入 /etc/systemd/system/goproxy.service"
fi

# ---------- 10. 收尾 ----------
echo
echo "安装完成。"
echo "  二进制    $BIN_DIR/goproxy"
echo "  配置文件  $CONFIG_DIR/config.json"
echo
echo "下一步："
echo "  1. 改配置：把每条路由的 target 指向你自己的后端"
echo "  2. 前台试跑：$BIN_DIR/goproxy -c $CONFIG_DIR/config.json（看有没有报错）"
if [ "$WITH_SERVICE" = "1" ] && command -v systemctl >/dev/null 2>&1; then
    echo "  3. 正式启动：sudo systemctl enable --now goproxy"
    echo "     看日志：sudo journalctl -u goproxy -f"
else
    echo "  3. 后台运行：nohup $BIN_DIR/goproxy -c $CONFIG_DIR/config.json &"
fi
echo
echo "卸载："
echo "  sudo systemctl disable --now goproxy 2>/dev/null"
echo "  sudo rm -f $BIN_DIR/goproxy /etc/systemd/system/goproxy.service"
echo "  sudo rm -rf $CONFIG_DIR"
