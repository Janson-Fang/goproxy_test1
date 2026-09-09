#!/usr/bin/env bash
# goproxy 一键安装脚本（Linux）
#
# 最简用法（会装 systemd 服务）：
#   curl -fsSL https://raw.githubusercontent.com/Janson-Fang/goproxy_test1/main/install.sh | sudo bash
#
# 指定版本：
#   curl -fsSL .../install.sh | sudo VERSION=v0.3.0 bash
#
# 只装二进制、不装 systemd（容器里用这个）：
#   curl -fsSL .../install.sh | sudo bash -s -- --no-service
#
# 不想用 root（装到自己的家目录）：
#   curl -fsSL .../install.sh | BIN_DIR=$HOME/.local/bin CONFIG_DIR=$HOME/.goproxy bash -s -- --no-service

set -euo pipefail

REPO="${REPO:-Janson-Fang/goproxy_test1}"
VERSION="${VERSION:-latest}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/goproxy}"
WITH_SERVICE=1

usage() {
    sed -n '2,20p' "${BASH_SOURCE[0]:-}" 2>/dev/null ||
        echo "用法: [VERSION=vX.Y.Z] [BIN_DIR=...] [CONFIG_DIR=...] install.sh [--no-service]"
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

# 只有确实写不进去时才要求 sudo —— 装到自家目录的场景不该被拦
SUDO=""
if [ "$(id -u)" -ne 0 ] && [ ! -w "$BIN_DIR" ]; then
    command -v sudo >/dev/null 2>&1 ||
        die "没有写 $BIN_DIR 的权限，且系统里没有 sudo。改用 BIN_DIR=\$HOME/.local/bin CONFIG_DIR=\$HOME/.goproxy"
    SUDO=sudo
fi

# ---------- 2. 解析版本号 ----------
if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
        sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
    [ -n "$VERSION" ] || die "取不到最新版本号（可能还没发过 Release），请用 VERSION=v0.3.0 手动指定"
fi
info "安装 goproxy $VERSION（linux/$ARCH）"

# ---------- 3. 下载 ----------
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

BASE="https://github.com/$REPO/releases/download/$VERSION"
PKG="goproxy-linux-$ARCH.tar.gz"
info "下载 $PKG"
if [ "$DL" = "curl" ]; then
    curl -fsSL -o "$TMP/$PKG" "$BASE/$PKG" || die "下载失败：版本 $VERSION 不存在，或网络不通"
    curl -fsSL -o "$TMP/SHA256SUMS.txt" "$BASE/SHA256SUMS-$ARCH.txt" 2>/dev/null || true
else
    wget -q -O "$TMP/$PKG" "$BASE/$PKG" || die "下载失败：版本 $VERSION 不存在，或网络不通"
    wget -q -O "$TMP/SHA256SUMS.txt" "$BASE/SHA256SUMS-$ARCH.txt" 2>/dev/null || true
fi

# ---------- 4. 校验 ----------
if [ -f "$TMP/SHA256SUMS.txt" ] && command -v sha256sum >/dev/null 2>&1; then
    (cd "$TMP" && sha256sum -c --ignore-missing SHA256SUMS.txt) \
        && ok "校验和匹配" \
        || die "校验和不匹配，文件可能被替换，已中止安装"
else
    warn "没有拿到校验和文件，跳过完整性校验"
fi

tar -xzf "$TMP/$PKG" -C "$TMP" || die "解压失败"
[ -f "$TMP/goproxy" ] || die "包里没有 goproxy 二进制"

# ---------- 5. 装二进制 ----------
$SUDO install -d "$BIN_DIR"
$SUDO install -m 0755 "$TMP/goproxy" "$BIN_DIR/goproxy"
ok "已安装到 $BIN_DIR/goproxy"
"$BIN_DIR/goproxy" -version

# ---------- 6. 配置文件 ----------
$SUDO install -d "$CONFIG_DIR"
if [ -f "$CONFIG_DIR/config.json" ]; then
    warn "$CONFIG_DIR/config.json 已存在，保持不动（新版本示例放在 config.json.example）"
    $SUDO install -m 0644 "$TMP/config.example.json" "$CONFIG_DIR/config.json.example"
else
    $SUDO install -m 0644 "$TMP/config.example.json" "$CONFIG_DIR/config.json"
    ok "已生成配置 $CONFIG_DIR/config.json"
    warn "这是示例配置，后端指向 127.0.0.1:9001 等本机端口，先改成你自己的后端"
fi

# ---------- 7. systemd 服务 ----------
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

# ---------- 8. 收尾 ----------
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
