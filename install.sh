#!/usr/bin/env bash
# goproxy 一键安装 / 升级脚本（Linux）
#
# 最简用法（装 systemd 服务）：
#   curl -fsSL https://cdn.jsdelivr.net/gh/Janson-Fang/goproxy_test1@main/install.sh | sudo bash
#
# 升级：重跑同一条命令即可 —— 二进制就地替换（服务正在跑也安全），
#       config.json 保持不动，systemd 单元先备份再重写，
#       原本在运行的服务会自动重启，并确认真的起来了。
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
# 单元文件目录做成可覆盖的：一来某些发行版不放在这里，
# 二来 CI 里要能指到临时目录去验证「先备份再重写」这条路径。
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
# 运行态目录（systemd 单元里的 WorkingDirectory / ReadWritePaths）。
# 同样可覆盖，否则非 root 环境跑服务分支时会卡在 mkdir /var/lib/goproxy。
STATE_DIR="${STATE_DIR:-/var/lib/goproxy}"
MIRROR="${MIRROR:-auto}"
# 实测（2026-09，国内直连 GitHub 下不动 7MB 包的环境）：
#   gh-proxy.com  4.7s  ✓   ghfast.top  12.0s  ✓   ghproxy.net  大文件不可用
# 顺序按实测速度排，全部只做传输加速，内容仍以官方 sha256 校验为准。
MIRROR_LIST="${MIRROR_LIST:-https://gh-proxy.com/ https://ghfast.top/ https://ghproxy.net/}"
WITH_SERVICE=1
RESTART=1

# 只取脚本头部的注释块当帮助信息。
# 之前写的是 2,24p —— 会把 set / REPO= / VERSION= 这些内部语句一起打出来。
usage() {
    sed -n '2,23p' "${BASH_SOURCE[0]:-}" 2>/dev/null ||
        echo "用法: install.sh [--no-service] [--no-restart] [--version vX.Y.Z]"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-service) WITH_SERVICE=0 ;;
        --no-restart) RESTART=0 ;;
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
# 直连优先是因为镜像有缓存，刚发布的版本可能还拉不到，会静默装成旧的。
#
# 用字面量 "direct" 而不是空串表示直连：空串会和「还没探到可用通道」撞车，
# 使 [ -n "$CH" ] 把直连误判成无通道 —— MIRROR=direct 时表现为必定失败。
CANDIDATES=("direct")
case "$MIRROR" in
    auto)            for m in $MIRROR_LIST; do CANDIDATES+=("$m"); done ;;
    direct|none|off) ;;
    *)               CANDIDATES+=("$MIRROR") ;;
esac

chan_prefix() { [ "$1" = "direct" ] && printf '' || printf '%s' "$1"; }
chan_label() {
    case "$1" in
        direct) printf '直连' ;;
        "")     printf '未探到可用通道' ;;
        *)      printf '%s' "$1" ;;
    esac
}

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
                "$(chan_prefix "$m")https://github.com/$REPO/releases/latest" 2>/dev/null || true)
            out=$(printf '%s' "$out" | sed -n 's|.*/tag/||p' | head -1)
        else
            out=$(wget -qS --spider --max-redirect=10 \
                "$(chan_prefix "$m")https://github.com/$REPO/releases/latest" 2>&1 |
                sed -n 's|.*[Ll]ocation: .*/tag/\([^[:space:]]*\).*|\1|p' | tail -1 || true)
        fi
        if [ -n "$out" ]; then printf '%s' "$out"; return 0; fi
    done
    # 退回 API（有些环境 HEAD 被拦，但 GET 正常）
    for m in "${CANDIDATES[@]}"; do
        if dl "$(chan_prefix "$m")https://api.github.com/repos/$REPO/releases/latest" "$TMPTAG/rel" 15; then
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
    if dl "$(chan_prefix "$m")${BASE}/${SUMS}" "$TMP/SHA256SUMS.txt" 8 \
        && grep -qE '^[0-9a-f]{64}' "$TMP/SHA256SUMS.txt" 2>/dev/null; then
        CH="$m"
        ok "下载通道：$(chan_label "$m")"
        break
    fi
done
if [ -z "$CH" ]; then
    warn "直连和镜像都没拿到校验和文件，跳过完整性校验"
fi

# ---------- 5. 下载主包 ----------
# 直连给短超时：93 字节的校验和能秒下，不代表 7MB 的包也下得动。
# 与其让用户干等一分半再回退镜像，不如 35 秒就切过去。
pkg_timeout() { if [ "$1" = "direct" ]; then echo 35; else echo 90; fi; }

info "下载 $PKG（通道：$(chan_label "$CH")）"
if [ -n "$CH" ] && dl "$(chan_prefix "$CH")${BASE}/${PKG}" "$TMP/$PKG" "$(pkg_timeout "$CH")" \
    && [ -s "$TMP/$PKG" ]; then
    :
else
    if [ -n "$CH" ]; then warn "通道 $(chan_label "$CH") 下载失败或过慢，换下一个通道重试"; fi
    GOT=0
    for m in "${CANDIDATES[@]}"; do
        if [ "$m" = "$CH" ]; then continue; fi
        if dl "$(chan_prefix "$m")${BASE}/${PKG}" "$TMP/$PKG" "$(pkg_timeout "$m")" && [ -s "$TMP/$PKG" ]; then
            CH="$m"; GOT=1; ok "改用 $(chan_label "$m") 成功"; break
        fi
    done
    [ "$GOT" = "1" ] || die "所有通道都下载失败。检查版本号是否存在，或手动指定 MIRROR=..."
fi
ok "下载完成（$(du -h "$TMP/$PKG" 2>/dev/null | cut -f1)）"

# ---------- 6. 校验 ----------
if [ -n "$CH" ] && [ -f "$TMP/SHA256SUMS.txt" ] && command -v sha256sum >/dev/null 2>&1; then
    if (cd "$TMP" && sha256sum -c --ignore-missing SHA256SUMS.txt) >/dev/null 2>&1; then
        ok "校验和匹配"
    elif [ "$CH" = "direct" ]; then
        die "校验和不匹配（直连获取）。文件可能在传输中损坏，重跑一次；若仍失败请提 issue"
    else
        # 镜像缓存了旧版本时哈希会对不上，最容易被误判成「文件损坏」，所以单列一条
        die "校验和不匹配。当前走的是加速镜像 $(chan_label "$CH")，多半是它缓存着旧版本（或下载被截断）：
     换直连重试：curl -fsSL .../install.sh | sudo MIRROR=direct bash
     换个镜像：  curl -fsSL .../install.sh | sudo MIRROR=https://gh-proxy.com/ bash
     指定版本：  curl -fsSL .../install.sh | sudo VERSION=$VERSION bash"
    fi
else
    warn "没有校验和文件，跳过完整性校验"
fi

tar -xzf "$TMP/$PKG" -C "$TMP" || die "解压失败"
[ -f "$TMP/goproxy" ] || die "包里没有 goproxy 二进制"

# ---------- 7. 装二进制（支持原地升级） ----------
$SUDO install -d "$BIN_DIR"

# -version 打印的是 "goproxy <version> (commit <commit>)"，取第二个字段
OLD_VER=""
if [ -x "$BIN_DIR/goproxy" ]; then
    OLD_VER=$("$BIN_DIR/goproxy" -version 2>/dev/null | sed -n 's/^goproxy \([^ ]*\).*/\1/p' | head -1)
    [ -n "$OLD_VER" ] || OLD_VER="unknown"
    if [ "$OLD_VER" = "$VERSION" ]; then
        info "已安装 $OLD_VER，重装同一版本"
    else
        info "已安装 $OLD_VER，升级到 $VERSION"
    fi
    # 留一份旧二进制以便回滚。config.json 一直有 .bak，二进制以前没有，
    # 新版本起不来就只能重新下载，有个落点会舒服很多。
    if $SUDO cp -p "$BIN_DIR/goproxy" "$BIN_DIR/goproxy.old" 2>/dev/null; then
        ok "旧二进制已备份到 $BIN_DIR/goproxy.old"
    else
        warn "旧二进制备份失败（不影响本次升级，只是没法一键回滚）"
    fi
else
    info "全新安装 $VERSION"
fi

# 先装成临时名、再 rename 覆盖：
#   · rename 是原子的，不会出现「路径短暂不存在」的窗口 —— 这个窗口里
#     如果服务刚好重启，systemd 会报 203/EXEC 找不到文件。
#   · 服务正在运行时替换也不会 Text file busy：install 本身就会先 unlink 目标，
#     加上 rename 之后，运行中的进程继续持有旧 inode 照常跑完，
#     新起的进程才拿到新文件。
$SUDO install -m 0755 "$TMP/goproxy" "$BIN_DIR/goproxy.new"
$SUDO mv -f "$BIN_DIR/goproxy.new" "$BIN_DIR/goproxy"
ok "已安装到 $BIN_DIR/goproxy"

# 装完立刻验一下新二进制跑不跑得起来。放到这里是为了在重启服务之前
# 就暴露问题 —— 否则要等 systemd 重启失败才回头查，回滚窗口也更大。
if ! VER_OUT=$("$BIN_DIR/goproxy" -version 2>&1); then
    warn "新二进制执行失败：$VER_OUT"
    if [ -x "$BIN_DIR/goproxy.old" ]; then
        warn "回滚到上一个版本："
        warn "  sudo cp -p $BIN_DIR/goproxy.old $BIN_DIR/goproxy"
    else
        warn "没有可回滚的备份（本次是全新安装）"
    fi
    exit 1
fi
printf '%s\n' "$VER_OUT"
NEW_VER=$(printf '%s\n' "$VER_OUT" | sed -n 's/^goproxy \([^ ]*\).*/\1/p' | head -1)

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
SVC_WAS_ACTIVE=0
SVC_RESTARTED=0
UNIT="$SYSTEMD_DIR/goproxy.service"

if [ "$WITH_SERVICE" = "1" ] && command -v systemctl >/dev/null 2>&1; then
    # 先记下服务当前是不是在跑，决定第 10 步要不要重启它。
    # 不在跑就不去启动 —— 用户可能是特意停的（比如还在改配置）。
    if systemctl is-active --quiet goproxy 2>/dev/null; then
        SVC_WAS_ACTIVE=1
    fi

    if ! id -u goproxy >/dev/null 2>&1; then
        $SUDO useradd --system --no-create-home --shell /usr/sbin/nologin goproxy 2>/dev/null || true
    fi
    $SUDO install -d "$STATE_DIR"
    $SUDO chown goproxy:goproxy "$STATE_DIR" 2>/dev/null || true
    $SUDO install -d "$SYSTEMD_DIR"

    # 单元文件是要覆盖的（ExecStart 里带着本次的 BIN_DIR / CONFIG_DIR）。
    # 但有人会往里加 Environment=、LimitNOFILE= 之类的东西，
    # 所以先备份一份，覆盖后还能对照把自定义项找回来。
    if [ -f "$UNIT" ]; then
        if $SUDO cp -p "$UNIT" "$UNIT.bak" 2>/dev/null; then
            warn "$UNIT 已存在，已备份为 $UNIT.bak（有自定义项请从这里取回）"
        else
            warn "$UNIT 已存在但备份失败，覆盖后原有自定义项会丢"
        fi
    fi

    $SUDO tee "$UNIT" >/dev/null <<EOF
[Unit]
Description=goproxy reverse proxy
After=network.target

[Service]
Type=simple
User=goproxy
ExecStart=$BIN_DIR/goproxy -c $CONFIG_DIR/config.json
WorkingDirectory=$STATE_DIR
Restart=always
RestartSec=3

# 不加这个，绑定 80/443 会 permission denied
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$STATE_DIR

[Install]
WantedBy=multi-user.target
EOF

    # 容器 / 非 systemd 环境里 daemon-reload 会失败，不该因此中断安装
    $SUDO systemctl daemon-reload 2>/dev/null ||
        warn "systemctl daemon-reload 失败（可能不在 systemd 环境），需要时请手动执行"
    ok "已写入 $UNIT"
fi

# ---------- 10. 升级后重启 ----------
# 这一步不做事的话，「重跑 install.sh」就只是把磁盘上的文件换了 ——
# 运行中的进程继续跑旧代码，看起来升级成功其实没生效。
if [ "$WITH_SERVICE" = "1" ] && command -v systemctl >/dev/null 2>&1 && [ "$SVC_WAS_ACTIVE" = "1" ]; then
    if [ "$RESTART" = "1" ]; then
        info "服务原本在运行，重启以加载新版本"
        $SUDO systemctl restart goproxy || true

        # 等它真的起来。restart 返回 0 不等于进程活着：
        # Type=simple 下进程起来后立刻挂掉，restart 一样算成功。
        ST=0
        i=0
        while [ "$i" -lt 20 ]; do
            if systemctl is-active --quiet goproxy 2>/dev/null; then ST=1; break; fi
            i=$((i + 1))
            sleep 0.5
        done

        if [ "$ST" = "1" ]; then
            ok "服务已重启，确认正在运行"
            SVC_RESTARTED=1
        else
            warn "服务重启后没能起来。回滚到上一个版本："
            warn "  sudo cp -p $BIN_DIR/goproxy.old $BIN_DIR/goproxy && sudo systemctl restart goproxy"
            warn "看日志定位： sudo journalctl -u goproxy -n 50 --no-pager"
            exit 1
        fi
    else
        warn "按要求跳过了重启（--no-restart）。服务仍在跑旧版本，记得手动执行："
        warn "  sudo systemctl restart goproxy"
    fi
fi

# ---------- 11. 收尾 ----------
echo
if [ "$SVC_RESTARTED" = "1" ]; then
    echo "升级完成：$OLD_VER -> $NEW_VER，服务已重启生效。"
    echo "  回滚    sudo cp -p $BIN_DIR/goproxy.old $BIN_DIR/goproxy && sudo systemctl restart goproxy"
else
    echo "安装完成。"
fi
echo "  二进制    $BIN_DIR/goproxy"
echo "  配置文件  $CONFIG_DIR/config.json"
if [ -n "$OLD_VER" ]; then
    echo "  旧二进制  $BIN_DIR/goproxy.old（回滚用）"
fi
echo
if [ "$SVC_RESTARTED" = "1" ]; then
    echo "看日志：sudo journalctl -u goproxy -f"
    echo "看版本：$BIN_DIR/goproxy -version"
elif [ "$WITH_SERVICE" = "1" ] && command -v systemctl >/dev/null 2>&1; then
    echo "下一步："
    echo "  1. 改配置：把每条路由的 target 指向你自己的后端"
    echo "  2. 前台试跑：$BIN_DIR/goproxy -c $CONFIG_DIR/config.json（看有没有报错）"
    echo "  3. 正式启动：sudo systemctl enable --now goproxy"
    echo "     看日志：sudo journalctl -u goproxy -f"
else
    echo "下一步："
    echo "  1. 改配置：把每条路由的 target 指向你自己的后端"
    echo "  2. 后台运行：nohup $BIN_DIR/goproxy -c $CONFIG_DIR/config.json &"
fi
echo
echo "卸载："
echo "  sudo systemctl disable --now goproxy 2>/dev/null"
echo "  sudo rm -f $BIN_DIR/goproxy $BIN_DIR/goproxy.old $UNIT"
echo "  sudo rm -rf $CONFIG_DIR"
