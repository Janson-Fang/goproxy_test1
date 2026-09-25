#!/usr/bin/env bash
# goproxy 一键安装 / 升级脚本（Linux）
#
# 最简用法（装 systemd 服务）：
#   curl -fsSL https://cdn.jsdelivr.net/gh/Janson-Fang/goproxy_test1@main/install.sh | sudo bash
#
# 升级：重跑同一条命令即可 —— 二进制就地替换（服务正在跑也安全），
#       配置数据库保持不动，systemd 单元先备份再重写，
#       原本在运行的服务会自动重启，并确认真的起来了。
#
# 指定版本：
#   curl -fsSL .../install.sh | sudo VERSION=v0.3.0 bash
#
# 只装二进制、不装 systemd（容器里用这个）：
#   curl -fsSL .../install.sh | sudo bash -s -- --no-service
#
# 无人值守安装（CI / 容器 / 批量部署）—— 跳过设置管理员账号的交互：
#   curl -fsSL .../install.sh | sudo bash -s -- --no-admin-prompt
#
# 不想用 root（装到家目录）：
#   curl -fsSL .../install.sh | BIN_DIR=$HOME/.local/bin CONFIG_DIR=$HOME/.goproxy bash -s -- --no-service
#
# 下载慢 / 连不上 GitHub 时（国内常见）：
#   MIRROR=auto   默认值，先试直连，不通自动切加速镜像
#   MIRROR=direct 强制直连，不走镜像
#   MIRROR=https://ghfast.top/  指定自己的镜像前缀
#
# 首次安装会引导你设置一个管理账号（用户名 + 密码）。控制台需要登录才能用，
# 从 v0.6.0 起连本机访问也不例外。密码不会明文落地，只保存 bcrypt 哈希。
# 之后想改密码：控制台没有改密码的界面（那会让明文经过一个本该只读的接口），走命令行：
#   goproxy -c 配置库 -config-export cfg.json   # 导出
#   用 goproxy -hash-password '新密码' 算出哈希，填进 cfg.json 的 admin_users
#   改完再 -config-import cfg.json 导回并重启。

set -euo pipefail

REPO="${REPO:-Janson-Fang/goproxy_test1}"
VERSION="${VERSION:-latest}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/goproxy}"
# 配置数据库。v0.9.0 起**它**才是配置的真源，config.json 不再是。
#
# config.json 只剩一个用途：库里还没有配置时作为「种子」被导入一次。
# 导入之后它就不再被读取了 —— 所以升级时绝对不能用它去覆盖库里那份
# 已经被控制台改过的配置，这一步下面有判断。
CONFIG_DB="${CONFIG_DB:-$CONFIG_DIR/goproxy.db}"
# 旧版二进制的配置文件路径（见下面 CONFIG_BACKEND 的说明）。
CONFIG_FILE="$CONFIG_DIR/config.json"
# 配置源由**装出来的那个二进制**决定，不是由脚本决定，所以下面探测一次再分流：
#   sqlite —— v0.9.0 起，`-c` 指向库文件，有 -config-import / -config-export
#   json   —— v0.8.x 及更早，`-c` 指向 JSON 文件，没有那两个开关
#
# 为什么必须有这条分支：脚本给「最新版」写，但 VERSION= 允许装任意历史版本，
# 而且 Release 刚发出来之前 latest 还停在上一个 tag。硬按库流程走的话，
# 对旧二进制调 -config-import 会直接报「flag provided but not defined」，
# 现象是「装不上」，真正的原因却是版本不匹配 —— 极难查，所以这里主动分辨。
CONFIG_BACKEND="sqlite"
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
# 设成 1 就完全跳过「引导设置管理员账号」那一步。
# CI / 容器 / 无人值守安装必须开它 —— 否则脚本会挂在等待终端输入上。
# 也可以用环境变量 NO_ADMIN_PROMPT=1 达到同样效果。
NO_ADMIN_PROMPT="${NO_ADMIN_PROMPT:-0}"

# 只取脚本头部的注释块当帮助信息。
#
# 之前写的是 2,23p，两个毛病：一是会把 set / REPO= / VERSION= 这些内部语句
# 一起打出来，二是范围写死 —— 往头部补几行说明，帮助里就会**少掉最后几行**
# （v0.6.0 加「引导设置管理员账号」那段时就踩到了，静默截断，没有任何报错）。
#
# 现在改成「从第 2 行读到最后一个连续注释行为止」：范围跟着内容走，
# 补注释不用再来改这个数字。
usage() {
    sed -n '2,/^[^#]/p' "${BASH_SOURCE[0]:-}" 2>/dev/null | sed '$d' ||
        echo "用法: install.sh [--no-service] [--no-restart] [--version vX.Y.Z] [--no-admin-prompt]"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-service)      WITH_SERVICE=0 ;;
        --no-restart)      RESTART=0 ;;
        --no-admin-prompt) NO_ADMIN_PROMPT=1 ;;
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

# 探测这个二进制支不支持 SQLite 配置源（即有没有 -config-import / -config-export）。
#
# 用 -h 的输出而不是比版本号：比版本号要在这里重新实现一遍「v0.9.0 > v0.8.0」的
# 语义比较，而 flags 是二进制的自述，永远是对的。
#
# 两个细节：
#   · 先把输出收进变量再匹配，不走管道 —— 脚本开了 pipefail，而 -h 的退出码是 2，
#     走管道会让整条管道判成失败，结果永远是 json 分支（看起来「探测没生效」）。
#   · `|| true` 是为了不让 set -e 在 -h 的非 0 退出码上把脚本打死。
USAGE_PROBE=$("$BIN_DIR/goproxy" -h 2>&1 || true)
case "$USAGE_PROBE" in
    *-config-import*) CONFIG_BACKEND="sqlite" ;;
    *)                CONFIG_BACKEND="json" ;;
esac
unset USAGE_PROBE

# 单元文件 / 收尾提示里的 -c 指哪个文件，由上面探测出的配置源决定。
if [ "$CONFIG_BACKEND" = "sqlite" ]; then
    SERVICE_CONFIG="$CONFIG_DB"
else
    SERVICE_CONFIG="$CONFIG_FILE"
fi

# ---------- 8. 配置数据库 ----------
$SUDO install -d "$CONFIG_DIR"

# gen_admin_hash <密码> —— 调 goproxy 自己的 -hash-password 算 bcrypt。
#
# 为什么不在这里内联别的实现：密码哈希一旦算错（cost 不对、salt 生成有 bug、
# 用了没法验的编码），症状是「登录永远失败」而且极难排查。
# 让二进制自己算，服务端用什么校验、这里就生成什么，不可能不一致。
gen_admin_hash() {
    "$BIN_DIR/goproxy" -hash-password "$1" 2>/dev/null | head -n1
}

# 把 admin_users 注入 config.json。优先用 python3（几乎所有发行版都有），
# 没有就退回 sed —— 示例配置里 admin_users 恰好是空数组 "admin_users": []，
# 这个形态足够稳定，不会误伤别处。
inject_admin_user() { # inject_admin_user <文件> <用户名> <哈希>
    local f="$1" u="$2" h="$3"
    if command -v python3 >/dev/null 2>&1; then
        $SUDO python3 - "$f" "$u" "$h" <<'PYEOF'
import json, sys
path, user, phash = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as fh:
    cfg = json.load(fh)
cfg.setdefault("admin_users", [])
cfg["admin_users"] = [u for u in cfg["admin_users"] if u.get("username") != user]
cfg["admin_users"].append({"username": user, "password_hash": phash})
with open(path, "w") as fh:
    json.dump(cfg, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
PYEOF
    else
        # 转义哈希与用户名里的 / & \ 以适配 sed 的替换语义
        local eu eh
        eu=$(printf '%s' "$u" | sed 's/[&/\\]/\\&/g')
        eh=$(printf '%s' "$h" | sed 's/[&/\\]/\\&/g')
        $SUDO sed -i \
            "s|\"admin_users\"[[:space:]]*:[[:space:]]*\[\]|\"admin_users\": [{\"username\": \"$eu\", \"password_hash\": \"$eh\"}]|" \
            "$f"
    fi
}

# 交互式引导设置一个管理员账号。
#
# 从 /dev/tty 读而不是 stdin：这个脚本最常见的用法是
#   curl ... | sudo bash
# 那时 stdin 是**脚本自身的管道**，对它 read 会吃掉还没执行的脚本文本。
# /dev/tty 指向真正的终端，不受管道影响。非交互环境（CI、容器）下
# /dev/tty 打不开，所以必须处理好这个分支。
prompt_admin_credentials() { # prompt_admin_credentials <文件>
    local f="$1" user pw pw2 hash

    if [ "${NO_ADMIN_PROMPT:-0}" = "1" ]; then
        return 1
    fi
    # 有 /dev/tty 且可读才进入交互；否则交给调用方打非交互提示。
    if [ ! -r /dev/tty ]; then
        return 1
    fi

    printf '\n' > /dev/tty
    printf '%s\n' "----------------------------------------" > /dev/tty
    printf '%s\n' " 设置管理控制台的登录账号" > /dev/tty
    printf '%s\n' "----------------------------------------" > /dev/tty
    printf '%s\n' "控制台现在需要用户名 + 密码登录。请现在设置一个，" > /dev/tty
    printf '%s\n' "否则从浏览器打开会看到「还没有配置管理员账号」。" > /dev/tty
    printf '%s\n' "（以后也可以用: goproxy -hash-password '密码' 自己改）" > /dev/tty
    printf '\n' > /dev/tty

    printf '用户名 [admin]: ' > /dev/tty
    read -r user < /dev/tty || return 1
    [ -n "$user" ] || user="admin"

    # read -s：不回显密码。两次输入以防打错 —— 密码是要进 bcrypt 的，
    # 打错了自己看不出来，只能靠登录失败才发现。
    while :; do
        printf '密码: ' > /dev/tty
        read -rs pw < /dev/tty || return 1
        printf '\n' > /dev/tty
        if [ -z "$pw" ]; then
            printf '密码不能为空，请重新输入。\n' > /dev/tty
            continue
        fi
        printf '再输一次: ' > /dev/tty
        read -rs pw2 < /dev/tty || return 1
        printf '\n' > /dev/tty
        if [ "$pw" = "$pw2" ]; then
            break
        fi
        printf '两次输入不一致，请重新输入。\n' > /dev/tty
    done

    hash=$(gen_admin_hash "$pw")
    unset pw pw2
    if [ -z "$hash" ]; then
        warn "生成密码哈希失败，请稍后手动执行: goproxy -hash-password '密码'"
        return 1
    fi
    if ! inject_admin_user "$f" "$user" "$hash"; then
        warn "写入 admin_users 失败，请手动编辑 $f"
        return 1
    fi
    ok "已设置管理账号「$user」（密码只以 bcrypt 哈希形式保存，脚本不留副本）"
    return 0
}

if [ "$CONFIG_BACKEND" = "json" ]; then
    # ---- 旧版二进制（v0.8.x 及更早）：配置就是 config.json 本身 ----
    #
    # 保留原行为：文件在就不动它，不在就铺一份示例并引导设账号。
    # 这条分支存在的意义是让 `VERSION=v0.3.0` 这类固定版本安装照旧可用 ——
    # 用脚本的新旧去决定装法，而不是用装出来的那个二进制的能力，是不对的。
    info "$NEW_VER 用的是 JSON 配置文件（该版本还不支持 SQLite 配置源）"
    if [ -f "$CONFIG_FILE" ]; then
        ok "$CONFIG_FILE 已存在，保持不动"
    else
        $SUDO install -m 0644 "$TMP/config.example.json" "$CONFIG_FILE"
        ok "已生成配置 $CONFIG_FILE"

        # 示例配置里没有 admin_token，历史版本因此让人从浏览器打开时只看到
        # 一张「已拒绝所有外部请求」的说明页（用户反馈过「没见到登录界面」）。
        if ! prompt_admin_credentials "$CONFIG_FILE"; then
            warn "尚未设置管理账号 —— 控制台现在需要用户名 + 密码才能登录。"
            warn "补法：重新运行本脚本，在交互提示里设置；或手动编辑 $CONFIG_FILE。"
        fi
        warn "这是示例配置，后端指向 127.0.0.1:9001 等本机端口，先改成你自己的后端"
    fi
    $SUDO install -m 0644 "$TMP/config.example.json" "$CONFIG_DIR/config.json.example"
fi

if [ "$CONFIG_BACKEND" = "sqlite" ]; then
# 数据库已经在 → 升级场景，一律不碰。
#
# 判据从「config.json 存不存在」换成了「数据库存不存在」，这一点很关键：
# config.json 导入之后就不再被读取，它可能早就过时了（控制台里改过的路由都在库里）。
# 按老判据走，一次重跑安装就会拿那份陈旧的文件把库里真实的配置覆盖掉。
if [ -e "$CONFIG_DB" ]; then
    ok "$CONFIG_DB 已存在，保持不动"
    $SUDO install -m 0644 "$TMP/config.example.json" "$CONFIG_DIR/config.json.example"
else
    # 库里还没有配置。这一步决定「装完之后控制台能不能进去」，
    # 所以先把种子文件备好（老配置就沿用，全新安装就铺一份示例），再导入。
    if [ -f "$CONFIG_DIR/config.json" ]; then
        warn "检测到旧版配置文件 $CONFIG_DIR/config.json，将导入配置数据库（只导这一次）"

        # 老配置升级上来的情况：以前 admin_token 是唯一凭据，现在用户也可能
        # 想改用账号登录。这里只在**确实一个凭据都没有**时才提示 ——
        # 已经有 admin_token 的环境照样能用（Bearer 仍然有效），不该被打扰。
        if ! grep -q '"admin_users"[[:space:]]*:[[:space:]]*\[[^]]' "$CONFIG_DIR/config.json" 2>/dev/null &&
           ! grep -q '"admin_token"[[:space:]]*:[[:space:]]*"[^"]' "$CONFIG_DIR/config.json" 2>/dev/null; then
            warn "检测到这份配置里没有任何管理员凭据 —— 管理接口会拒绝所有请求。"
            if ! prompt_admin_credentials "$CONFIG_DIR/config.json"; then
                warn "没有设置账号。请手动在 $CONFIG_DIR/config.json 里加 admin_users，例如："
                warn "  \"admin_users\": [{\"username\": \"admin\", \"password_hash\": \"\$(goproxy -hash-password '你的密码')\"}]"
            fi
        fi
    else
        $SUDO install -m 0644 "$TMP/config.example.json" "$CONFIG_DIR/config.json"
        ok "已生成配置 $CONFIG_DIR/config.json"

        # 这是「默认安装」路径 —— 也是最容易出问题的一条。
        # 示例配置里没有 admin_token，历史版本因此让人从浏览器打开时
        # 只看到一张「已拒绝所有外部请求」的说明页（用户反馈过「没见到登录界面」）。
        # 现在一律要登录，所以这一步要么在这里问出账号，要么明确告诉人怎么补。
        if ! prompt_admin_credentials "$CONFIG_DIR/config.json"; then
            warn "尚未设置管理账号 —— 控制台现在需要用户名 + 密码才能登录。"
            warn "补法（任选其一）："
            warn "  1. 重新运行本脚本，在交互提示里设置；"
            warn "  2. 手动编辑 $CONFIG_DIR/config.json 加上账号，再执行一次导入："
            warn "       goproxy -hash-password '你的密码'"
            warn "       sudo $BIN_DIR/goproxy -c $CONFIG_DB -config-import $CONFIG_DIR/config.json"
            warn "     字段格式见 config.json.example。"
        fi
        warn "这是示例配置，后端指向 127.0.0.1:9001 等本机端口，先改成你自己的后端"
    fi

    # 导入交给二进制自己走 -config-import：它做的是完整校验（含旧写法拦截），
    # 而且失败时**不动原配置** —— 所以这里可以放心 die，不会留下半坏的库。
    #
    # 用这个通道而不是「启动时自动导入」是有意的：启动时那一步只在库为空时
    # 触发一次，而安装脚本需要的是「现在就知道导没导成功」，还要能把报错
    # 直接摊在终端上给人看。
    info "正在把 $CONFIG_DIR/config.json 导入配置数据库…"
    if ! $SUDO "$BIN_DIR/goproxy" -c "$CONFIG_DB" -config-import "$CONFIG_DIR/config.json"; then
        die "导入失败（原因见上面那条报错）。库没有被改动，修好 $CONFIG_DIR/config.json 后重跑本脚本即可。
     最常见的原因是旧版的 acl 写法：v0.8.0 起路由只能**引用**顶层的命名名单，
     报错信息里带迁移映射，照它改；或在控制台「IP 名单」页建好名单再让路由引用。"
    fi
    ok "已导入到 $CONFIG_DB"
    info "config.json 只是种子，以后不再被读取 —— 改配置请用控制台，"
    info "  或 $BIN_DIR/goproxy -c $CONFIG_DB -config-export / -config-import"
fi
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

    # 证书与 ACME 缓存目录。单独建一个而不是复用 $STATE_DIR 根：
    # 配置里 tls.cert_dir / tls.acme.cache_dir 默认是相对路径，会相对「配置文件
    # 所在目录」解析，也就是 $CONFIG_DIR/data。
    #
    # 这里主动建好 $STATE_DIR/certs 并做成软链 $CONFIG_DIR/data -> 它，
    # 让证书这类**运行态数据**落在 /var/lib 而不是 /etc —— 证书是状态不是配置，
    # 混在配置目录里，备份配置时会一并带走私钥。软链已存在就不动
    # （--no-service 或用户自己配了绝对路径的场景）。
    CERT_DIR="$STATE_DIR/certs"
    $SUDO install -d "$CERT_DIR"
    $SUDO chown goproxy:goproxy "$CERT_DIR" 2>/dev/null || true
    if [ ! -e "$CONFIG_DIR/data" ]; then
        if $SUDO ln -s "$CERT_DIR" "$CONFIG_DIR/data" 2>/dev/null; then
            ok "已把 $CONFIG_DIR/data 指向 $CERT_DIR（供 TLS/ACME 写证书）"
        else
            warn "建软链 $CONFIG_DIR/data -> $CERT_DIR 失败。若启用 TLS，请在配置里把"
            warn "  tls.cert_dir / tls.acme.cache_dir 改成绝对路径 $CERT_DIR"
        fi
    elif [ ! -L "$CONFIG_DIR/data" ] && [ ! -w "$CONFIG_DIR/data" ]; then
        warn "$CONFIG_DIR/data 已存在且不可写。启用 TLS 前请把它指到 $CERT_DIR，"
        warn "  或在配置里把 tls.cert_dir / tls.acme.cache_dir 写成绝对路径"
    fi

    # 配置目录要对服务账号可写。管理接口的增删改路由、POST /reload、
    # PATCH /_goproxy/config 全都要写配置数据库 —— 写不进去这些操作直接失败。
    #
    # 换成 SQLite 之后要求没变松：数据库写入时要在库文件**旁边**建
    # -wal / -shm，所以「整个目录可写」才是硬要求，光让库文件本身可写不够。
    #
    # 这里踩过一次：ProtectSystem=strict 会把整个文件系统挂成只读，而单元里
    # ReadWritePaths 只放行了 $STATE_DIR，于是「删除路由」报
    #   attempt to write a readonly database
    #
    # 关键是 systemd 的 ReadWritePaths 只改挂载属性、**不改 Unix 权限**：
    # $CONFIG_DIR 是 root:root 0755 时，以 goproxy 身份跑的服务照样写不进去。
    # 所以下面改属主和单元里的 ReadWritePaths 缺一不可，两个都得有。
    if ! $SUDO chown goproxy:goproxy "$CONFIG_DIR" 2>/dev/null; then
        warn "改不了 $CONFIG_DIR 的属主，管理接口改配置会失败。请手动执行："
        warn "  sudo chown goproxy:goproxy $CONFIG_DIR"
    fi

    # 目录里的文件也要过一遍属主。数据库那几个尤其重要：-wal / -shm 是 SQLite
    # 在写入过程中现建的，如果库文件是 root:root 0644，服务连 -wal 都建不出来，
    # 报的还是一句看不出跟权限有关的错。
    #
    # 旧版二进制没有库文件，那份列表里的项自然都不存在，多列几项没有副作用。
    for f in goproxy.db goproxy.db-wal goproxy.db-shm config.json; do
        if [ -e "$CONFIG_DIR/$f" ]; then
            $SUDO chown goproxy:goproxy "$CONFIG_DIR/$f" 2>/dev/null || true
        fi
    done

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
ExecStart=$BIN_DIR/goproxy -c $SERVICE_CONFIG
WorkingDirectory=$STATE_DIR
Restart=always
RestartSec=3

# 不加这个，绑定 80/443 会 permission denied
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

# ProtectSystem=strict 会把整个文件系统挂成只读（/etc 也在内），
# 所以凡是运行期要写的地方都必须显式放行：
#   $STATE_DIR  —— 证书、ACME 缓存、运行态文件（$CONFIG_DIR/data 软链到这里）
#   $CONFIG_DIR —— 管理接口要写配置。SQLite 还要在库文件旁边建 -wal / -shm，
#                  所以放行的是整个目录而不是那一个文件。
#                  漏掉它，「删除路由」会报 attempt to write a readonly database。
ReadWritePaths=$STATE_DIR $CONFIG_DIR

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
if [ "$CONFIG_BACKEND" = "sqlite" ]; then
    echo "  配置库    $CONFIG_DB"
else
    echo "  配置文件  $CONFIG_FILE"
fi
if [ -n "$OLD_VER" ]; then
    echo "  旧二进制  $BIN_DIR/goproxy.old（回滚用）"
fi

# 明确告诉人「控制台地址是什么、以及有没有账号能进去」。
#
# 这段是有意加的：以前装完只说了配置文件和二进制路径，用户从浏览器打开
# 管理端口时看到的是「已拒绝所有外部请求」，完全不知道下一步该干什么，
# 反馈过「没见到登录界面」。把这两条直接写出来能省掉一整轮排查。
#
# 配置的真源是数据库，所以这里用 -config-export 导出一份临时 JSON 再读 ——
# 导出的就是那套规范化 JSON，字段名和以前完全一样。导出文件里带着
# admin_token 与密码哈希（所以 goproxy 自己按 0600 写），读完立刻删掉。
#
# 旧版二进制没有这个开关，那时配置文件本身就是真源，直接读文件即可。
ADMIN_ADDR=""
HAS_CRED="no"
if [ "$CONFIG_BACKEND" = "sqlite" ]; then
    CRED_TMP="$(mktemp)"
    if $SUDO "$BIN_DIR/goproxy" -c "$CONFIG_DB" -config-export "$CRED_TMP" >/dev/null 2>&1; then
        ADMIN_ADDR=$(sed -n 's/.*"admin_addr"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CRED_TMP" | head -n1)
        if grep -q '"admin_users"[[:space:]]*:[[:space:]]*\[[^]]' "$CRED_TMP" 2>/dev/null; then
            HAS_CRED="yes"
        fi
    fi
    rm -f "$CRED_TMP"
else
    # 这里刻意和 v0.8.0 的判据保持一致（只看 admin_users）：这条分支是兼容旧版本
    # 用的，连提示语都该和那时候一模一样 —— 否则「升级脚本让老部署的话术变了」
    # 本身就是一次没必要的意外。
    if [ -f "$CONFIG_FILE" ]; then
        ADMIN_ADDR=$(sed -n 's/.*"admin_addr"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -n1)
        if grep -q '"admin_users"[[:space:]]*:[[:space:]]*\[[^]]' "$CONFIG_FILE" 2>/dev/null; then
            HAS_CRED="yes"
        fi
    fi
fi

# admin_addr 留空的意思是「用默认值」（127.0.0.1:8080），那种情况下导出的 JSON
# 里根本没有这个键。以前直接 grep config.json，留空就什么都不打印 ——
# 而这恰恰是最常见的默认安装。这里补上默认值。
[ -n "$ADMIN_ADDR" ] || ADMIN_ADDR="127.0.0.1:8080"
echo "  控制台    http://${ADMIN_ADDR}/_goproxy/ui/"
echo
if [ "$HAS_CRED" = "yes" ]; then
    echo "控制台登录：用刚才设置的用户名 + 密码。"
elif [ "$CONFIG_BACKEND" = "json" ]; then
    # 与 v0.8.0 的提示语逐字一致 —— 这条分支服务的就是那些版本。
    echo "注意：没有设置管理员账号，控制台暂时登录不进去。补一个："
    echo "  $BIN_DIR/goproxy -hash-password '你的密码'"
    echo "  把输出填进 $CONFIG_FILE 的 admin_users[].password_hash"
    echo "  保存后自动热重载，不用重启。"
elif [ "$NO_ADMIN_PROMPT" = "1" ]; then
    echo "注意：没有设置管理员账号，控制台暂时登录不进去。补一个："
    echo "  $BIN_DIR/goproxy -hash-password '你的密码'"
    echo "  然后 $BIN_DIR/goproxy -c $CONFIG_DB -config-export cfg.json，"
    echo "  把哈希填进 cfg.json 的 admin_users[].password_hash，再 -config-import 导回并重启。"
else
    echo "注意：没有设置管理员账号，控制台暂时登录不进去。"
    echo "  重新运行本安装脚本即可在交互提示里设置，或按上面的命令手动补。"
fi
echo
if [ "$SVC_RESTARTED" = "1" ]; then
    echo "看日志：sudo journalctl -u goproxy -f"
    echo "看版本：$BIN_DIR/goproxy -version"
elif [ "$WITH_SERVICE" = "1" ] && command -v systemctl >/dev/null 2>&1; then
    echo "下一步："
    echo "  1. 改配置：打开控制台，把每条路由的 target 指向你自己的后端"
    echo "  2. 前台试跑：$BIN_DIR/goproxy -c $SERVICE_CONFIG（看有没有报错）"
    echo "  3. 正式启动：sudo systemctl enable --now goproxy"
    echo "     看日志：sudo journalctl -u goproxy -f"
else
    echo "下一步："
    echo "  1. 改配置：打开控制台，把每条路由的 target 指向你自己的后端"
    echo "  2. 后台运行：nohup $BIN_DIR/goproxy -c $SERVICE_CONFIG &"
fi
echo
if [ "$CONFIG_BACKEND" = "sqlite" ]; then
    echo "改配置的两条路（config.json 已经不再被读取了）："
    echo "  控制台    http://${ADMIN_ADDR}/_goproxy/ui/  —— 保存即生效"
    echo "  命令行    导出、改完再导回（适合批量改或界面进不去时救急）："
    echo "              $BIN_DIR/goproxy -c $CONFIG_DB -config-export cfg.json"
    echo "              ……改 cfg.json……"
    echo "              $BIN_DIR/goproxy -c $CONFIG_DB -config-import cfg.json   # 需重启或调 reload 生效"
    echo "  改错了    每次写入前会自动留一版历史（最近 20 版），就在 $CONFIG_DB 里"
else
    echo "改配置的两条路（$NEW_VER 还是 JSON 配置文件）："
    echo "  控制台    http://${ADMIN_ADDR}/_goproxy/ui/  —— 保存即生效"
    echo "  直接编辑  $CONFIG_FILE —— 这个版本每秒轮询 mtime，保存后自动热重载"
fi
echo
echo "卸载："
echo "  sudo systemctl disable --now goproxy 2>/dev/null"
echo "  sudo rm -f $BIN_DIR/goproxy $BIN_DIR/goproxy.old $UNIT"
echo "  sudo rm -rf $CONFIG_DIR"
