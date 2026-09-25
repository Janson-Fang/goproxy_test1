# goproxy

用 Go 写的 L7 HTTP 反向代理。核心是 **「同一个 IP、不同端口 → 不同后端」**，同时支持按域名 / 路径前缀分流。

它解决的是一台机器、一个公网 IP 要对外提供好几个服务这件事：每个服务各占一个端口，
各自转发到本机或内网的某个后端；配置改完不用重启，控制台里点几下就生效。
整体是一个静态二进制加一个 SQLite 配置库，没有外部依赖，也不需要 root 常驻。

## 项目介绍

| 方面 | 说明 |
|---|---|
| 转发 | 多端口 / 多域名 / 路径前缀分流；WebSocket 升级与流式响应都走原生（不缓冲整包） |
| 变更 | 改配置**不用重启**：路由增删、端口开关、名单改动即时生效；写接口带 `revision` + ETag 并发保护 |
| 限制 | 按 IP 的令牌桶限流；滑动窗口熔断（后端持续失败时快速失败，不打穿） |
| 访问控制 | 三层 IP 名单（全局黑名单 / 命名名单库 / 路由引用）、Basic 认证、JWT |
| TLS | 手动证书与 ACME 自动申请续期，按 SNI 分发，证书热重载 |
| 控制台 | 网页版管理界面（`/_goproxy/ui/`），用户名 + 密码登录、多用户、HttpOnly 会话 |
| 观测 | `/stats`、`/logs`（最近 N 条，可选显示客户端 IP 的归属地）、`/events`（SSE 实时推送）、健康探针 |
| 防护 | 蜜罐端口 + 自动封禁扫描来源（默认关闭，可先跑观察模式） |
| 配置 | 存 SQLite（v0.9.0 起）：整份配置在一个事务里读写、带历史归档、可导出成 JSON 进版本控制 |

**故意不做**：泛域名自动证书、mTLS。

## 安装步骤

### 一键安装（Linux，推荐）

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/Janson-Fang/goproxy_test1@main/install.sh | sudo bash
sudo systemctl enable --now goproxy
sudo journalctl -u goproxy -f
```

> 用 jsdelivr 取脚本而不是 `raw.githubusercontent.com`，因为后者在国内经常连不上。

脚本做的事：识别 amd64 / arm64 → 下载并**校验 SHA256**（对不上直接中止）→ 装到 `/usr/local/bin/goproxy`
→ 创建 `goproxy` 系统用户并以非 root 运行 → **交互式引导设置管理员账号**（密码不回显、要输两次，
哈希由 `goproxy -hash-password` 现算，不可能出现「算出来的哈希验不过」）→
**已存在的配置库绝不覆盖**。

装完的默认位置：

| 东西 | 位置 |
|---|---|
| 二进制 | `/usr/local/bin/goproxy` |
| 配置库 | `/etc/goproxy/goproxy.db` |
| 运行状态 | `/var/lib/goproxy` |
| systemd 单元 | `/etc/systemd/system/goproxy.service` |
| 控制台 | `http://127.0.0.1:9080/_goproxy/ui/` |

默认 `admin_addr` 是 `127.0.0.1:9080`，只有本机能连；要开放到局域网 / 公网，在控制台里改它。
**建议同时配一个 `admin_token`** —— 探针和脚本走 `Authorization: Bearer` 更省事，不用管登录会话。

### 常用安装变体

```bash
# CI / 批量部署：跳过交互提问
curl -fsSL .../install.sh | sudo bash -s -- --no-admin-prompt
curl -fsSL .../install.sh | sudo NO_ADMIN_PROMPT=1 bash        # 同上，另一种写法

# 固定版本（推荐：不依赖 latest 的在线解析）
curl -fsSL .../install.sh | sudo VERSION=v0.13.0 bash

# 容器里用：只装二进制，不碰 systemd
curl -fsSL .../install.sh | sudo bash -s -- --no-service

# 装到家目录，不要 root
curl -fsSL .../install.sh | BIN_DIR=$HOME/.local/bin CONFIG_DIR=$HOME/.goproxy bash -s -- --no-service
```

无人值守装出来的环境**一个凭据都没有**，管理接口一律 403 —— 这是**预期行为**，不是坏了。
补账号用 `goproxy -hash-password`，把输出的哈希填进配置的 `admin_users`。

### 国内网络：走加速镜像

实测国内直连 GitHub 下载 Release 基本下不动，所以脚本内置加速通道，`MIRROR` 默认 `auto`：

| 取值 | 行为 |
|---|---|
| `auto`（默认） | 先试直连，失败或过慢自动切镜像（gh-proxy.com → ghfast.top → ghproxy.net） |
| `direct` | 强制直连，不碰任何第三方（海外机器用这个） |
| `https://你的镜像/` | 只用指定前缀的镜像 |

```bash
curl -fsSL .../install.sh | sudo MIRROR=direct bash
curl -fsSL .../install.sh | sudo MIRROR=https://ghfast.top/ bash
```

镜像是第三方服务，只负责传输；下载后仍会用 Release 里的 `SHA256SUMS` 校验，**对不上直接中止**。
刚发布的版本可能还没同步进镜像缓存（表现为「校验和不匹配」），换直连或显式指定 `VERSION=`。

也可以不用脚本，手动下载 Release 附件（国内记得套一层镜像前缀）：

```bash
VERSION=v0.13.0; MIRROR=https://gh-proxy.com/
curl -fsSL -o goproxy.tar.gz \
  "${MIRROR}https://github.com/Janson-Fang/goproxy_test1/releases/download/$VERSION/goproxy-linux-amd64.tar.gz"
tar -xzf goproxy.tar.gz && sudo install -m 0755 goproxy /usr/local/bin/goproxy
```

### 升级

**再跑一遍同一条安装命令就是升级**，没有单独的 upgrade 子命令。脚本会：

- **就地替换**二进制（先写 `goproxy.new` 再 rename 覆盖，不会有「路径短暂不存在」的窗口；
  服务正在运行也安全），并把它备份成 `goproxy.old`；
- **不动已存在的配置库** —— 库才是配置的真源，升级绝不覆盖；
- **先备份再重写** systemd 单元（留 `.bak`）；服务原来在跑就**自动重启并轮询确认真的起来了**。

```bash
sudo cp -p /usr/local/bin/goproxy.old /usr/local/bin/goproxy && sudo systemctl restart goproxy   # 回滚
/usr/local/bin/goproxy -version                                                                   # 确认版本
systemctl show -p ExecMainStartTimestamp goproxy                                                  # 重启时间应是刚刚
```

> 最容易踩的一条：**光替换文件不重启，进程还在跑旧代码**。不想让它动服务就加 `--no-restart`。

控制台里也能升级（「升级」页 → 上传二进制或发布用的 `.tar.gz`）。这条路只走**上传文件**：
跑反代的服务器多半连不通 `github.com`，所以让**你的浏览器**去发布页下载，服务器只负责装。

> 升级**不改配置库**。跨破坏性版本时，新二进制遇到旧写法会**拒绝启动**并打印迁移映射
> （不静默忽略、不自动转换）——不会带着旧配置跑出别的意思。想先留个底：
> `goproxy -c <配置库> -config-export backup.json`。

### Docker

```bash
mkdir -p config data
cp config.json config/
sudo chown -R 10001:10001 config data        # 容器里以 uid 10001 运行，属主不对就写不进去
docker compose up -d --build
# 或
docker build -t goproxy:demo . && docker run --network host \
  -v $PWD/config:/etc/goproxy -v $PWD/data:/etc/goproxy/data goproxy:demo
```

**配置要挂目录，不能挂单个文件**：写配置库时要在库文件**旁边**建 `-wal` / `-shm`，
单文件挂载会把它们丢在容器临时层里，容器一重建库就可能不完整。
`config.json` 只是种子，库为空时才被导入一次。

> CI 目前不构建 Docker 镜像，上面这条是本地 build。

### 手动编译部署

```bash
VERSION=$(git describe --tags --always --dirty)
COMMIT=$(git rev-parse --short=7 HEAD)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT" -o goproxy .
./goproxy -version          # 少了 -X 这两行，二进制只会自报 "dev"
```

装了 `make` 的机器可以省掉上面这串：`make build`（编译，版本号自动带上）/
`make release`（先重建控制台再编译）/ `make test`。

systemd 单元（`/etc/systemd/system/goproxy.service`）要点：

```ini
[Service]
User=goproxy
Group=goproxy
ExecStart=/opt/goproxy/goproxy -c /opt/goproxy/goproxy.db
WorkingDirectory=/opt/goproxy
AmbientCapabilities=CAP_NET_BIND_SERVICE   # 允许绑定 80 / 443 而不用 root
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/goproxy                # 配置目录必须同时可读可写，见下
Restart=always
RestartSec=3
```

配置目录**必须同时可读可写**：管理接口写配置库时要在库文件旁边建 `-wal` / `-shm`，
写不进去就报 `attempt to write a readonly database` —— 而且只在真正操作时才暴露。
`ReadWritePaths` 只解除只读挂载、不改 Unix 权限，目录属主还要给服务账号：

```bash
sudo chown goproxy:goproxy /opt/goproxy
```

（`install.sh` 装出来的服务已经配好了这些；管理接口报 `readonly database` 或 `permission denied`
时，重跑一次安装脚本即可。）
