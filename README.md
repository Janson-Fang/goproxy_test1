# goproxy —— 最小可跑版（demo）

一个用 Go 写的 L7 HTTP 反向代理，核心验证 **「同一 IP 不同端口 → 不同后端」**（场景 C）以及按域名/路径分流。

demo 已经做到 M4：转发、多端口分流、热重载、限流、**熔断**、**访问控制（IP 黑白名单 / Basic / JWT）**、
**TLS / ACME 自动证书**，外加**多用户登录、会话保护、管理写接口、监控数据源和网页版管理控制台**。

仍然**故意不做**：SQLite（配置仍用 JSON 文件）、泛域名自动证书、mTLS。这些按正式方案的 M5–M7 迭代。

> **v0.6.0 是破坏性变更**：管理控制台改为**用户名 + 密码**登录，并且**本机访问也不再免认证**。
> 升级前请先看[从 v0.5.x 升级](#从-v05x-升级破坏性变更)，照着做一遍，否则控制台会打不开。

---

## 一分钟跑起来

```bash
# 1. 启动几个测试后端（另开终端，或用 & 放后台）
go run ./backend -port 9001 -name 服务A &
go run ./backend -port 9002 -name 服务B &
go run ./backend -port 9003 -name 服务C &
go run ./backend -port 9004 -name 服务D &

# 2. 给控制台设一个管理员账号（用户名 + 密码）
./goproxy -hash-password '你的密码'
# → $2a$10$....  把这行填进 config.json 的 admin_users

# 3. 启动反代
go run . -c config.json -text-log
```

看到这两行就说明起来了：

```
INFO 配置已生效 routes=5 ports=[8000 8081 8082 8083] admin=127.0.0.1:9080
INFO 管理端口已启动 addr=127.0.0.1:9080
```

注意 `ports` 里没有 9001–9004 —— 那是后端，不是监听端口。反代监听的是 **8000/8081/8082/8083**。

浏览器打开 **<http://127.0.0.1:9080/>** 就是管理控制台，会先跳到登录页。
**没有配任何凭据时会看到一张「还没有配置管理员账号」的指引页**（含可直接照抄的命令），
而不是空白或 401（详见[管理端认证](#管理端认证)）。

---

## 从 v0.5.x 升级（破坏性变更）

v0.6.0 动了三件**会让老环境无法照常使用**的事，升级前逐条对照：

| 变更 | 现象 | 怎么办 |
|---|---|---|
| **本机访问不再免认证** | 以前 `curl http://127.0.0.1:9080/_goproxy/routes` 直接 200，现在 **401** | 管理接口一律要凭据。脚本改用 `Authorization: Bearer <admin_token>`，浏览器去控制台登录 |
| **登录方式从「贴令牌」改成「用户名 + 密码」** | 原来贴在浏览器里的 `admin_token` 输入框没有了 | 在 `config.json` 里加 `admin_users`（用户名 + bcrypt 哈希），见下 |
| **`/healthz`、`/readyz`、`/metrics` 现在也要认证** | 监控探针、`docker-compose` 的健康检查开始报 401/403 | 探针带上 `Authorization: Bearer <admin_token>`；compose 的健康检查已改好，见[探针与健康检查](#探针与健康检查) |

错误码也从 `admin_token_not_set` 改名成 **`admin_credentials_not_set`** —— 因为令牌不再是唯一的凭据来源。
如果你有脚本/告警规则在匹配这个字符串，需要一起改。

### 最小升级步骤

```bash
# 1. 升级二进制（重跑安装脚本就是升级，配置文件不会被覆盖）
curl -fsSL https://cdn.jsdelivr.net/gh/Janson-Fang/goproxy_test1@main/install.sh | sudo bash

# 2. 加一个管理员账号。脚本升级时会检测到「一个凭据都没有」
#    并弹出交互提示；没弹出来就手动做：
goproxy -hash-password '你的密码'      # → $2a$10$...
```

```jsonc
// config.json
{
  "admin_users": [
    { "username": "admin", "password_hash": "$2a$10$..." }
  ]
}
```

保存即热重载，**不用重启**。此时浏览器打开 `http://<你的地址>:9080/` 就有登录页了。

> **老会话不会被立刻踢掉。** 会话绑定的是「账号的当前密码哈希 + 令牌指纹」。
> 只加 `admin_users`、不动 `admin_token` 的话，靠令牌指纹建立的旧会话仍然有效，
> 直到它自己超时（空闲 30 分钟 / 绝对 12 小时）。想把所有人立刻下线，
> 改一下 `admin_token` 即可 —— 令牌一变，靠它绑定的会话全部立刻失效。

### 只用了 `admin_token` 的环境

**不配 `admin_users` 也能正常用**，两条凭据路径是并列的：

- 浏览器：登录页会提示「还没有配置管理员账号」，可点「仍然尝试登录」用令牌登录；
- 脚本 / Prometheus：`Authorization: Bearer <admin_token>` 一直有效。

但推荐**两个都配**：给人用的走账号，给机器用的走令牌，职责分开。

---

## 验证多端口分流

> 没有 `jq` 的环境（比如 Windows）把 `| jq .` 去掉就行，直接看返回的 JSON。
> 另外如果本机设了 HTTP 代理，curl 访问 127.0.0.1 需要加 `--noproxy '*'`，否则会被代理截走。

```bash
# 同一个 IP，四个端口，四个不同后端
curl -s http://127.0.0.1:8000/ | jq .   # → 服务A（兜底路由）
curl -s http://127.0.0.1:8081/ | jq .   # → 服务A
curl -s http://127.0.0.1:8082/ | jq .   # → 服务B（有限流）
curl -s http://127.0.0.1:8083/ | jq .   # → 服务D
curl -s http://127.0.0.1:8083/api/x | jq .  # → 服务C，且 path 变成 /x（strip_prefix）
```

返回体里能看到后端收到的头，用来验证转发是否正确：

```json
{
  "service": "服务C",
  "backend_port": 9003,
  "path": "/x",
  "host_header": "127.0.0.1:9003",
  "x_forwarded_for": "127.0.0.1",
  "x_real_ip": "127.0.0.1",
  "x_forwarded_host": "127.0.0.1:8083",
  "x_forwarded_proto": "http"
}
```

`path` 从 `/api/x` 变成 `/x` 说明 `strip_prefix` 生效；`x_forwarded_host` 保留了客户端看到的原始地址。

### 其它验证

```bash
# 路径边界：/apixxx 不属于 /api，应落到服务D
curl -s http://127.0.0.1:8083/apixxx | jq .service   # → 服务D

# 限流：服务B 是 10rps/突发20，连续打 30 次会看到 429
for i in $(seq 1 30); do curl -s -o /dev/null -w "%{http_code} " http://127.0.0.1:8082/; done; echo

# 流式响应（SSE 场景）：应该一块一块地出，而不是最后一次性输出
curl -N http://127.0.0.1:8081/slow

# 未匹配的端口
curl -s http://127.0.0.1:8084/   # → 连接被拒绝（端口没开监听）
```

---

## 热重载：改配置不重启

改 `config.json` 里任意一条路由（比如加一个 `listen_port: 8085`），**保存**，一秒内日志会出现：

```
INFO 检测到配置变化，开始热重载
INFO 开始监听 port=8085
INFO 配置已生效 routes=6 ports=[8000 8081 8082 8083 8085]
```

新端口立刻可用，**已有连接不受影响**。删除端口同理，端口会被自动关掉。

不想等自动检测，也可以手动触发：

```bash
curl -X POST http://127.0.0.1:9080/_goproxy/reload
```

> 热重载时**限流器实例会被复用**（配置没变的话），否则改一次配置限流计数就清零，等于给客户端开了个绕过限流的口子。

---

## 管理控制台（网页版）

浏览器打开管理端口的根路径，会被自动送到控制台：

```bash
# 默认 admin_addr 是 127.0.0.1:9080
open http://127.0.0.1:9080/            # 等价于 http://127.0.0.1:9080/_goproxy/ui/
```

**第一次打开会让你登录**（用户名 + 密码）。没配账号的话看到的是配置指引页，不是登录表单。

四个页签：

| 页签 | 能做什么 |
|---|---|
| **总览** | 请求量 / 5xx 错误率 / P95 / 在途 / 限流与拒绝计数；最近 5 分钟的 QPS 与错误曲线；熔断器概况；状态码分布；监听端口与运行信息 |
| **路由** | 路由列表（三级匹配规则、实时请求数、熔断状态），一键启停；新建 / 编辑 / 删除；表单分「基础 · 转发 · 限流 · 熔断 · 认证与 ACL」五组 |
| **日志** | 最近 500 条访问记录，按状态 / 路由 / 方法 / 关键字过滤，被拦截的请求单独标色；SSE 实时追加，可暂停、可跟随滚动 |
| **配置** | `default_ports` / `access_log` / `trusted_proxies` / `admin_token` 的读写与手动重载；`admin_users` 与 `admin_addr` 只读并说明原因 |

几个和权限有关的点，部署前值得看一眼：

- **控制台的静态页面不鉴权。** 它只是一堆公开的前端代码，不含任何机密；但它必须能先加载出来，
  你才有机会登录。如果连页面壳都要鉴权，就成了「要登录才能打开页面、要页面才能登录」的死循环。
  真正敏感的操作全在 `/_goproxy/*` 接口上，那些**一律**要凭据（本机访问也一样）。
- **`admin_users` 只以用户名形式出现在界面上**，`password_hash` 从来不回传。
  「配置」页里那一排用户名标签只是让你确认「有哪些账号」，具体哈希在服务器上的 `config.json` 里。
- 会话凭据只存在 `HttpOnly` Cookie 里，脚本读不到，也不发给任何第三方。

### 从别的机器 / 公网访问控制台

`admin_addr` 默认只听 `127.0.0.1`，所以默认情况下**只有本机能打开控制台**。想让外部也能访问，
有两种做法，各自适合不同场景。

**做法一：把管理端口直接暴露出来**（最简单）

```json
{
  "admin_addr": "0.0.0.0:9080"
}
```

改完热重载即生效，然后 `http://<服务器IP>:9080/_goproxy/ui/` 就能打开。
代价是这个端口完全暴露 —— 请确认有防火墙 / 安全组把关，并且一定配了强密码。

**做法二：用一条代理路由把控制台「发布」出去**（推荐，也是项目自己的部署形态）

```json
{
  "admin_addr": "127.0.0.1:9080",
  "routes": [
    {
      "id": "console",
      "name": "控制台",
      "listen_port": 32000,
      "path_prefix": "/",
      "target": "http://127.0.0.1:9080"
    }
  ]
}
```

于是 `http://<服务器IP>:32000/_goproxy/ui/` 就是控制台。管理端口仍只听回环，
外部只能从 32000 进 —— 少暴露一个端口，也方便以后在这一层加 TLS / 访问控制。

> 这条路由 **不会** 让谁免登录。经代理进来的请求会带上内部标记头，
> 管理端一看到它就按「外部请求」处理，该要凭据一样要凭据。
> 详见下面「为什么不再有『回环免认证』」。

两种做法下的登录、会话、CSRF 行为完全一致，不需要额外配置。

#### 经代理访问时「卡在正在检查管理接口…」

v0.6.1 修掉了这个 bug，现象是：**页面能打开，但一直停在「正在检查管理接口…」**，
点登录也没反应（网络面板里能看到 `POST /_goproxy/login` 返回
`403 {"error":"cross_origin_rejected"}`）。

根因在两处，都已修复：

1. **CSRF 同源校验比错了对象。** 代理转发时 `proxy.go` 会把 `Host` 改写成目标地址
   （`127.0.0.1:9080`），而浏览器发的 `Origin` 是它实际访问的地址
   （`http://<公网IP>:32000`）—— 拿改写后的 `Host` 去比，永远不相等，登录必然被拒。
   现在改成比「浏览器实际用的那个 host」，取值来自代理写入的 `X-Forwarded-Host`；
   但这个头**只在请求确实经过本案代理时**才采信，否则它就是客户端随手能伪造的 ——
   详见 `session.go` 里 `effectiveRequestHost` 的注释。
2. **前端没处理非 401 的错误。** 原来的探测逻辑只在 401 时切换界面状态，其它错误
   只记了一条日志，「正在检查管理接口…」的显示条件因此永远成立 —— 于是无限转圈，
   连失败原因都看不到。现在非 401 的失败会切到一屏明确的错误提示（含状态码与排查建议）。

如果你在 v0.6.0 或更早的版本上遇到这个现象，升级到 v0.6.1 即可。
临时绕过办法：把 `admin_addr` 改成 `0.0.0.0:9080` 直接开控制台端口。

### 自己构建控制台

控制台是 `web/` 下的 React + Vite 工程，产物 `web/dist` 由 `go:embed` 打进二进制。

```bash
cd web
npm install
npm run build                     # 产物进 web/dist
cd .. && go build -o goproxy .    # go:embed 在编译期读 dist，所以要先构建前端
```

> `web/dist` 是**提交进仓库**的：`go:embed` 要求目录必须存在，不提交的话别人 clone 下来
> 直接 `go build` 会编译失败。CI 里有一道检查挡住「改了前端却忘了重新构建」。

调前端时不必每次都重新编译 Go，Vite dev server 会把管理接口代理到后端：

```bash
cd web && npm run dev
# 打开 http://127.0.0.1:5173/_goproxy/ui/
# 后端不在默认地址时：GOPROXY_ADMIN=http://127.0.0.1:9080 npm run dev
```

万一二进制里的 `web/dist` 缺失，访问控制台会看到一页构建指引，而不是白屏或 500。

---

## 管理端点

默认只监听 `127.0.0.1:9080`（`admin_addr` 可改）。控制台就建立在这些接口上，
用 curl 也能直接操作。管理端只服务两类东西，分流规则很简单：

| 你敲的地址 | 浏览器（`Accept` 含 `text/html`） | curl / 监控探针 |
|---|---|---|
| 接口路径（下表中的 `/healthz`、`/_goproxy/routes`…） | 原样返回数据，**不跳转** | 原样返回数据 |
| `/`、`/_goproxy`、`/_goproxy/` | 302 → `/_goproxy/ui/` | 纯文本接口清单 |
| 其余路径（`/index.html`、写错的地址…） | 302 → `/_goproxy/ui/` | 404 |

两个要点：

- **地址栏里随便敲哪个路径都会进控制台**，不必记住 `/_goproxy/ui/`。只有接口路径例外
  —— 浏览器直接打开 `/_goproxy/routes` 拿到的是 JSON，不会被重定向成网页。
- curl 拼错接口（如 `/_goproxy/statss`）会老实 404，不会用一个 200 的提示页伪装成成功。

| 路径 | 方法 | 说明 |
|---|---|---|
| `/_goproxy/ui/` | GET | 管理控制台（静态页面，**不需要凭据**；见上一节） |
| `/healthz` | GET | 存活探针（**需要凭据**） |
| `/readyz` | GET | 就绪探针，路由表未加载时 503（**需要凭据**） |
| `/metrics` | GET | Prometheus 文本格式指标（**需要凭据**） |
| `/_goproxy/routes` | GET | 路由列表，带实时观测值；响应带 `ETag` |
| `/_goproxy/routes` | POST | 新建路由，`id` 可省略（自动生成 `rt-xxxxxx`） |
| `/_goproxy/routes/{id}` | GET | 单条路由 |
| `/_goproxy/routes/{id}` | PUT | 全量替换（未提到的字段回默认值） |
| `/_goproxy/routes/{id}` | PATCH | 局部更新，启停路由就用它 |
| `/_goproxy/routes/{id}` | DELETE | 删除 |
| `/_goproxy/ports` | GET | 当前实际监听的端口，以及每个端口是否走 TLS |
| `/_goproxy/certs` | GET | 证书状态：域名、来源、签发者、到期时间、剩余天数、状态 |
| `/_goproxy/config` | GET | 全局配置（**不回传 `admin_token` 明文、不回传 `password_hash`**） |
| `/_goproxy/config` | PATCH | 改 `default_ports` / `access_log` / `trusted_proxies` / `admin_token` / `admin_users` |
| `/_goproxy/stats` | GET | 聚合状态：版本、uptime、指标汇总、熔断计数、采样曲线 |
| `/_goproxy/logs` | GET | 最近 N 条访问记录，`?limit=200`（上限 1000） |
| `/_goproxy/events` | GET | 实时访问日志，SSE 推送 |
| `/_goproxy/reload` | POST | 手动触发重载 |
| `/_goproxy/login` | POST | 用 `{"username","password"}` 或 `{"token"}` 换取会话 Cookie（**在鉴权闸门之外**，见下节） |
| `/_goproxy/session` | GET | 当前会话状态：`authenticated` / `via` / `has_session` / `username` / `token_set` |
| `/_goproxy/session` | DELETE | 登出（吊销会话 + 清 Cookie；也接受 `POST`） |
| 其余 `/_goproxy/` 下的路径 | 任意 | 通过认证后 404；**没配任何凭据时一律 403**，见下 |

> **表里除了控制台静态页面，其余全部需要凭据**，包括三个探针 —— 本机访问也不例外。
>
> 为什么不给探针留豁免：探针一旦免认证，就等于给了未认证调用者一个「服务端是否活着、
> 有哪些路由、错误率多少」的观测窗口，`/metrics` 更是把全部指标摊开。
> 想给 Prometheus 用就配 `admin_token`，那是它本来就该有的配置项。

### 管理端认证

管理接口能改路由，等于能改流量走向，**不能裸奔**。

v0.6.0 起管理端有**两条并列的凭据**，任一通过即放行：

| 凭据 | 给谁用 | 怎么配 |
|---|---|---|
| **`admin_users`** —— 用户名 + bcrypt 密码哈希 | **给人**用，浏览器登录控制台 | `goproxy -hash-password '你的密码'` 生成哈希，填进 `admin_users[].password_hash` |
| **`admin_token`** —— 一个 Bearer 令牌 | **给机器**用，脚本 / Prometheus / 监控探针 | `admin_token` 直接写字符串 |

两者可以同时配，也可以只配一个。**一个都不配时，所有管理接口（含三个探针）返回 403
`admin_credentials_not_set`**，控制台会显示配置指引页。

> 改配置保存后**自动热重载，不用重启**。账号表是热重载时重建的，
> 所以加账号、改密码、删账号都是保存即生效。

#### 登录：从「贴令牌」改成「用户名 + 密码」

v0.5.x 的做法是让用户在浏览器里贴 `admin_token`。这有两个问题：
令牌是**机器凭据**，贴在浏览器里一旦泄露就是全权；而且它没法区分「谁」在操作。

现在浏览器登录走真实的账号密码：

```bash
curl -s -X POST http://127.0.0.1:9080/_goproxy/login \
  -d '{"username":"admin","password":"你的密码"}' -i
# → 200，Set-Cookie: goproxy_admin_session=...
```

脚本仍然可以走令牌（`{"token":"..."}` 或直接 `Authorization: Bearer`），那条路没变。

同时**回环免认证被彻底移除**：以前来自 `127.0.0.1` 的请求无条件放行，
现在本机访问一样要凭据。这一条是「能看见登录页」的前提 ——
只要还有免认证的回环路径，从本机打开控制台就永远绕过登录页，
而线上排障又总是在本机做。

#### 凭据合法性与会话有效性是同一件事

会话里记的是**「哪个账号 + 该账号当前密码哈希」算出的指纹**：

```go
sessionFingerprintForUser(username, passwordHash)   // sha256("admin-user\0<name>\0<hash>")
```

于是：

- **改密码 → 该账号所有会话立刻失效**（指纹变了），不需要额外的吊销机制；
- **删账号 → 该账号所有会话立刻失效**（账号查不到，指纹为空）；
- **两个账号碰巧同密码也不会串**（指纹里带了用户名）。

令牌那条路同理，指纹是 `sha256(admin_token)`。

> 热重载会重建账号表，这正是「改密码不用重启」生效的机制。

#### 未知用户名也走一次 bcrypt

用户名不存在时，服务端**仍然对一个固定的占位哈希跑一次 bcrypt 比对**才返回错误。

不这么做的话，「用户名不存在」会立刻返回，而「密码错误」要等几十毫秒的 bcrypt ——
攻击者用响应时间就能枚举出哪些用户名是真的。登录接口本身有恒定 ~400ms 的兜底延时，
但那是**总时长**的兜底，挡不住「先返回 vs 后返回」这种更细的差异，所以这一层必须自己做。

实测：**错密码与不存在的用户名返回的 401 响应体逐字节相同**（端到端测试里断言了这一点，
不是靠"看着差不多"）。

#### 控制台登录（会话）

浏览器打开控制台时，如果没有会话，会看到**用户名 + 密码**的登录表单：

1. `POST /_goproxy/login`，body `{"username":"admin","password":"..."}`
2. 校验通过 → 下发 `HttpOnly` 会话 Cookie，**前端不保留任何密码**
3. 之后所有请求靠 Cookie 鉴权；密码用完即从组件状态里清掉

会话的几个关键设计：

| 项 | 值 | 为什么 |
|---|---|---|
| Cookie 名 | `goproxy_admin_session` | — |
| Cookie `Path` | `/_goproxy/` | **不能**写成 `/_goproxy/ui/`：接口不在 `ui/` 之下，会导致「登录成功但刷新后仍然 401」 |
| `HttpOnly` | 始终 | XSS 偷不走凭据的唯一依据 |
| `SameSite` | `Strict` | CSRF 第一道防线 |
| `Secure` | 仅请求走 TLS 时 | 明文端口加了会被浏览器直接丢弃 |
| 空闲超时 | 30 分钟（滑动） | 一直在用就一直有效 |
| 绝对超时 | 12 小时（不延长） | 不能靠「一直点」无限续期 |
| 服务端存储 | 只存 `sha256(handle)` | 内存被 dump 也拿不到可用句柄 |
| 上限 | 128 条 | 防内存无限增长 |
| 绑定 | 账号密码哈希指纹，或令牌指纹 | 改密码 / 改令牌即相关会话立刻失效 |

登出走 `DELETE /_goproxy/session`（也接受 `POST`），会吊销会话并清 Cookie。
控制台顶栏会显示当前登录的用户名，旁边就是登出按钮。

##### 登录防爆破

| 机制 | 参数 |
|---|---|
| 单 IP 失败封禁 | 5 次 → 10 分钟 |
| 全局失败封禁 | 50 次 → 1 分钟（挡换 IP 池） |
| 响应时间 | 恒定 ~400ms，抹平时序侧信道 |
| 失败响应 | 用户名不存在 / 密码错误 / 空凭据**完全一致** |

`429` 会带 `Retry-After`（加了抖动，避免所有客户端同时重试）。

##### CSRF

`SameSite=Strict` 是第一层，显式校验是第二层（纵深防御，代价几乎为零）。
只对**写方法 + 会话鉴权**生效：`Bearer` 不随请求自动携带，本来就没有 CSRF 面，
不该给 curl 增加负担。

两种校验策略，差别只在「两个头都没有」时怎么办：

| 场景 | 策略 | 理由 |
|---|---|---|
| 会话写请求 | **fail-closed**：缺头即拒 | 能走到这里说明带了 Cookie，而浏览器跨站写请求**一定**会发 `Origin`；缺头就可疑 |
| 登录请求 | **fail-open**：缺头放行 | 登录本来就没有 Cookie，curl/脚本也不发这两个头。跨站攻击**一定**会发 `Origin`/`Sec-Fetch-Site`，所以放行的只是「本来就非浏览器」的请求，不构成 CSRF 面。一律 fail-closed 会让 `curl -d '{"username":...,"password":...}' /_goproxy/login` 直接 403 |

##### 为什么 `/login` 必须在鉴权闸门**之外**

`POST /_goproxy/login` 和 `GET /_goproxy/session` 这两条路径**不经过** `adminGuard`。

这不是随手放行：登录接口的职责就是「在还没有凭据的时候拿到凭据」，
放在闸门之内等于把钥匙锁在屋里 —— 未登录的浏览器只会拿到 401，
永远走不到登录页。代码里由 `isAuthPath()` 单独列出，安全评审只需看这一个函数。

放行不等于不设防，两条路径各自带完整防护（见上面的防爆破与 CSRF 表）。
其余所有管理接口仍然一律经过 `adminGuard`，没有任何豁免。

##### 没有凭据时控制台看到什么

「有意拒绝」和「配置漏了」在现象上一样，都是打不开，所以这里把两者分开：

| 状态 | HTTP | 错误码 | 控制台 |
|---|---|---|---|
| 凭据已配、未登录 | 401 | `unauthorized` | 用户名 + 密码登录表单 |
| 凭据已配、登录中填错 | 401 | `unauthorized` | 表单 + 错误提示 |
| **一个凭据都没配** | **403** | **`admin_credentials_not_set`** | **配置指引页**（含 `config.json` 片段和生成哈希的命令） |

`GET /_goproxy/session` 在未登录时也会带上 `"credentials_configured": false`，
前端靠它决定显示表单还是指引页 —— 只用状态码判断的话，这两种情况都是「没登录」。

`POST /_goproxy/login` 在没配凭据时同样返回 **403 而不是 401**：
401 意味着「你密码错了」，会让人一直重试一个根本不存在的账号；
403 才能让前端正确地切到「去配置」那条路。

启动时也会打四条明确的 WARN，把 `admin_addr`、控制台路径、两种凭据的区别、
以及生成哈希的命令一次说清楚，不用去翻文档。

#### 安全响应头

所有响应（静态资源、接口、纯文本清单）都带：

| 头 | 值 |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-Robots-Tag` | `noindex, nofollow` |
| `Referrer-Policy` | `no-referrer` |
| `Content-Security-Policy` | 控制台与接口用两套不同策略 |

控制台 CSP 是 `script-src 'self'`（**不允许**内联脚本）。这也是首屏主题脚本
必须是外链 `theme.js` 而不是内联 `<script>` 的原因 —— 详见 `web/public/theme.js` 的注释。

`style-src` 保留了 `'unsafe-inline'`，这是**刻意的取舍**：React 的 `style={{...}}`
会产出内联样式属性，去掉它就得把所有动态样式改成 CSS 变量，收益不抵成本。

接口的 CSP 更严（`default-src 'none'`），因为它只返回 JSON，不需要加载任何东西。

#### 500 错误不回显内部信息

`writeErr` 对未预期的错误**不返回 `err.Error()`** —— 那里面常常带着绝对路径、
`permission denied`、甚至配置内容片段，等于免费给攻击者做信息收集。

客户端拿到的是一个短错误编号：

```json
{"error":"internal","message":"服务端内部错误，详情见服务端日志（错误编号 3f2a9c1b）。"}
```

详情只进服务端日志（带同一个 `error_id`），排查时按编号对账。

#### 为什么不再有「回环免认证」

v0.5.x 有一条「来自回环地址的请求免认证」的捷径，并且额外加了一个条件来堵它的洞
（因为**代理转发到管理端口时源地址就是 `127.0.0.1`**，把某条路由的 `target` 指向管理端口
就等于给外部客户端开了一道免认证后门）。那个条件本身是对的，但整个前提在 v0.6.0 被删掉了：

**只要还存在任何一条免认证路径，控制台的登录页就永远可能被绕过去。**

这条捷径的问题不在安全性（后门已经堵上），而在可用性：

- 从本机浏览器打开控制台 → 直接进界面，**永远看不到登录页**，用户会以为「没有登录功能」；
- 而线上排障、装机自检又总是在本机做，于是**这个 bug 只在别人从局域网访问时才暴露**；
- 排障时你会看到「本机好的、别人 401」，很容易去怀疑网络或防火墙。

现在一律要凭据，路径只有一条，行为在任何来源下都一致。

> 判断来源仍然只认 `RemoteAddr`，`X-Forwarded-For` 依旧被无视 ——
> 那条头是客户端随手就能写的，拿它判断「是不是本机」等于把认证决定权交给攻击者。
> 相关断言保留在测试里，作用是**防止有人日后悄悄把基于来源的判断加回来**。

把控制台通过一条 TLS 路由发布出去（比如 `host: admin.example.com`）**仍然可行**，
访问它时正常登录即可 —— 那就是一次普通的外部访问，和本机访问没有任何区别。

### 用法

```bash
A=http://127.0.0.1:9080
# 管理接口一律要凭据，本机也一样。脚本用令牌最省事：
T='Authorization: Bearer 你的 admin_token'

# 看路由（含熔断状态、请求数、在途数等实时值）
curl -s -H "$T" $A/_goproxy/routes | jq .

# 新建：同一个 IP 再开一个端口指向别的后端
curl -s -H "$T" -X POST $A/_goproxy/routes -d '{
  "id": "svc-e", "name": "服务E",
  "listen_port": 8090, "path_prefix": "/",
  "target": "http://127.0.0.1:9005"
}'
# → 端口 8090 立刻开始监听，不用重启也不用改启动参数

# 停用 / 启用（PATCH 只覆盖你写了的字段）
curl -s -H "$T" -X PATCH $A/_goproxy/routes/svc-e -d '{"enabled": false}'
curl -s -H "$T" -X PATCH $A/_goproxy/routes/svc-e -d '{"enabled": true}'

# 改限流，其它字段原样保留
curl -s -H "$T" -X PATCH $A/_goproxy/routes/svc-e -d '{"rate_limit": {"rps": 20, "burst": 40}}'

# 清掉某项嵌套配置：显式传 null
curl -s -H "$T" -X PATCH $A/_goproxy/routes/svc-e -d '{"rate_limit": null}'

# 删除
curl -s -H "$T" -X DELETE $A/_goproxy/routes/svc-e
```

没有配 `admin_token` 时（只用了 `admin_users`），要么给脚本也配一个令牌，要么用会话 Cookie：

```bash
# 登录拿 Cookie，之后 -b 带上
curl -s -c /tmp/gp.jar -X POST $A/_goproxy/login \
  -d '{"username":"admin","password":"你的密码"}'
curl -s -b /tmp/gp.jar $A/_goproxy/routes | jq .
```

管理端口开到外网时同理，认证和来源无关：

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://10.0.0.5:9080/_goproxy/routes
```

### 并发安全：ETag / If-Match

两个浏览器标签同时编辑时，后保存的会覆盖前一个的改动（lost update）。
`GET /_goproxy/routes` 和 `GET /_goproxy/config` 都会返回 `ETag`，
写请求带上 `If-Match` 即可让服务端把过期写拒掉：

```bash
ETAG=$(curl -sI -H "$T" $A/_goproxy/routes | tr -d '\r' | awk '/^Etag:/ {print $2}')

curl -s -H "$T" -X POST $A/_goproxy/routes \
  -H "If-Match: $ETAG" \
  -d '{"id":"new","listen_port":8091,"target":"http://127.0.0.1:9006"}'
# 若期间已有别人改过配置 → 409 revision_mismatch
```

不传 `If-Match` 就退化成「后写覆盖」（单向覆盖，仍是原子的，不会写出半个文件）。

### 写接口的几个行为约定

- **磁盘上的 `config.json` 是唯一真源**。每次写都是「读文件 → 改 → 校验 → 原子写回 → 热重载」，
  所以手工编辑过的配置不会被界面的一次保存悄悄覆盖。
- **校验不过就不落盘**。非法 `target`、端口与管理端口冲突这类错误一律 400，
  文件一个字节都不会动。
- **写回是原子的**：先写 `<path>.tmp` 并 `fsync`，再 `rename` 覆盖；旧内容备份到 `<path>.bak`。
  直接截断重写的话，写到一半断电就会留下一个解析不了的配置。
- **热重载失败会自动回滚**，不会把进程留在一个读不了配置的状态。
- **不写「默认值」**：配置里没写 `admin_addr` 时，写回也不会替它填上默认地址 ——
  否则一次保存就会把原本关闭的管理端口悄悄打开。
- **`admin_addr` 不能通过接口改**（启动期就绑定了套接字，改了不生效），改它请编辑文件后重启；
  显式返回 400 而不是假装成功。
- **`admin_addr` 写 `off` / `none` / `disabled` 可彻底关闭管理端口**；留空表示用默认值。
- **`admin_users` 读得到、写也写得进，但回显里没有密码材料**：
  `GET /_goproxy/config` 只返回用户名列表（`admin_users: ["admin"]`），
  `password_hash` 从不回传 —— 它是可以直接拿去爆破的东西，没有理由发到浏览器。
  通过 PATCH 提交 `admin_users` 会整表替换，记得把哈希一起带上。

> **破坏性变更**：`GET /_goproxy/routes` 现在返回**完整路由配置**（加上 `live` 实时字段），
> 不再是早先那个只有几个计算字段的精简形状。编辑界面需要拿到可回写的完整字段。

```bash
curl -s -H "$T" http://127.0.0.1:9080/_goproxy/routes | jq .
curl -s -H "$T" http://127.0.0.1:9080/metrics | grep goproxy_requests_total
```

---

## 监控数据源（前端就靠这三个）

管理台需要的数据在这一层就取全了，前端不必去解析 Prometheus 文本。

> 下面三条**都要认证**，示例里统一用 `T='Authorization: Bearer <admin_token>'`。
> Prometheus 抓取 `/metrics` 同理，在 scrape config 里配 `authorization: {credentials: <token>}`。

### `GET /_goproxy/stats` —— 一次拿全所有看板数字

```bash
curl -s -H "$T" http://127.0.0.1:9080/_goproxy/stats \
  | jq '{uptime_seconds, routes_active, ports, summary, circuit}'
```

关键字段：

| 字段 | 说明 |
|---|---|
| `summary.requests_total` | 全部请求数 |
| `summary.by_status` | 按状态码分桶，如 `{"200": 120, "404": 3}` |
| `summary.unmatched_total` | **没匹配到任何路由**的请求数，配置写歪了就看它 |
| `summary.error_rate` / `p95_ms` / `avg_ms` | 错误率与耗时（p95 由直方图桶估算） |
| `circuit` | 熔断器按状态计数 + 累计跳闸/快速失败次数 |
| `series` | 最近 5 分钟的**每秒增量**（`requests` / `errors` / `blocked`），直接画曲线 |
| `logs` | 缓冲条数、SSE 订阅者数、因订阅者太慢而丢弃的条数 |

`series` 由服务端每秒采样，**界面一打开就有历史曲线**，不用等前端自己攒。
`circuit` 读的是熔断器当前真实状态，不走那个 5 秒同步一次的指标缓存 ——
跳闸了却要等 5 秒才在界面上看见，排查时会以为熔断没生效。

### `GET /_goproxy/logs` —— 最近 N 条

```bash
curl -s -H "$T" "http://127.0.0.1:9080/_goproxy/logs?limit=20" \
  | jq '.entries[] | {seq, status, path, blocked}'
```

返回结构化字段（不是格式化好的日志文本，省得前端再解析一遍）。`blocked` 非空表示
这条请求**没有被转发出去**，值是拦截原因：`acl` / `rate_limited` / `circuit_open` / `auth_*`。
被拦掉的请求也会进日志 —— 排查限流误伤、ACL 配错时全靠它。

### `GET /_goproxy/events` —— SSE 实时推送

```bash
curl -N -H "$T" http://127.0.0.1:9080/_goproxy/events
```

```
event: hello
data: {"latest_seq":128,"buffered":42}

id: 129
event: access
data: {"seq":129,"time":"2026-09-15T22:44:49.284+08:00","route":"r1","port":8081,...}
```

- 连上先发一个 `hello`，带上当前 `latest_seq`，前端拿它和 `/logs` 的历史做去重
- 每 20 秒一个 `: ping` 注释行做保活，免得被中间代理掐掉空闲连接
- 响应带 `X-Accel-Buffering: no` —— 不加这个头，走 nginx 时事件会被缓冲，
  表现为「日志延迟几十秒甚至完全不动」

> **访问日志缓冲始终在记录**（定长 500 条，只在内存、不落盘），它和管理台的实时日志是同一个东西，
> 关掉界面就空了。`access_log` 控制的是**标准输出**那条结构化日志，量大了或者接了日志系统就关它。
>
> 订阅者慢（标签页切到后台、网络卡住）时消息**直接丢**并计数，不会阻塞请求路径 ——
> 访问日志这种顺手做的事，绝不该有能力把整个代理拖死。

---

## 探针与健康检查

`/healthz`、`/readyz`、`/metrics` 三条路径**都要求凭据**（v0.6.0 起，本机访问也不例外）。

这几条配起来比业务接口更容易踩坑，因为**配置它们的地方往往不支持自定义请求头**：

| 场景 | 怎么配 |
|---|---|
| Prometheus | scrape config 里加 `authorization: {type: Bearer, credentials: <admin_token>}` |
| Kubernetes 探针 | `httpGet` 支持 `httpHeaders`，带上 `Authorization: Bearer <token>` |
| `docker-compose` | 健康检查是 `CMD-SHELL`，直接写 `wget --header=...`（见下） |
| systemd / 简单脚本 | 用 `nc -z 127.0.0.1 9080` 只探端口是否在听，绕开 HTTP 认证 |

`docker-compose.yml` 里的健康检查已经改好，写法值得抄：

```yaml
test:
  - CMD-SHELL
  - >-
    wget -qO- --header="Authorization: Bearer $$GPROXY_ADMIN_TOKEN"
    http://127.0.0.1:9080/healthz | grep -q '^ok'
environment:
  GPROXY_ADMIN_TOKEN: ${GPROXY_ADMIN_TOKEN:-}
```

> **`$$` 是必须的**：compose 先把 `$` 当变量插值处理，写单个 `$` 的话
> `$GPROXY_ADMIN_TOKEN` 会在 compose 解析阶段就被替换成宿主机的值（没设就是空串），
> 到容器里就变成 `Authorization: Bearer ` —— 探针恒定 401，而 `docker ps` 只显示 unhealthy，
> 看不出是变量没传进去。`$$` 才是「交给容器内部展开」。
>
> 只用 `admin_users`、没有 `admin_token` 的部署，`environment` 里那行拿不到值，
> 健康检查会失败 —— 那就改用 `nc -z 127.0.0.1 9080`（探端口，不探 HTTP）。

---

## `listen_port` 怎么填

这是多端口分流的关键字段：

| 值 | 含义 |
|---|---|
| `0` | 不挑端口。挂到**所有**监听端口上，作为兜底 |
| `8081` | 只有从 8081 进来的请求才匹配它 |
| `80` / `443` | 标准端口，通常与域名路由混用 |

匹配顺序：**端口精确 → 端口兜底(0)**，端口内部再按 **host 精确 → host 通配(`*.x.com`) → host 任意(空)**，最后按 **path 最长前缀**。

举个组合例子（同一个 8083 端口内部再分流）：

```json
{ "id": "c", "listen_port": 8083, "path_prefix": "/api", "target": "http://127.0.0.1:9003", "strip_prefix": true },
{ "id": "d", "listen_port": 8083, "path_prefix": "/",    "target": "http://127.0.0.1:9004" }
```

不需要在启动参数里声明 8083 —— 路由里写了，端口就自动开。

---

## 熔断

单后端没法切流，所以熔断的价值是**快速失败** —— 后端已经挂了的时候，与其让每个请求都等到超时，不如立刻返回 503。

```json
{
  "id": "svc-cb",
  "listen_port": 8089,
  "target": "http://127.0.0.1:9099",
  "circuit_breaker": {
    "error_rate": 0.5,     // 窗口内错误率超过 50% 就跳闸
    "min_calls": 3,        // 窗口内至少这么多调用才评估，避免刚启动被零星错误打挂
    "open_secs": 10,       // 跳闸后保持 10 秒
    "half_open_calls": 2,  // 之后放行 2 个探测请求
    "window_secs": 10      // 滑动窗口长度
  }
}
```

状态机 `closed → open → half-open → closed`：

```bash
# 后端不可达时，前几次是 502（真实转发失败），达到阈值后直接 503（快速失败）
for i in $(seq 1 6); do
  curl -s --noproxy '*' -o /dev/null -w "%{http_code} " http://127.0.0.1:8089/
done
# → 502 502 502 503 503 503
```

「后端错误」的判定规则：**5xx 和连不上算，4xx 不算**（客户端的问题不该让后端背锅），**429 也不算**，否则限流会误触发熔断。

热重载时如果熔断配置没变，熔断器实例会被复用 —— 否则改一次配置统计窗口就清零了。

---

## 访问控制

三种方式可以按路由单独配，也能叠加。执行顺序是：**IP 黑白名单 → 限流 → 熔断 → 认证 → 转发**。

### IP 黑白名单

```json
"acl": { "mode": "deny", "cidrs": ["10.0.0.0/8", "192.168.1.5"] }
```

`mode` 为 `allow` 时是白名单（只有列表内可访问），`deny` 时是黑名单。单个 IP 不写 CIDR 会自动补成 /32。`allow` 模式如果 `cidrs` 是空的会直接报错，因为那等于拒绝所有流量，八成是配错了。

### Basic 认证

```json
"auth": {
  "mode": "basic",
  "realm": "goproxy",
  "basic": [{ "username": "admin", "password_hash": "$2a$10$..." }]
}
```

密码用 bcrypt。图省事也可以写明文 `"password": "s3cret"`，启动时会打一条 warning 并打印对应的 hash，粘回配置即可。

bcrypt 单次几十毫秒，所以校验结果缓存 60 秒 —— 不然高并发下 CPU 全耗在算哈希上。

### JWT

```json
"auth": {
  "mode": "jwt",
  "jwt": {
    "secret": "demo-secret-change-me",
    "issuer": "goproxy-demo",
    "audience": "my-api",
    "forward_claims": { "sub": "X-User-Id" }
  }
}
```

也支持 RS256（配 `public_key_pem`）。`forward_claims` 把 claim 透传给后端，后端不用再解一次 token：

```
X-USER-ID: user-42      ← 由 forward_claims 注入
```

两条安全硬约束：

- **算法白名单**：只认配置里声明的算法，`alg: none` 永远被拒绝
- **防算法混淆**：配了 RSA 公钥时，拿公钥当 HMAC 密钥伪造的 token 会被拒

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8087/                          # 401
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer <token>" ...          # 200
```

生成一个测试用的 HS256 token：

```bash
python - <<'EOF'
import hmac, hashlib, base64, json, time
b = lambda d: base64.urlsafe_b64encode(d).rstrip(b'=').decode()
h = b(json.dumps({'alg':'HS256','typ':'JWT'}).encode())
p = b(json.dumps({'sub':'user-42','iss':'goproxy-demo','exp':int(time.time())+3600}).encode())
s = b(hmac.new(b'demo-secret-change-me', (h+'.'+p).encode(), hashlib.sha256).digest())
print(h + '.' + p + '.' + s)
EOF
```

---

## TLS / HTTPS

### 总开关 + 路由覆盖

TLS 由**顶层 `tls.enabled` 开关**控制，每条路由再用 `tls_mode` 决定自己的行为：

```jsonc
{
  "tls": {
    "enabled": true,          // 全局开关，关掉则所有路由都退回明文
    "https_port": 443,        // HTTPS 监听端口（HTTP 在下面 acme 的 http_port）
    "cert_dir": "data/certs", // 相对路径 → 相对配置文件所在目录
    "acme": {
      "email": "you@example.com",
      "staging": false,       // true = 用 Let's Encrypt 测试环境，不占正式额度
      "directory_url": ""     // 留空按 staging 自动选；也可指向自建 ACME（如 step-ca）
    }
  },
  "routes": [
    { "id": "web", "listen_port": 443, "host": "app.example.com",
      "tls_mode": "auto", "target": "http://127.0.0.1:9001" },

    { "id": "legacy", "listen_port": 8443, "host": "old.example.com",
      "tls_mode": "manual", "cert_file": "data/certs/old.crt",
      "key_file": "data/certs/old.key", "redirect_http": false,
      "target": "http://127.0.0.1:9002" },

    { "id": "plain", "listen_port": 8080,
      "tls_mode": "off", "target": "http://127.0.0.1:9003" }
  ]
}
```

| `tls_mode` | 含义 | 证书来源 |
|---|---|---|
| `auto` | 自动申请 + 自动续期 | ACME（Let's Encrypt），走 HTTP-01 |
| `manual` | 用你自己指定的证书 | `cert_file` / `key_file`，**支持热更新** |
| `off` | 该路由纯明文 | 无 |

路由不写 `tls_mode` 时默认跟随全局：全局开了就是 `auto`，没开就是 `off`。

### 端口级，不是路由级

**一个端口要么全明文、要么全 TLS**，二者不能混。原因很实际：如果同一个端口
对某些请求加密、对另一些不加密，攻击者只要构造一个走明文的请求就能把流量降级
（TLS stripping）。所以 TLS 是按**监听端口**决定的，不是按路由。

由此带来一个必须知道的约束：**路由的 `listen_port` 就是决定它跑不跑 TLS 的依据**。
同在 443 上的路由都走 TLS，同在 8080 上的都走明文。

### HTTP→HTTPS 跳转

开着 TLS 时，打到明文端口（默认 80）的请求会 **301 跳到 HTTPS**，路径和 query 原样保留：

```
http://app.example.com/a?b=1   →   https://app.example.com/a?b=1
```

不想要跳转就在路由上写 `redirect_http: false`（比如想让明文端口继续提供 API，
不逼客户端跟着跳）。`tls_mode: "off"` 的路由天然不跳 —— 它本来就没有 HTTPS 可跳。

判断「这个请求是不是已经走了 TLS」靠的是监听端口本身，不是请求里的头，
所以不存在 `X-Forwarded-Proto` 被伪造导致的重定向死循环。

### 80 端口的三个职责

开了 TLS 之后，80 端口同时干三件事，按顺序判断：

1. **ACME 挑战** —— `/.well-known/acme-challenge/*` 交给 autocert 应答（申请/续期要用）
2. **跳转** —— 其余请求 301 到 HTTPS（除非路由写了 `redirect_http: false`）
3. **明文代理** —— 该端口上的 `tls_mode: "off"` 路由照常提供明文服务

### 证书热更新

`manual` 模式的证书文件**每 30 秒轮询一次 mtime**，文件变了就重新加载，不用重启：

```bash
# 换了证书直接覆盖文件，30 秒内自动生效
sudo cp new.crt /etc/goproxy/data/certs/old.crt
sudo cp new.key /etc/goproxy/data/certs/old.key
```

重新加载**失败时会继续用旧证书**——轮换期间写错文件不至于把站点搞挂，
但错误会通过下面的接口暴露出来，方便你发现这次轮换其实没生效。

### ACME 的硬约束

自动证书有几个绕不过去的限制，配之前必须知道：

| 约束 | 说明 |
|---|---|
| **HTTP-01 固定走 80** | 申请时必须能从公网访问你域名的 80 端口。所以 `listen_port` 自定义的路由**拿不到自动证书**，只能 `manual` 或 `off` |
| **TLS-ALPN-01 固定走 443** | 同上，443 也必须是标准端口 |
| **不能给裸 IP 签发** | Let's Encrypt 拒绝为 IP 地址签发证书，`auto` 只认域名 |
| **不支持泛域名** | `*.example.com` 需要 DNS-01 验证，demo 没做。泛域名请用 `manual` 挂通配证书 |
| **有严格频率限制** | 同一域名重复签发有每周限额，所以 `data/` 目录（ACME 缓存）**必须持久化**，容器/服务重启后不能丢 |

验证阶段建议先开 `staging: true` 跑通流程，确认没问题再切回正式环境
—— 测试环境的额度宽松得多，出错了也不会把正式域名拖进限流。

### 查看证书状态

```bash
curl -s http://127.0.0.1:9080/_goproxy/certs | jq .
```

```jsonc
{
  "tls_enabled": true,
  "acme_dir": "https://acme-v02.api.letsencrypt.org/directory",
  "certs": [
    { "domain": "app.example.com", "source": "acme", "issuer": "Let's Encrypt",
      "not_after": "2026-12-14T08:30:00Z", "days_left": 89, "state": "valid" },
    { "domain": "old.example.com", "source": "manual", "issuer": "My CA",
      "not_after": "2026-10-01T00:00:00Z", "days_left": 15, "state": "expiring" }
  ]
}
```

`state` 有四种：`valid` / `expiring`（**剩不到 20 天**）/ `expired` / `error`（加载失败）。
证书加载失败时 `days_left` 是 0，别把它误读成「还有很久」——所以 `error` 的判断
优先级高于 `expiring`，控制台的「证书」页就是这么显示的。

控制台左侧「证书」标签页也有一份同样的表格，外加当前监听的端口及各端口是否走 TLS。

### 与自带部署脚本的配合

`install.sh` 会处理三件事：

- systemd 单元里给了 `AmbientCapabilities=CAP_NET_BIND_SERVICE`，**非 root 也能绑 80/443**
- **让配置目录对服务账号可写**。管理接口增删改路由靠的是原子写
  （写 `config.json.tmp` 再 `rename` 覆盖），而 `ProtectSystem=strict` 下 `/etc`
  默认只读 —— 不放行的话「删除路由」会直接报
  `open /etc/goproxy/config.json.tmp: read-only file system`。
  脚本会把 `$CONFIG_DIR` 加进 `ReadWritePaths`，**并且**把它 `chown` 给 `goproxy`。
  两件都得做：`ReadWritePaths` 只改挂载属性，不改 Unix 权限
- 把 `$CONFIG_DIR/data` 软链到 `/var/lib/goproxy/certs`，让证书这类运行态数据落在
  `/var/lib` 而不是 `/etc` —— 证书是状态不是配置，混在配置目录里，备份配置会连私钥一起带走

---

## 已知限制（demo 边界）

| 不做 | 原因 / 何时做 |
|---|---|
| 泛域名（`*.example.com`）自动证书 | 需要 DNS-01 验证。要泛域名就用 `manual` 挂通配证书 |
| 客户端证书（mTLS） | 没做。需要双向认证的话建议在上一层网关终结 |
| 访问日志落盘 | 只往标准输出写，没有内置文件轮转。需要留存就接 `systemd` 的 journal 或外部 logrotate |
| SQLite | M1 正式版。现在用 JSON 文件，`loadConfig` 换掉即可，下游不动 |
| 路由变更审计 | 写接口目前不记录「谁在什么时候改了哪条路由」。多人共用管理端时会需要 |
| 多实例共享状态 | 限流和熔断都是进程内内存，多副本各算各的。另外**写配置也是单机行为**，两个实例各写各的会互相覆盖，多副本场景需要换成共享存储 + 一致性协议。预留了接口，后续换 Redis / SQLite |
| 会话持久化 | 会话存在进程内存里，**重启即全部失效**。对单机自托管是可接受的取舍（换来的是「不引入存储依赖」）。要跨重启保持登录就得引入存储 |
| 权限分级 | 有多个账号了，但**账号之间没有权限差别** —— 任一账号登录后都是全权。没有只读账号、没有按路由授权 |
| 改密码要手工 | 没有「修改密码」界面。靠 `goproxy -hash-password` 生成哈希再改 `config.json`（保存即生效）。加界面要引入「改密时验证旧密码」「强制复杂度」等一串决策，暂不做 |
| 账号数量无上限但也没约束 | `admin_users` 里放多少人都行，不过它是配置文件里的明文结构 —— 适合 1~5 个运维账号，不是给终端用户用的用户体系 |
| CSP 的 `style-src` 内联 | 保留 `'unsafe-inline'`，因为 React 的 `style={{...}}` 产出内联样式属性。去掉需要把动态样式全改成 CSS 变量，收益不抵成本 |

---

## 在线编译（GitHub Actions）

仓库里带了 `.github/workflows/ci.yml`，**push 上去就自动编译**，不需要本地装 Go：

| 触发条件 | 做什么 |
|---|---|
| push / PR 到 main | 先跑 **管理控制台构建与一致性**：`npm ci` → `npm run typecheck` → `npm run build`，然后校验提交进仓库的 `web/dist` 与重新构建的结果一致 |
| 同上 | gofmt 检查、`go vet`、`go test -race`（依赖上面的 console 任务先通过） |
| 同上 | 交叉编译 **linux/amd64 + linux/arm64** 静态二进制 |
| 同上 | 构建多架构 Docker 镜像并推到 `ghcr.io/<owner>/<repo>` |
| 打 tag `v*` | 额外创建 GitHub Release，把两个平台的 tar.gz 挂上去 |

> `web/dist` 是提交进仓库的（`go:embed` 要求它必须存在，否则别人 clone 下来直接 `go build` 会失败）。
> 那道一致性校验就是为了挡住「改了前端却忘了重新构建」——否则仓库里的产物会悄悄过期。
> 本地改完前端记得 `cd web && npm run build` 再提交。

拿编译产物：仓库页面 → **Actions** → 点进最新的 workflow run → 页面底部 **Artifacts** 下载 `goproxy-linux-amd64`。压缩包里除了二进制还有 `config.example.json`。

发版本：

```bash
git tag v0.3.0 && git push origin v0.3.0
```

镜像：

```bash
docker pull ghcr.io/janson-fang/goproxy_test1:main   # 注意镜像名必须全小写
```

> 公开仓库的 Actions 时长**完全免费且无上限**，只有私有仓库才受每月 2000 分钟限制。

---

## 安装到 Linux

### 一键安装（推荐）

在目标机器上一条命令搞定：下载预编译二进制 → 装到 `/usr/local/bin` → 生成配置 → 注册 systemd 服务。

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/Janson-Fang/goproxy_test1@main/install.sh | sudo bash
```

> 用 jsdelivr 取脚本而不是 `raw.githubusercontent.com`，因为后者在国内经常连不上。
> 脚本内部下载 Release 时也会自动挑加速通道，见下。

脚本做的事：自动识别 amd64/arm64、校验 sha256（对不上直接中止）、**已存在的 `config.json` 不会被覆盖**、
创建 `goproxy` 系统用户并以非 root 运行、**交互式引导你设置一个管理员账号**。
装完按提示改配置，然后：

```bash
sudo systemctl enable --now goproxy
sudo journalctl -u goproxy -f
```

**从 v0.6.0 起安装过程会多问一步**（这是用户反馈「没见到登录界面」之后加的）：

```
----------------------------------------
 设置管理控制台的登录账号
----------------------------------------
控制台现在需要用户名 + 密码登录。请现在设置一个，
否则从浏览器打开会看到「还没有配置管理员账号」。
（以后也可以用: goproxy -hash-password '密码' 自己改）

用户名 [admin]: 
密码: 
再输一次: 
 OK 已设置管理账号「admin」（密码只以 bcrypt 哈希形式保存，脚本不留副本）
```

几个细节：

- **密码不回显、要输两次**。它要进 bcrypt，打错了自己看不出来，只能靠登录失败才发现。
- **哈希由二进制自己算**（调 `goproxy -hash-password`），不在脚本里重新实现一遍 bcrypt ——
  服务端用什么校验、这里就生成什么，不可能出现「算出来的哈希验不过」这种极难排查的故障。
- **不用 sudo 跑也能问**；非交互环境（`curl | sudo bash` 在 CI 里、容器里）读不到 `/dev/tty`，
  会**跳过提问并打印手动补法**，不会把你挂在那儿等输入。
- **升级时只在「一个凭据都没有」才问**。已经有 `admin_token` 或者 `admin_users` 的环境
  不会被反复打扰（`admin_token` 依然有效，老的脚本不用改）。

装完的收尾提示会直接把控制台地址和「有没有账号能进去」写出来：

```
  二进制    /usr/local/bin/goproxy
  配置文件  /etc/goproxy/config.json
  控制台    http://127.0.0.1:9080/_goproxy/ui/

控制台登录：用刚才设置的用户名 + 密码。
```

> 别指望「装完就能从浏览器进去」这件事自动成立 —— 收尾提示里这句话是有意加的。
> 之前装完只说二进制和配置文件路径，用户打开管理端口看到的是「已拒绝所有外部请求」，
> 完全不知道下一步该干什么。

起来之后浏览器打开 **`http://<服务器IP>:9080/`** 就是管理控制台（要先登录）。
默认的 `admin_addr` 是 `127.0.0.1:9080`，只有本机能连；要开放到局域网/公网就改 `admin_addr`，
并**建议同时配一个 `admin_token`** 给探针用 —— 探针不方便走账号登录。

### 无人值守安装

CI / 容器 / 批量部署跳过交互提问：

```bash
curl -fsSL .../install.sh | sudo bash -s -- --no-admin-prompt
# 或
curl -fsSL .../install.sh | sudo NO_ADMIN_PROMPT=1 bash
```

这样装出来的环境**一个凭据都没有**，管理接口全部 403。要注意这是**预期行为**而不是坏了 ——
装完记得用 `goproxy -hash-password` 补账号，或者准备好 `admin_token`。
（脚本收尾也会提醒这一条。）

### 国内网络：脚本会自动走加速镜像

实测国内直连 GitHub 下载 Release **基本下不动**（7MB 的包 35 秒都拉不完），所以脚本内置了加速通道，`MIRROR` 默认 `auto`：

| 取值 | 行为 |
|---|---|
| `auto`（默认） | 先试直连，失败或过慢自动切镜像；顺序 gh-proxy.com → ghfast.top → ghproxy.net |
| `direct` | 强制直连，不碰任何第三方 |
| `https://你的镜像/` | 只用指定前缀的镜像 |

```bash
# 什么都不用加，慢了自己切
curl -fsSL .../install.sh | sudo bash

# 能顺畅访问 GitHub 的机器（如海外 VPS）：强制直连
curl -fsSL .../install.sh | sudo MIRROR=direct bash

# 指定镜像
curl -fsSL .../install.sh | sudo MIRROR=https://gh-proxy.com/ bash
```

脚本的选路逻辑有两处细节，都是为了少让你干等：

- **直连给短超时（35s），镜像给长超时（90s）**。93 字节的校验和文件能秒下，不代表 7MB 的包也下得动 —— 实测就是「小文件通、大文件死」，所以不能因为探测通过就一直等直连。
- **下载慢于 2KB/s 持续 20 秒直接放弃换通道**，避免卡死在龟速连接上。

**安全性**：镜像是第三方服务，只负责加速传输。下载完会用 Release 里的 `SHA256SUMS` 校验内容，**对不上直接中止安装**，想篡改会被拦住。对第三方有顾虑就用 `MIRROR=direct`。

**已知坑**：镜像有缓存，刚发布的版本可能还没同步过去，表现是「校验和不匹配」。脚本会提示你换直连或换个镜像；要绝对保险就显式指定 `VERSION=`。

### 常用变体

```bash
# 指定版本（推荐，避免 latest 解析依赖网络）
curl -fsSL .../install.sh | sudo VERSION=v0.3.0 bash

# 无人值守：跳过设置管理员账号那一步
curl -fsSL .../install.sh | sudo bash -s -- --no-admin-prompt

# 容器里用：只装二进制，不碰 systemd
curl -fsSL .../install.sh | sudo bash -s -- --no-service

# 不想用 root：装到家目录
curl -fsSL .../install.sh | BIN_DIR=$HOME/.local/bin CONFIG_DIR=$HOME/.goproxy bash -s -- --no-service
```

不想用脚本的话，手动下载 Release 附件也一样（国内记得套一层镜像前缀）：

```bash
VERSION=v0.3.0
MIRROR=https://gh-proxy.com/          # 能直连 GitHub 就去掉这个前缀
curl -fsSL -o goproxy.tar.gz \
  "${MIRROR}https://github.com/Janson-Fang/goproxy_test1/releases/download/$VERSION/goproxy-linux-amd64.tar.gz"
tar -xzf goproxy.tar.gz && sudo install -m 0755 goproxy /usr/local/bin/goproxy
```

容器镜像（无需安装，两平台自动选）：

```bash
docker run --rm ghcr.io/janson-fang/goproxy_test1:main -version   # 注意镜像名全小写
```

### 升级

**再跑一遍同一条命令就是升级**，没有单独的 upgrade 子命令：

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/Janson-Fang/goproxy_test1@main/install.sh | sudo bash
```

脚本会识别出「已经装过」，然后按下面的规则处理：

| 东西 | 升级时怎么处理 |
|---|---|
| `$BIN_DIR/goproxy` | **就地替换**。先写成 `goproxy.new` 再 `mv` 覆盖（rename 是原子的），所以不会出现「路径短暂不存在」的窗口；服务正在运行也没问题 —— 运行中的进程继续持有旧 inode 跑完，新起的进程才拿到新文件，不会 `Text file busy` |
| `$BIN_DIR/goproxy.old` | **新增**。升级前的二进制自动留一份，出问题能一键回滚 |
| `config.json` | **不动**。新版本的示例另存为 `config.json.example`，方便对照新增字段 |
| systemd 单元 | **先备份再重写**（`goproxy.service.bak`）。因为 `ExecStart` 里带着本次的 `BIN_DIR` / `CONFIG_DIR`，必须跟着更新；但你手动加过的 `Environment=`、`LimitNOFILE=` 之类会从 `.bak` 里找回来 |
| 服务 | **原来在跑就自动重启**，并轮询确认真的起来了；原来没跑就保持不启动（可能是你自己停的） |

> 最后一条是最容易踩的：**光替换文件不重启，进程还在跑旧代码**，看着升级成功了其实没生效。
> 脚本默认会自动重启，不想让它动服务就加 `--no-restart`。

回滚到上一个版本：

```bash
sudo cp -p /usr/local/bin/goproxy.old /usr/local/bin/goproxy
sudo systemctl restart goproxy
```

确认升级后的版本：

```bash
/usr/local/bin/goproxy -version
systemctl show -p ExecMainStartTimestamp goproxy   # 重启时间应该是刚刚
```

如果服务重启后没起来，脚本会**以非 0 退出**并直接把回滚命令和 `journalctl` 查看方式打出来。

可覆盖的环境变量（除 `MIRROR` / `VERSION` / `BIN_DIR` / `CONFIG_DIR` 外）：

| 变量 | 默认值 | 用途 |
|---|---|---|
| `SYSTEMD_DIR` | `/etc/systemd/system` | 单元文件放哪 |
| `STATE_DIR` | `/var/lib/goproxy` | 单元里的 `WorkingDirectory`，也是证书目录的落点（`ReadWritePaths` 里除了它还包含配置目录 —— 管理接口要能写配置） |

### 版本号从哪来

版本号不在源码里写死，编译时由 git 推导（`Makefile` 与 CI 用同一套规则）：

| 构建时机 | 版本串 |
|---|---|
| 正好打在 tag 上（发版） | `v0.4.0` |
| tag 之后又有新提交 | `v0.4.0-9-gef38364` —— 9 表示距该 tag 有 9 个提交 |
| 有未提交的改动 | 末尾再追加 `-dirty` |
| 没传 `-X main.version`（裸 `go build`） | `dev` |

能查到的位置：`goproxy -version`、启动日志第一行、`/_goproxy/stats` 的 `version` 字段，
以及控制台顶栏和「仪表盘 → 运行时信息」。

> **装出来的版本一直是旧版？** `install.sh` 默认装的是「最新 Release」——
> `VERSION=latest` 会去查 `/releases/latest`。所以只要这个仓库还没打新 tag，
> 无论 `main` 上有多少新提交，一键安装拿到的都还是上一个 tag 的内容。
> 这不是脚本的问题，是确实没发版。想用 `main` 上的最新代码，自己编译（见下节），
> 或者先发一版：
>
> ```bash
> git tag -a v0.4.0 -m "v0.4.0" && git push origin v0.4.0
> ```
>
> 推送后 CI 会自动交叉编译、创建 Release 并挂上 `SHA256SUMS-*`，之后再跑
> `install.sh` 拿到的就是新版本（升级路径见上一节）。

---

## 命令行

```bash
goproxy [-c 配置文件] [-log-level 级别] [-text-log] [-version] [-hash-password 密码]
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `-c <路径>` | `config.json` | 配置文件路径（**是 `-c`，不是 `-config`**） |
| `-log-level <级别>` | `info` | `debug` / `info` / `warn` / `error` |
| `-text-log` | 关 | 输出人类可读的文本日志。默认是 JSON，方便接日志系统 |
| `-version` | — | 打印版本与 commit 后退出 |
| `-hash-password <密码>` | — | 把密码算成 bcrypt 哈希后退出，用于填进 `config.json` |

**`goproxy -hash-password` 是设置/修改管理密码的唯一入口**：

```bash
goproxy -hash-password '你的新密码'
# stdout 只有哈希本身：$2a$10$...
# 提示语走 stderr，所以可以直接 $(...) 取用，不会被污染
```

```jsonc
// 把输出填进这里，保存后自动热重载（不用重启）
{ "admin_users": [{ "username": "admin", "password_hash": "$2a$10$..." }] }
```

> 为什么不在文档里教你装个 `htpasswd` 或写段 Python 算 bcrypt：
> cost 参数、salt 生成、编码任意一处不一致，症状都是「登录永远失败」而没有任何报错。
> 用这个命令拿到的哈希，和**服务端校验用的是同一个库、同一份实现**，不可能对不上。
> `install.sh` 生成哈希走的也是这一条路。

也可以直接在 `config.json` 里写明文 `"password": "..."`（和路由的 Basic 认证一致），
启动时会打一条 WARN 并把算好的哈希打印出来，粘回去即可。

---

## 手动编译部署

```bash
# 交叉编译（无需 CGO，静态二进制）
# 这两行 -X 别省 —— 少了它二进制只会自报 "dev"，线上分不清跑的是哪一版
VERSION=$(git describe --tags --always --dirty)
COMMIT=$(git rev-parse --short=7 HEAD)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT" \
  -o goproxy .
./goproxy -version        # goproxy v0.4.0-9-gabc1234 (commit abc1234)

# 放到服务器
scp goproxy config.json user@server:/opt/goproxy/
```

装了 `make` 的机器（Linux / macOS）上面这串可以省掉：

```bash
make build      # 编译，版本号自动带上
make release    # 先重建控制台再编译
make version    # 只看当前会用什么版本串
```

systemd unit（`/etc/systemd/system/goproxy.service`）：

```ini
[Unit]
Description=goproxy reverse proxy
After=network.target

[Service]
# 降权运行。注意：得给服务账号配置目录的写权限（见下面 ReadWritePaths 的说明）
User=goproxy
Group=goproxy
ExecStart=/opt/goproxy/goproxy -c /opt/goproxy/config.json
WorkingDirectory=/opt/goproxy
Restart=always
RestartSec=3

# 允许绑定 80/443 而不用 root，比直接跑 root 安全
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

# 这个目录必须同时可读**可写**：管理接口改配置走原子写
# （写 config.json.tmp 再 rename 覆盖）。只读的话「删除路由」会报
# read-only file system，而且只在真正操作时才暴露。
#
# 把配置放 /etc/goproxy（脚本的默认布局）时同理 —— 要一起放行，
# 并且把属主给服务账号：ReadWritePaths 只解除只读挂载，不改 Unix 权限，
# 目录还是 root:root 0755 的话服务照样建不出 .tmp。
ReadWritePaths=/opt/goproxy

[Install]
WantedBy=multi-user.target
```

> **管理接口报 `read-only file system` 或 `permission denied`？** 都是上面这条
> 没配对，跟接口本身无关。`install.sh` 装的话重跑一次即可（配置不动、
> 单元重写、在跑的服务会自动重启）；手写单元的按上面两件事补：
> `ReadWritePaths` 里加上配置目录，并 `chown <服务账号> <配置目录>`。

Docker：

```bash
# 配置要挂「目录」不能挂单个文件：单文件在容器里是个挂载点，
# 而原子写的最后一步是 rename 覆盖它 —— 内核禁止 rename 到挂载点（EBUSY），
# 改成 :rw 也没用，只会把 read-only file system 换成 device or resource busy。
# 宿主目录的属主要给容器里的 uid 10001，否则同样写不进去。
mkdir -p config data && cp config.json config/ && sudo chown -R 10001:10001 config data

docker compose up -d --build
# 或
docker build -t goproxy:demo . && docker run --network host \
  -v $PWD/config:/etc/goproxy \
  -v $PWD/data:/etc/goproxy/data \
  goproxy:demo
```

---

## 源码结构

| 文件 | 职责 |
|---|---|
| `main.go` | 组装、请求入口、管理端点注册、配置热重载、优雅停机 |
| `config.go` | 配置结构与校验、配置文件的原子写入与 revision |
| `admin_api.go` | 管理接口：认证闸门、路由 CRUD、全局配置读写、登录与会话端点 |
| `admin_users.go` | 管理端账号表：bcrypt 校验、按账号算会话指纹、未知用户名的恒定耗时兜底 |
| `session.go` | 控制台登录会话：只存句柄哈希、空闲/绝对过期、登录限流、CSRF 同源校验 |
| `secheaders.go` | 安全响应头与 CSP（控制台与接口用两套策略） |
| `router.go` | 三级匹配表（端口 → host → path），不可变快照 |
| `proxy.go` | ReverseProxy 封装：连接池、超时、XFF、真实 IP 解析 |
| `listener.go` | 多端口监听管理，按路由表变化自动增删；TLS 端口用 `tls.NewListener` 包一层 |
| `tlsconfig.go` | TLS/ACME 配置结构、默认值、校验；端口 → TLS 配置的推导 |
| `tls.go` | 证书管理器：按 SNI 分发、manual 热加载（30s 轮询）、autocert 接入、证书状态 |
| `ratelimit.go` | 按 IP 分桶的令牌桶（带过期清理） |
| `circuitbreaker.go` | 滑动窗口熔断器（closed / open / half-open） |
| `acl.go` | IP 黑白名单（CIDR） |
| `auth.go` | Basic（bcrypt + 校验缓存）与 JWT 认证器 |
| `jwt.go` | JWT 校验：HS256/384/512、RS256，带算法白名单 |
| `metrics.go` | Prometheus 指标 + 实时观测值 + 每秒采样曲线 |
| `accesslog.go` | 访问记录的定长环形缓冲，兼作 SSE 广播源 |
| `stats.go` | `stats` / `logs` / `events` 三个监控接口 |
| `webui.go` | 内嵌并托管管理控制台：`go:embed`、缓存策略、SPA 回落、根路径分流 |
| `web/` | 管理控制台前端工程（React 19 + Vite + TypeScript），产物 `web/dist` 提交进仓库 |
| `router_test.go` | 路由匹配单测 |
| `governance_test.go` | 熔断、ACL、JWT、Basic 单测 |
| `admin_api_test.go` | 管理接口单测：CRUD、并发写冲突、认证、坏配置不落盘 |
| `stats_test.go` | 环形缓冲、采样序列、SSE、并发重载单测 |
| `webui_test.go` | 控制台托管单测：内嵌资源、缓存头、SPA 回落、静态壳免鉴权但接口一律鉴权 |
| `tls_test.go` | TLS 单测：按 SNI 分发、通配匹配、热加载、续期告警阈值、跳转逻辑、ACME 约束 |
| `example_config_test.go` | 守卫测试：`config.example.json` 必须能加载，部署文件必须暴露 443 |
| `deploy_test.go` | 部署守卫：单元 `ReadWritePaths` 含配置目录、`install.sh` 改属主、Dockerfile `chown`、compose 挂目录而非单文件 |
| `session_test.go` | 会话与登录单测：存储哈希、过期、限流、Cookie 属性、CSRF、端点可达性、恒定耗时、账号指纹失效 |
| `scripts/e2e_console.py` | 端到端自检：真实后端 + 真实反代，**121 项断言**（含认证、账号登录、负向验证） |

```bash
go test ./...   # 跑测试
go vet ./...    # 静态检查

# 端到端自检：会用真实二进制起 4 个测试后端 + 反代，
# 覆盖控制台依赖的全部接口（静态资源、根路径分流、限流/认证真实流量、
# stats/logs、SSE、路由 CRUD + ETag 并发、全局配置、Prometheus 指标、
# 以及「无凭据一律拒绝」/ 账号密码登录 / CSRF / 登出 / 安全响应头）。
# 里面有几条是**负向断言**，值得单独提一句：
#   · 错密码与「用户名不存在」的 401 响应体必须逐字节相同（防用户名枚举）
#   · 一个凭据都没配时，回环地址访问三个探针也必须 403（防回环豁免复活）
# 需要 PATH 里有 go 和 python3；产物都落在临时目录，不污染工作区。
python scripts/e2e_console.py
```

TLS 另有两个实机端到端脚本（在仓库外的开发目录里，自签证书 + 真实进程）：

- **`e2e_tls.py`** —— 起两个后端 + 两个自签证书，逐个 SNI 校验**证书链和域名**
  （用自签证书当 CA 做完整校验，而不是只看握手成功）、HTTPS 是否转到了正确的后端、
  明文端口是否 301（含非标准端口）、`/certs` 与 `/ports` 接口的形状。
- **`e2e_tls_reload.py`** —— 热加载验证：比对**DER 指纹**（PEM 解码后再哈希，
  直接哈希 PEM 文件比的是错的字节），替换磁盘上的证书后等 30 秒轮询周期，
  断言服务端换上了新证书且**没有重启**。

> ACME 的签发流程没有端到端覆盖 —— 本地没有公网域名，HTTP-01 拿不到证书。
> 这部分靠单测覆盖（`TestACMEEffectiveDirectoryURL`、`TestAutoCertRejectsIPAndWildcard`、
> `TestAutoCertRejectsCustomPort` 等），实机验证只能等有域名时做。

---

## 下一步

已完成 M1–M4（含 TLS / ACME 自动证书）、管理写接口、监控数据源、管理控制台前端、
**登录 / 会话 / 安全加固**（会话 Cookie、防爆破、CSRF、安全响应头），
以及**多用户账号体系与强制登录**（用户名 + 密码、本机不再豁免、探针也要认证）。

接下来：

- **配置源换成 SQLite（M5 正式版）** —— `loadConfig` 换掉即可，HTTP 层与前端不动
- 审计日志：记录「谁在什么时候改了哪条路由」（多账号之后这件事才有意义，见下）
- 权限分级：账号之间现在没有区别，任一账号都是全权

> 提到审计日志是因为它和多账号是同一件事的两半：有了 `admin_users` 之后，
> 写接口已经知道「是谁在操作」了，缺的只是把 `username` 记进审计记录。
> 现在多个账号能登录，但**改了什么、谁改的**依然查不到。

> 完整的架构方案、数据模型与里程碑计划不在这个仓库里。

## 许可

MIT
