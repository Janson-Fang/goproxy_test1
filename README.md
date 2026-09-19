# goproxy —— 最小可跑版（demo）

用 Go 写的 L7 HTTP 反向代理，核心验证 **「同一 IP 不同端口 → 不同后端」**，以及按域名 / 路径分流。

已完成：转发、多端口分流、热重载、限流、熔断、访问控制（三层 IP 名单 / Basic / JWT）、TLS / ACME 自动证书、
多用户登录与会话保护、管理写接口、监控数据源、网页版管理控制台，以及**配置存进 SQLite**（v0.9.0 起）。
**故意不做**：泛域名自动证书、mTLS。

> **破坏性变更速查** —— 用旧写法的配置**进程会拒绝启动**并打印迁移映射，迁移步骤见文末[升级](#升级四版都是破坏性变更)：
>
> | 版本 | 变更 |
> |---|---|
> | **v0.9.0** | 配置源从 `config.json` 换成 SQLite；旧文件只在**首次启动时导入一次**，之后不再被读取 |
> | **v0.8.0** | IP 名单不再内联写在路由里，改成顶层 `ip_lists` 集中定义、路由按名字引用 |
> | **v0.7.0** | 路由名单从 `acl.mode` 二选一改成可并存的 `allow` / `deny`，并新增全入口 `global_ip_deny` |
> | **v0.6.0** | 控制台改为用户名 + 密码登录；本机不再免认证；三个探针也要凭据 |
>
> 另：CI **暂时不构建 Docker 镜像**（发布不受影响，见[在线编译](#在线编译github-actions)）。

---

## 一分钟跑起来

```bash
# 1. 启动几个测试后端（另开终端，或用 & 放后台）
go run ./backend -port 9001 -name 服务A &
go run ./backend -port 9002 -name 服务B &
go run ./backend -port 9003 -name 服务C &
go run ./backend -port 9004 -name 服务D &

# 2. 给控制台设一个管理员账号，把输出的哈希填进 config.json 的 admin_users
#    （config.json 只在**首次启动**时被导入一次，之后配置以数据库为准）
./goproxy -hash-password '你的密码'

# 3. 启动反代（首次启动会建 goproxy.db 并把同目录的 config.json 导进去）
go run . -c goproxy.db -text-log
```

看到这三行就说明起来了（`ports` 里没有 9001–9004 —— 那是后端，不是监听端口）：

```
INFO 已把旧的 config.json 导入配置数据库（只导入这一次） file=config.json db=goproxy.db
INFO 配置已生效 routes=5 ports=[8000 8081 8082 8083] admin=127.0.0.1:9080
INFO 管理端口已启动 addr=127.0.0.1:9080
```

第一行只在**第一次**出现 —— 之后配置以 `goproxy.db` 为准，`config.json` 不再被读取（详细见[配置存在哪儿](#配置存在哪儿sqlitev090-起)）。

浏览器打开 **<http://127.0.0.1:9080/>** 就是控制台（会先跳登录页）。
**没配任何凭据时**看到的是一张「还没有配置管理员账号」的指引页（含可直接照抄的命令），见[管理端认证](#管理端认证)。

---

## 验证多端口分流

> 没有 `jq` 就去掉 `| jq .`；本机设了 HTTP 代理时，curl 访问 127.0.0.1 要加 `--noproxy '*'`。

```bash
curl -s http://127.0.0.1:8000/ | jq .                # → 服务A（兜底路由）
curl -s http://127.0.0.1:8081/ | jq .                # → 服务A
curl -s http://127.0.0.1:8082/ | jq .                # → 服务B（有限流）
curl -s http://127.0.0.1:8083/ | jq .                # → 服务D
curl -s http://127.0.0.1:8083/api/x | jq .           # → 服务C，且 path 变成 /x（strip_prefix）
curl -s http://127.0.0.1:8083/apixxx | jq .service   # → 服务D（/apixxx 不属于 /api）

# 限流：服务B 是 10rps/突发20，连续打 30 次会看到 429
for i in $(seq 1 30); do curl -s -o /dev/null -w "%{http_code} " http://127.0.0.1:8082/; done; echo

curl -N http://127.0.0.1:8081/slow                   # SSE：一块块地出，而不是最后一次性输出
curl -s http://127.0.0.1:8084/                       # 连接被拒绝（端口没开监听）
```

返回体里能看到后端收到的头，用来验证转发是否正确：

```json
{ "service": "服务C", "backend_port": 9003, "path": "/x", "host_header": "127.0.0.1:9003",
  "x_forwarded_for": "127.0.0.1", "x_real_ip": "127.0.0.1",
  "x_forwarded_host": "127.0.0.1:8083", "x_forwarded_proto": "http" }
```

`path` 从 `/api/x` 变成 `/x` 说明 `strip_prefix` 生效；`x_forwarded_host` 保留了客户端看到的原始地址。

---

## 热重载：改配置不重启

改配置的唯一入口是**管理接口**（控制台里保存，或 curl 打 `POST` / `PATCH` / `DELETE /_goproxy/*`）。
保存成功后进程在同一个请求里完成热重载，日志会出现：

```
INFO 检测到配置变化，开始热重载
INFO 开始监听 port=8085
INFO 配置已生效 routes=6 ports=[8000 8081 8082 8083 8085]
```

新端口立刻可用，**已有连接不受影响**；删除端口同理。手动重读一遍库：`curl -X POST http://127.0.0.1:9080/_goproxy/reload`。

> v0.8.0 及更早版本会**每秒轮询 `config.json` 的 mtime**，直接改文件也能触发重载。
> 配置搬进 SQLite 之后**这条路径没有了**：配置不再是一份「谁都能随手编辑的文本文件」，
> 绕开校验、自锁检查和引用完整性去改配置本身就是不安全的。
> 批量 / 离线改配置请走 `-config-export` → 改 → `-config-import`，导入后重启进程或调一次 `POST /_goproxy/reload`。

> 热重载时**限流器 / 熔断器实例会被复用**（配置没变的话）—— 否则改一次配置计数就清零，等于开了个绕过的口子。

---

## 配置存在哪儿（SQLite，v0.9.0 起）

配置不再是一份 `config.json`，而是一个 SQLite 数据库（路径由 `-c` 指定，默认 `goproxy.db`）。

| | |
|---|---|
| **为什么换** | 旧实现里「先备份 → 写临时文件 → `rename`」这套原子性是代码手工拼出来的；「这份名单还被哪几条路由引用」是每次现扫内存算的（`listUsage`）；改名改写引用要靠调用方声明（`ip_list_renames`）。换成数据库之后这三件事分别由**事务**、**外键**、`ON UPDATE CASCADE` 承担 —— 「忘了写就出错」的逻辑写进约束里就不会忘 |
| **谁在读** | 进程启动、热重载。**读成一份不可变快照常驻内存**，请求路径上完全不碰数据库 |
| **谁在写** | 只有管理接口（控制台 / curl），写完全是事务性的 |
| **不再支持的路径** | 文件轮询（已删）；直接拿 `sqlite3` 改库 —— 那条路会绕过校验、自锁检查和引用完整性，而这几样恰恰是配置安全的地方。要批量改就用下面两个命令行开关 |
| **表结构** | `settings`（顶层标量）、`default_ports`、`trusted_proxies`、`global_ip_deny`、`admin_users`、`ip_lists` + `ip_list_rules`、`routes`、`route_acl_lists`（路由 → 名单引用）、`tls_settings`、`acme_hosts`、`config_history`。限流 / 熔断 / 认证这三段叶子配置仍然是整块 JSON 列 —— 它们要么整块配、要么整块不配，从来不会被单独查询或按字段过滤 |
| **引用完整性** | `route_acl_lists.list_name` 上两条约束：`ON DELETE RESTRICT`（**还被引用的名单删不掉**，对应原来的 `listUsage` 扫描 + `409 list_in_use`）和 `ON UPDATE CASCADE`（**改名自动改写所有引用**，对应原来的 `renameListRefs`） |
| **历史版本** | 每次写入前把上一版存进 `config_history` 表，**保留最近 20 版**并按 revision 去重。替代了原来的 `config.json.bak`（只留一版 = 改错两次就回不去了） |
| **schema 版本** | `meta.schema_version`。用新二进制打开旧库会**明确报错**，而不是等某条 `SELECT` 报 `no such column` 才被发现 |
| **并发** | 连接数固定为 1（SQLite 单写者，写入频率是「人手点一次保存」级别），DSN 上带 WAL + `busy_timeout(5000)` + `foreign_keys(1)` |

对外一个字节都没变：`Config` 结构、HTTP 接口的 JSON 形状、`ETag` / `If-Match` 语义全部保持原样，前端不需要知道底下换了存储。

### 批量 / 离线改配置：`-config-export` / `-config-import`

日常改动走控制台就够了。这两个命令存在的理由是**自锁逃生**：万一 `global_ip_deny` 配错把自己关在门外，控制台就进不去了。

```bash
goproxy -c goproxy.db -config-export config.json   # 导出成人可读的 JSON
# ……改这份 JSON……
goproxy -c goproxy.db -config-import config.json   # 导回（走完整校验，失败一个字节都不动）
curl -X POST http://127.0.0.1:9080/_goproxy/reload # 让运行中的进程重新读库（或重启进程）
```

导入走的**是和管理接口完全相同的校验**（`manual` 证书的相对路径以数据库所在目录为基准解析）——
它不是一个「绕过校验的后门」，只是一个「不需要先进控制台」的入口。

### 备份

```bash
# 要么直接拷库（连同 -wal / -shm 一起，或者干脆先停进程再拷）
cp goproxy.db goproxy.db-wal goproxy.db-shm /backup/

# 要么导一份 JSON（人可读、可 diff、能进版本控制）
goproxy -c goproxy.db -config-export "/backup/goproxy-$(date +%F).json"
```

> 想「回滚到上一版」不用翻备份：库里 `config_history` 就留着最近 20 版，可以 `-config-export` 之后对着 diff 手工改回去。

### 首次导入：`config.json` 只在第一次被读

`-c` 指向一个**空库**（或还不存在的库）时，进程会尝试导入**同目录下的 `config.json`**，**只导一次**。

- **为什么只导一次**：如果每次都「库为空就导入」，那你哪天删光所有路由、重启，旧文件里的内容会**突然复活** —— 那比不导入更难排查。
- `-c` 还指着 `config.json`（旧 JSON 文件）会**直接报错**并给出两条出路，而不是安静地在旁边建个空库让你以为「升级完配置全没了」：

```
config.json 不是 SQLite 数据库（看起来还是旧版的 JSON 配置文件）。
    配置源已经换成 SQLite，请二选一：
      1. 保留 -c 指向它，另外执行一次导入：goproxy -config-import config.json -c goproxy.db
      2. 直接把 -c 改成 goproxy.db，启动时会自动导入同目录下的 config.json（只导一次）
```

升级的完整步骤见文末[升级](#升级四版都是破坏性变更)。

---

## 管理控制台（网页版）

```bash
open http://127.0.0.1:9080/          # 等价于 /_goproxy/ui/；admin_addr 默认 127.0.0.1:9080
```

**第一次打开会让你登录**（用户名 + 密码）；没配账号的话看到的是配置指引页，不是登录表单。

| 页签 | 能做什么 |
|---|---|
| **总览** | 请求量 / 5xx 错误率 / P95 / 在途 / 限流与拒绝计数；最近 5 分钟的 QPS 与错误曲线；熔断器概况；状态码分布；监听端口与运行信息 |
| **路由** | 路由列表（三级匹配规则、实时请求数、熔断状态）一键启停、增删改；表单分「基础 · 转发 · IP 名单 · 限流 · 熔断 · 认证」。列表里有一列显示**这条路由用了哪些 IP 名单**（带白 / 黑角色 + 全局黑名单条数），表单里只勾引用、不写规则 |
| **IP 名单** | 三个区块：**① 地址列表库**（建 / 改名 / 改类型 / 改规则 / 删，并显示每份列表被哪些路由引用）、**② 全局黑名单**、**③ 命中测试** |
| **证书** | 每张证书的域名 / 签发者 / 到期时间 / 来源（ACME 还是手工上传），以及自动续期状态 |
| **日志** | 最近 500 条访问记录，按状态 / 路由 / 方法 / 关键字过滤，被拦截的请求单独标色；SSE 实时追加，可暂停、可跟随滚动 |
| **配置** | `default_ports` / `access_log` / `trusted_proxies` 的读写与手动重载；`admin_users` 与 `admin_addr` 只读并说明原因 |

几个和权限有关的点：

- **控制台的静态页面不鉴权** —— 它只是一堆公开的前端代码，不含机密；但它必须能先加载出来，你才有机会登录
  （否则就是「要登录才能打开页面、要页面才能登录」的死循环）。真正敏感的操作全在 `/_goproxy/*` 接口上，那些**一律**要凭据。
- `admin_users` 只以用户名形式出现在界面上，`password_hash` 从来不回传；会话凭据只存在 `HttpOnly` Cookie 里。

> 名单为什么单独占一个页签：三层名单共用同一条判定链，集中在一页维护、路由只勾引用，
> 「路由」页那一列则回答「这条路由到底受哪些名单管」—— 恰好是排查时要看的两个方向。
> 两边写的是同一份配置（同一个库），跨页保存会撞上 revision 校验（见[并发安全](#并发安全etag--if-match)），控制台会重读最新配置。

> 在 v0.6.0 及更早版本上经代理访问会**卡在「正在检查管理接口…」**（CSRF 比错了 host），v0.6.1 已修。
> 临时绕过：把 `admin_addr` 改成 `0.0.0.0:9080` 直接开控制台端口。

### 从别的机器 / 公网访问控制台

`admin_addr` 默认只听 `127.0.0.1`。**做法一**是直接暴露管理端口（`"admin_addr": "0.0.0.0:9080"`，热重载即生效，
代价是这个端口完全暴露 —— 确认有防火墙 / 安全组把关并配强密码）。

**做法二：用一条代理路由把控制台「发布」出去**（推荐，也是项目自己的部署形态）

```json
{
  "admin_addr": "127.0.0.1:9080",
  "routes": [
    { "id": "console", "name": "控制台", "listen_port": 32000,
      "path_prefix": "/", "target": "http://127.0.0.1:9080" }
  ]
}
```

于是 `http://<服务器IP>:32000/_goproxy/ui/` 就是控制台，管理端口仍只听回环。
这条路由**不会**让谁免登录：经代理进来的请求会带上内部标记头，管理端一看到就按「外部请求」处理。
两种做法下登录、会话、CSRF 行为完全一致。

### 自己构建控制台

控制台是 `web/` 下的 React + Vite 工程，产物 `web/dist` 由 `go:embed` 打进二进制。

```bash
cd web && npm install && npm run build      # 产物进 web/dist
cd .. && go build -o goproxy .              # go:embed 在编译期读 dist，所以要先构建前端

cd web && npm run dev                       # 调前端不必每次编译 Go，Vite 会代理管理接口
# 打开 http://127.0.0.1:5173/_goproxy/ui/
# 后端不在默认地址时：GOPROXY_ADMIN=http://127.0.0.1:9080 npm run dev
```

> `web/dist` **提交进仓库**：`go:embed` 要求目录必须存在，不提交的话别人 clone 下来直接 `go build` 会失败。
> CI 里有一道检查挡住「改了前端却忘了重新构建」。

---

## 管理端点

默认只监听 `127.0.0.1:9080`（`admin_addr` 可改）。控制台就建立在这些接口上，用 curl 也能直接操作。

| 你敲的地址 | 浏览器（`Accept` 含 `text/html`） | curl / 监控探针 |
|---|---|---|
| 接口路径（下表中的 `/healthz`、`/_goproxy/routes`…） | 原样返回数据，**不跳转** | 原样返回数据 |
| `/`、`/_goproxy`、`/_goproxy/` | 302 → `/_goproxy/ui/` | 纯文本接口清单 |
| 其余路径（`/index.html`、写错的地址…） | 302 → `/_goproxy/ui/` | 404 |

即**地址栏里随便敲哪个路径都会进控制台**，只有接口路径例外；curl 拼错接口会老实 404，不会用 200 的提示页伪装成功。

| 路径 | 方法 | 说明 |
|---|---|---|
| `/_goproxy/ui/` | GET | 管理控制台（静态页面，**不需要凭据**） |
| `/healthz` `/readyz` `/metrics` | GET | 存活 / 就绪（路由表未加载时 503）/ Prometheus 指标（**三个都要凭据**） |
| `/_goproxy/routes` | GET | 路由列表 + 实时观测值；响应带 `ETag` |
| `/_goproxy/routes` | POST | 新建路由，`id` 可省略（自动生成 `rt-xxxxxx`） |
| `/_goproxy/routes/{id}` | GET / PUT / PATCH / DELETE | 单条查 / 全量替换（未提到的回默认值）/ 局部更新（启停路由用它）/ 删除 |
| `/_goproxy/ports` | GET | 当前实际监听的端口，以及每个端口是否走 TLS |
| `/_goproxy/certs` | GET | 证书状态：域名、来源、签发者、到期时间、剩余天数、状态 |
| `/_goproxy/config` | GET | 全局配置（**不回传 `admin_token` 明文与 `password_hash`**；含 `ip_lists`） |
| `/_goproxy/config` | PATCH | 改 `default_ports` / `access_log` / `trusted_proxies` / `global_ip_deny` / `ip_lists` / `admin_token` / `admin_users`；配 `ip_list_renames`（`{"旧名":"新名"}`）可在同一次请求里把路由引用一起改写 |
| `/_goproxy/acl/test` | GET / POST | **命中测试**：拿一个地址跑一遍三层名单，看会被哪一层、哪份名单、哪条规则拦下。只读 |
| `/_goproxy/stats` | GET | 聚合状态：版本、uptime、指标汇总、熔断计数、采样曲线 |
| `/_goproxy/logs` | GET | 最近 N 条访问记录，`?limit=200`（上限 1000） |
| `/_goproxy/events` | GET | 实时访问日志，SSE 推送 |
| `/_goproxy/reload` | POST | 手动触发重载 |
| `/_goproxy/login` | POST | 用 `{"username","password"}` 或 `{"token"}` 换会话 Cookie（**在鉴权闸门之外**） |
| `/_goproxy/session` | GET / DELETE | 会话状态 / 登出（也接受 `POST`） |
| 其余 `/_goproxy/` 下的路径 | 任意 | 通过认证后 404；**没配任何凭据时一律 403** |

> 表里除控制台静态页面外**全部需要凭据**，包括三个探针 —— 本机访问也不例外。
> 不给探针豁免的理由：探针一旦免认证，就等于给了未认证调用者一个观测窗口（服务端活没活、有哪些路由、`/metrics` 的全部指标）。

### 管理端认证

v0.6.0 起有**两条并列的凭据**，任一通过即放行：

| 凭据 | 给谁用 | 怎么配 |
|---|---|---|
| **`admin_users`** —— 用户名 + bcrypt 密码哈希 | **给人**：浏览器登录控制台 | `goproxy -hash-password '密码'` 生成哈希，填进 `password_hash` |
| **`admin_token`** —— Bearer 令牌 | **给机器**：脚本 / Prometheus / 监控探针 | 直接写字符串 |

**一个都不配时，所有管理接口（含三个探针）返回 403 `admin_credentials_not_set`**，控制台显示配置指引页。
保存配置后自动热重载，加账号 / 改密码 / 删账号都是保存即生效。

```bash
# 浏览器登录：换取会话 Cookie
curl -s -X POST http://127.0.0.1:9080/_goproxy/login \
  -d '{"username":"admin","password":"你的密码"}' -i     # → 200，Set-Cookie: goproxy_admin_session=...
```

设计要点（每条都是刻意的）：

- **没有回环免认证**：本机访问一样要凭据 —— 否则从本机打开控制台永远绕过登录页，而线上排障又总是在本机做。
  判断来源只认 `RemoteAddr`，`X-Forwarded-For` 一律无视。
- **凭据合法性与会话有效性是同一件事**：会话指纹 = 「账号 + 该账号当前密码哈希」（令牌那条是 `sha256(admin_token)`），
  所以改密码 / 删账号 / 改令牌都会让相关会话**立刻失效**，不需要额外的吊销机制。
- **未知用户名也走一次 bcrypt**，否则用响应时间就能枚举用户名（实测错密码与不存在用户名的 401 响应体逐字节相同）。
- **`/login` 与 `/session` 在鉴权闸门之外**（代码里由 `isAuthPath()` 单独列出），否则未登录的浏览器永远走不到登录页；
  放行不等于不设防，这两条路径各带完整防护。
- **CSRF** 两层：`SameSite=Strict` + 显式同源校验，只对**写方法 + 会话鉴权**生效（`Bearer` 不随请求自动携带）。
  缺头时：会话写请求 fail-closed（跨站写请求一定会发 `Origin`），登录请求 fail-open（curl 本来就不发这两个头）。
- **登录防爆破**：单 IP 5 次失败封 10 分钟、全局 50 次封 1 分钟（挡换 IP 池）；响应恒定 ~400ms；`429` 带 `Retry-After`。
- **500 不回显内部信息**，只给一个短错误编号（详情进服务端日志，按 `error_id` 对账）—— 否则 `err.Error()` 里的绝对路径、
  `permission denied`、配置片段就是免费的信息收集。
- **安全响应头**：`nosniff` / `X-Frame-Options: DENY` / `X-Robots-Tag: noindex` / `Referrer-Policy: no-referrer`；
  控制台 CSP 是 `script-src 'self'`（所以首屏主题脚本是外链 `theme.js` 而非内联），接口 CSP 更严（`default-src 'none'`）。

会话 Cookie：`HttpOnly` + `SameSite=Strict` + `Path=/_goproxy/`（**不能**写 `/_goproxy/ui/` —— 接口不在 `ui/` 之下，
会导致「登录成功但刷新后仍然 401」）、服务端只存 `sha256(handle)`、空闲 30 分钟（滑动）/ 绝对 12 小时、上限 128 条。
登出走 `DELETE /_goproxy/session`（也接受 `POST`）。

「有意拒绝」和「配置漏了」在现象上都是打不开，所以把两者分开：

| 状态 | HTTP | 错误码 | 控制台 |
|---|---|---|---|
| 凭据已配、未登录 / 登录填错 | 401 | `unauthorized` | 用户名 + 密码登录表单（填错带提示） |
| **一个凭据都没配** | **403** | **`admin_credentials_not_set`** | **配置指引页**（含 `config.json` 片段和生成哈希的命令） |

`GET /_goproxy/session` 在未登录时也会带上 `"credentials_configured": false`，前端靠它区分这两种情况 ——
只用状态码判断的话，两者都是「没登录」。同理，没配凭据时 `POST /_goproxy/login` 返回 **403 而不是 401**：
401 意味着「密码错了」，会让人一直重试一个根本不存在的账号。

### 用法

```bash
A=http://127.0.0.1:9080
T='Authorization: Bearer 你的 admin_token'    # 脚本用令牌最省事

curl -s -H "$T" $A/_goproxy/routes | jq .      # 看路由（含熔断状态、请求数、在途数）

# 新建：同一个 IP 再开一个端口指向别的后端 → 端口立刻开始监听，不用重启
curl -s -H "$T" -X POST $A/_goproxy/routes -d '{
  "id": "svc-e", "name": "服务E", "listen_port": 8090,
  "path_prefix": "/", "target": "http://127.0.0.1:9005" }'

curl -s -H "$T" -X PATCH $A/_goproxy/routes/svc-e -d '{"enabled": false}'      # 停用
curl -s -H "$T" -X PATCH $A/_goproxy/routes/svc-e -d '{"rate_limit": {"rps": 20, "burst": 40}}'
curl -s -H "$T" -X PATCH $A/_goproxy/routes/svc-e -d '{"rate_limit": null}'    # 清掉某项嵌套配置
curl -s -H "$T" -X DELETE $A/_goproxy/routes/svc-e

# 没有 admin_token 时改用会话 Cookie
curl -s -c /tmp/gp.jar -X POST $A/_goproxy/login -d '{"username":"admin","password":"你的密码"}'
curl -s -b /tmp/gp.jar $A/_goproxy/routes | jq .
```

### 并发安全：ETag / If-Match

`GET /_goproxy/routes` 和 `GET /_goproxy/config` 都会返回 `ETag`，写请求带上 `If-Match` 即可让服务端把过期写拒掉
（两个标签页同时编辑时，避免后保存的静默覆盖前一个的改动）：

```bash
ETAG=$(curl -sI -H "$T" $A/_goproxy/routes | tr -d '\r' | awk '/^Etag:/ {print $2}')
curl -s -H "$T" -X POST $A/_goproxy/routes -H "If-Match: $ETAG" \
  -d '{"id":"new","listen_port":8091,"target":"http://127.0.0.1:9006"}'
# 若期间已有别人改过配置 → 409 revision_mismatch
```

不传 `If-Match` 就退化成「后写覆盖」（单向覆盖，仍是原子的，不会写进半份配置）。

### 写接口的几个行为约定

- **库里的当前配置是唯一真源**：每次写都是「读当前配置 → 改 → 校验 → 在一个事务里整份替换 → 热重载」，
  要么整份新配置落库、要么一个字段都不变，不存在「写了一半」的中间态。
- **校验不过就不落库**（非法 `target`、端口冲突这类一律 400，数据库一个字节都不会动），**热重载失败会自动回滚**。
- **每次写入前留一版**：上一版配置进 `config_history` 表（保留最近 20 版，按 revision 去重），
  比原来只留一份 `config.json.bak` 多一层余量 —— 改错了能往前翻好几步。
- **不写「默认值」**：配置里没写 `admin_addr` 时，写回也不会替你填上 —— 否则一次保存就会把原本关闭的管理端口打开。
- **`admin_addr` 不能通过接口改**（启动期就绑定了套接字），显式返回 400 而不是假装成功；
  改它请走 `-config-export` / `-config-import` 那条路再重启进程。
  写 `off` / `none` / `disabled` 可彻底关闭管理端口；留空表示用默认值。
- **`admin_users` 读得到、写也写得进，但回显里没有密码材料**：只返回用户名列表，`password_hash` 从不回传。
  PATCH 提交它是**整表替换**，记得把哈希一起带上。
- **`ip_lists` 是全量替换，不是逐个合并**（控制台总是把所有列表一起提交）；改名请用 `ip_list_renames` 显式声明。
- **几道 409 都是保护性拒绝，但处理方式不同**：`self_lockout`（规则会封掉自己）和 `list_in_use`（删的名单还被引用）
  是**你提交的东西本身有问题**，界面必须保留输入；`revision_mismatch` 是**你手上的副本过期了**，界面必须丢弃输入、重读最新配置。

> **破坏性变更**：`GET /_goproxy/routes` 现在返回**完整路由配置**（加上 `live` 实时字段），
> 不再是早先那个只有几个计算字段的精简形状 —— 编辑界面需要拿到可回写的完整字段。

---

## 监控数据源（前端就靠这三个）

> 三条**都要认证**，示例统一用 `T='Authorization: Bearer <admin_token>'`。

### `GET /_goproxy/stats` —— 一次拿全所有看板数字

```bash
curl -s -H "$T" http://127.0.0.1:9080/_goproxy/stats \
  | jq '{uptime_seconds, routes_active, ports, summary, circuit}'
```

| 字段 | 说明 |
|---|---|
| `summary.requests_total` / `summary.by_status` | 全部请求数；按状态码分桶，如 `{"200":120,"404":3}` |
| `summary.unmatched_total` | **没匹配到任何路由**的请求数，配置写歪了就看它 |
| `summary.error_rate` / `p95_ms` / `avg_ms` | 错误率与耗时（p95 由直方图桶估算） |
| `circuit` | 熔断器按状态计数 + 累计跳闸 / 快速失败次数 |
| `series` | 最近 5 分钟的**每秒增量**（`requests` / `errors` / `blocked`），直接画曲线 |
| `logs` | 缓冲条数、SSE 订阅者数、因订阅者太慢而丢弃的条数 |

`series` 由服务端每秒采样，**界面一打开就有历史曲线**；`circuit` 读的是熔断器当前真实状态，不走那个 5 秒同步一次的指标缓存 ——
跳闸了却要等 5 秒才看见，排查时会以为熔断没生效。

### `GET /_goproxy/logs` —— 最近 N 条

```bash
curl -s -H "$T" "http://127.0.0.1:9080/_goproxy/logs?limit=20" | jq '.entries[] | {seq, status, path, blocked}'
```

返回结构化字段（不是格式化好的文本，省得前端再解析一遍）。`blocked` 非空表示这条请求**没有被转发出去**，
值是拦截原因：`acl_global_deny` / `acl_route_allow_miss` / `acl_route_deny` / `rate_limited` / `circuit_open` / `auth_*`。
**被拦掉的请求也会进日志** —— 排查限流误伤、ACL 配错时全靠它。

### `GET /_goproxy/events` —— SSE 实时推送

```bash
curl -N -H "$T" http://127.0.0.1:9080/_goproxy/events

event: hello
data: {"latest_seq":128,"buffered":42}

id: 129
event: access
data: {"seq":129,"time":"2026-09-15T22:44:49.284+08:00","route":"r1","port":8081,...}
```

连上先发一个 `hello` 带当前 `latest_seq`（前端拿它和 `/logs` 的历史做去重）；每 20 秒一个 `: ping` 注释行保活；
响应带 `X-Accel-Buffering: no` —— 不加这个头，走 nginx 时事件会被缓冲，表现为「日志延迟几十秒甚至完全不动」。

> **访问日志缓冲始终在记录**（定长 500 条，只在内存、不落盘），它和管理台的实时日志是同一个东西；
> `access_log` 控制的是**标准输出**那条结构化日志。订阅者慢（标签页切后台、网络卡住）时消息**直接丢**并计数，
> 不会阻塞请求路径 —— 访问日志这种顺手做的事，绝不该有能力把整个代理拖死。

---

## 探针与健康检查

`/healthz`、`/readyz`、`/metrics` 三条路径**都要求凭据**（v0.6.0 起，本机访问也不例外）。
这几条配起来比业务接口更容易踩坑，因为**配置它们的地方往往不支持自定义请求头**：

| 场景 | 怎么配 |
|---|---|
| Prometheus | scrape config 加 `authorization: {type: Bearer, credentials: <admin_token>}` |
| Kubernetes 探针 | `httpGet` 支持 `httpHeaders`，带上 `Authorization: Bearer <token>` |
| `docker-compose` | 健康检查是 `CMD-SHELL`，直接用 `wget --header=...`（见下） |
| systemd / 简单脚本 | `nc -z 127.0.0.1 9080` 只探端口是否在听，绕开 HTTP 认证 |

```yaml
# docker-compose.yml 里的写法
test:
  - CMD-SHELL
  - >-
    wget -qO- --header="Authorization: Bearer $$GPROXY_ADMIN_TOKEN"
    http://127.0.0.1:9080/healthz | grep -q '^ok'
environment:
  GPROXY_ADMIN_TOKEN: ${GPROXY_ADMIN_TOKEN:-}
```

> **`$$` 是必须的**：compose 先把 `$` 当变量插值，写单个 `$` 的话到容器里就变成 `Authorization: Bearer `，
> 探针恒定 401，而 `docker ps` 只显示 unhealthy，看不出是变量没传进去。`$$` 才是「交给容器内部展开」。
>
> 只用 `admin_users`、没有 `admin_token` 的部署，`environment` 那行拿不到值，健康检查会失败 —— 改用 `nc -z 127.0.0.1 9080`。

---

## `listen_port` 怎么填

多端口分流的关键字段：`0` = 不挑端口（挂到**所有**监听端口上当兜底）；`8081` = 只有从 8081 进来的请求才匹配它；
`80` / `443` = 标准端口，通常与域名路由混用。

匹配顺序：**端口精确 → 端口兜底(0)**，端口内部再按 **host 精确 → host 通配(`*.x.com`) → host 任意(空)**，
最后按 **path 最长前缀**。同一个端口内部可以再分流：

```json
{ "id": "c", "listen_port": 8083, "path_prefix": "/api", "target": "http://127.0.0.1:9003", "strip_prefix": true },
{ "id": "d", "listen_port": 8083, "path_prefix": "/",    "target": "http://127.0.0.1:9004" }
```

不需要在启动参数里声明 8083 —— 路由里写了，端口就自动开。

---

## 熔断

单后端没法切流，所以熔断的价值是**快速失败**：后端已经挂了的时候，与其让每个请求都等到超时，不如立刻返回 503。

```json
{
  "id": "svc-cb", "listen_port": 8089, "target": "http://127.0.0.1:9099",
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
for i in $(seq 1 6); do curl -s --noproxy '*' -o /dev/null -w "%{http_code} " http://127.0.0.1:8089/; done
# → 502 502 502 503 503 503
```

「后端错误」的判定：**5xx 和连不上算，4xx 不算**（客户端的问题不该让后端背锅），**429 也不算**，否则限流会误触发熔断。

---

## 访问控制

四种方式可以按路由单独配，也能叠加。执行顺序固定为：

```
全局黑名单 → 路由匹配 → [IP 白名单 → IP 黑名单 → 限流 → 熔断 → 认证] → 转发
```

全局黑名单排在**路由匹配之前**是刻意的：扫描器挨个端口扫过来时压根不会命中任何路由，
把它放在路由匹配之后，那份名单就永远轮不到这些流量 —— 而那正是最需要拦下的流量。

### IP 名单（三份，统一管理）

> **v0.8.0 起名单不再内联写在路由里**，而是顶层 `ip_lists` 集中定义、路由按名字引用，见[升级](#升级三版都是破坏性变更)。

判定是**固定**的三层：

```
① 全局黑名单 global_ip_deny   → 命中即 403（对所有入口生效，含管理端口）
② 引用到的白名单列表们         → 一份都没命中即 403
③ 引用到的黑名单列表们         → 命中任意一份即 403
④ 都没拦下                     → 放行
```

三个容易搞错的地方：

- **白名单一旦被引用就只有一个含义：只允许名单内的地址。** 它是在收紧范围、不是额外放行，所以不存在
  「和黑名单谁优先」的问题 —— allow 永远先判。**一份 allow 列表都没引用**才是「不限制来源」。
- **全局黑名单不可被豁免**：地址即使落在某条路由引用的白名单里，只要命中全局黑名单照样 403。
  ②③ 是路由级的，只在那条路由上生效；① 是不分路由的。
- **同一层多份列表取并集**：「只允许办公网 + 只允许内网跳板」就是引用两份 allow 列表，各自维护、互不干扰。

#### 配置里长什么样

```json
{
  "global_ip_deny": [
    "203.0.113.7",
    { "cidr": "198.51.100.0/24", "note": "整段异常流量，2026-09 封" }
  ],
  "ip_lists": [
    { "name": "办公网", "kind": "allow",
      "rules": [{ "cidr": "10.0.0.0/8", "note": "办公网" }, "192.168.0.0/16"] },
    { "name": "内网跳板", "kind": "allow", "rules": ["172.16.0.0/12"] },
    { "name": "异常机", "kind": "deny", "rules": [{ "cidr": "10.0.0.66", "note": "老是异常流量" }] }
  ],
  "routes": [
    { "id": "office-only", "acl": { "lists": ["办公网", "内网跳板", "异常机"] } }
  ]
}
```

这份配置读出来就是：只允许办公网和内网跳板进来的流量，但其中 `10.0.0.66` 这台单独拉黑，另外有一台外部地址被全局封禁。

**列表名就是引用键**，所以有几条硬约束（校验阶段就会拒，不会等请求来了才发现）：不能重名、首尾不能有空白
（`"办公网 "` 和 `"办公网"` 是两个不同的键）；不超过 64 字符、不能含 `/` 或换行（名字会进日志的同一行，
一个换行就能在日志里伪造出一条并不存在的记录）；`kind` 只能是 `allow` / `deny`（**空串会被拒** —— 默认成哪个都是猜，
猜错的后果是这个地址段被放行）；引用不存在的名字拒绝保存 / 启动，并列出可用名字（fail-closed）。

条目两种写法都收，可以混着写：

| 写法 | 含义 |
|---|---|
| `"10.0.0.0/8"` | 纯字符串 = 不带备注 |
| `{ "cidr": "10.0.0.66", "note": "老是异常流量" }` | 带备注 |

单个 IP 不写 CIDR 会自动按 /32 处理（IPv6 按 /128）。`note` 只用于展示与排查：它会出现在访问日志的拦截原因和
**命中测试**结果里，回答「这个地址当初到底是为什么被封的」。没有备注的条目**会回写成字符串简写** ——
否则一次控制台保存就会把每条规则都撑成 `{"cidr": …}`，导出来的配置就不再是给人读的。

空白名单里有一条要小心：

| | 结果 |
|---|---|
| `kind: "allow"` + 空 `rules` | **报错**。它一旦被引用就只剩「只允许名单内的地址」一个含义，会让引用它的路由拒绝所有请求 —— 这是配置事故，不是意图 |
| `kind: "deny"` + 空 `rules` | 放行。空黑名单只是什么都不禁，没有危害 |

#### 在控制台里改

| 想改什么 | 在哪 |
|---|---|
| 建 / 改名 / 改类型 / 改规则 / 删一份地址列表 | 「IP 名单」页的「① 地址列表库」区块 |
| ① 全局黑名单 | 同页的「② 全局黑名单」区块，改完点「保存并生效」 |
| ② ③ 某条路由引用哪些列表 | 「路由」页该行的「IP 名单」列（一眼看到引用了什么），或路由表单里的「IP 名单」子页签（按类型勾选） |
| 想先验证一下再保存 | 「IP 名单」页的「③ 命中测试」面板 |

判定顺序就印在这一页上，不用来回翻。几条和操作安全相关的：**「路由」页那一列带白 / 黑角色标记**，
该路由也受全局黑名单管着时还会标出全局黑名单有几条规则；**路由表单只勾引用、不写规则**，避免同一份名单有两个入口；
**改名会自动改写引用**（`ip_list_renames`，一次原子写）；**被引用的列表删不掉**（`409 list_in_use` 并点名在用的路由）；
**清空某项要显式表达** —— 名单是「合并语义」写进去的（PATCH 只改你提交的键），省略等于「不改」，名字一样、结果相反，
所以控制台清空时会显式提交 `null`。

#### 地址列表库：为什么是「引用」而不是「内联」

内联写法下「办公网」那段网段要在 5 条路由里各写一遍 —— 改一处要改 N 处，漏一处就是一条路由的防护没跟上；
而且同一份名单的角色、改名、以及「哪条路由用了它」都只能靠全文搜索。引用式把这三件事都收敛到一处维护。

#### 命中测试：保存之前先看一眼

三层名单有明确的先后顺序，光盯着配置列表很难在脑子里推出结果 —— 特别是同一个地址既落在引用的白名单里、
又命中某层黑名单的时候。所以有个只读接口：

```bash
# 拿一个地址 + 一条路由跑一遍，看它会被哪一层、哪份名单、哪条规则拦下
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9080/_goproxy/acl/test?ip=10.0.0.66&route_id=office-only"

# 不填 ip = 「测我自己」：用本次请求的来源地址判；不填 route_id = 只判全局那一层
curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9080/_goproxy/acl/test?route_id=office-only"
curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9080/_goproxy/acl/test?ip=203.0.113.7"
```

`decision.allowed` 是结论，`reason` 是给日志 / 指标用的短标签，`list` 是**命中的那份名单**
（多份名单并存时，只说规则回答不了「我该去哪份名单里删掉它」），`steps` 把三层逐条回放：

```json
{ "decision": {
    "ip": "10.0.0.66", "allowed": false,
    "layer": "黑名单", "list": "异常机", "rule": "10.0.0.66", "note": "老是异常流量",
    "reason": "acl_route_deny",
    "message": "命中黑名单「异常机」中的 10.0.0.66（老是异常流量）。",
    "steps": [
      { "layer": "全局黑名单", "configured": true, "matched": false, "detail": "2 条规则，未命中" },
      { "layer": "白名单", "list": "办公网", "configured": true, "matched": true, "rule": "10.0.0.0/8",
        "detail": "落在名单「办公网」内，继续判黑名单" },
      { "layer": "黑名单", "list": "异常机", "configured": true, "matched": true, "rule": "10.0.0.66",
        "detail": "命中，判定结束" } ] },
  "self": false, "route_name": "只允许办公网和内网跳板访问，但其中一台机器单独拉黑" }
```

两个字段是刻意留白的：**全局黑名单命中时 `list` 为空**（全局那份没有名字，硬填一个名字是假信息）；
**「整层没命中」时 `list` 也为空**（那一层可能有好几份名单，点其中一份的名会冤枉它）——
这时候该看 `detail`，它会列出这一层引用了哪几份名单、共几条规则。

它读的是**库里的当前配置**，也就是「保存之后会怎样」—— 改完先保存，再来这里验证。
控制台的「IP 名单」页有同一个工具。

#### 全局黑名单也管管理端口（以及自锁护栏）

`global_ip_deny` 是**全入口**的，管理端口同样算。所以在控制台里加一条覆盖自己来源的规则，保存生效之后你就打不开控制台了。
后端因此在写路径上加了一道**自锁检查**：保存前先拿新名单去匹配发起者的来源地址（直连与「经本进程自己的代理进来」两种来源都算），命中就拒绝：

```
HTTP/1.1 409 Conflict
{"error":"self_lockout","message":"这条规则会把你关在门外，已拒绝保存：新的 global_ip_deny 命中 10.0.0.5
（来自规则 10.0.0.0/8（办公网）），而它同样作用于管理端口 —— 保存生效之后，你现在用的这个控制台就打不开了。

如果确实要这么配：用 goproxy -config-export 导出一份 JSON、改完之后再用 goproxy -config-import
导回并重启进程 —— 那条路不受此检查限制。"}
```

拒绝时**库里的配置不会被改动**，控制台也**不会**把页面重载回当前状态 —— 否则你刚敲进去的那条规则会被擦掉，
而那正是最需要它的时候。它只是把错误提示挂在旁边，编辑内容原样留着。

> 只有**全局黑名单**有这个护栏，路由级名单没有：路由名单的锁定范围限于那条路由所挂的端口，界面上端口和目标就在同一屏，
> 属于「看得见」的风险；全局名单会静默作用于所有入口，那才是容易误判的。

万一真的需要封自己的网段，走 `-config-export` / `-config-import` 那条路（不受此检查限制，导回后重启进程生效）
—— 动手之前先想好怎么进去。
`/healthz`、`/metrics` 这些探针也在这份名单的管辖范围内，别指望它们还能当后门。

#### 拦截原因拆成了三个

同一个「被 IP 名单拦了」在日志和指标里是三个不同的标签，因为处理方式完全不同：

| `blocked` / `reason` | 含义 | 通常该怎么办 |
|---|---|---|
| `acl_global_deny` | 命中全局黑名单 | 去 `global_ip_deny` 里解除（它不在 `ip_lists` 里） |
| `acl_route_allow_miss` | 该路由引用了白名单，但地址一份都没命中 | 往那份 allow 列表里补一条，或者去路由上取消引用 |
| `acl_route_deny` | 命中该路由引用的某份黑名单 | 去那份 deny 列表里解除；命中测试能看到具体是哪一份 |

（环形缓冲里可能还留着 v0.6.x 的老标签 `acl`，控制台会把它显示成「旧版标签」。）

#### 一个容易踩的坑：名单按「客户端 IP」判，受 `trusted_proxies` 影响

名单取的是 `clientIP()` 的结果。如果前面还有一层反代或 CDN 没被加进 `trusted_proxies`，
名单看到的会是**上一跳的地址**：按它封禁会误伤整条链路，按它做白名单则会连自己都进不来。
控制台的路由表单在 `trusted_proxies` 为空时会专门提示这一点。

### Basic 认证

```json
"auth": { "mode": "basic", "realm": "goproxy",
          "basic": [{ "username": "admin", "password_hash": "$2a$10$..." }] }
```

密码用 bcrypt。图省事也可以写明文 `"password": "s3cret"`，启动时会打一条 warning 并打印对应的 hash，粘回配置即可。
bcrypt 单次几十毫秒，所以校验结果缓存 60 秒 —— 不然高并发下 CPU 全耗在算哈希上。

### JWT

```json
"auth": { "mode": "jwt",
          "jwt": { "secret": "demo-secret-change-me", "issuer": "goproxy-demo",
                   "audience": "my-api", "forward_claims": { "sub": "X-User-Id" } } }
```

也支持 RS256（配 `public_key_pem`）。`forward_claims` 把 claim 透传给后端（`X-USER-ID: user-42`），后端不用再解一次 token。
两条安全硬约束：**算法白名单**（只认配置里声明的算法，`alg: none` 永远被拒绝）；
**防算法混淆**（配了 RSA 公钥时，拿公钥当 HMAC 密钥伪造的 token 会被拒）。

```bash
# 生成一个测试用的 HS256 token
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

TLS 由顶层 `tls.enabled` 控制，每条路由用 `tls_mode` 决定自己的行为：

```jsonc
{
  "tls": {
    "enabled": true,          // 全局开关，关掉则所有路由都退回明文
    "https_port": 443,        // HTTPS 监听端口（HTTP 用下面 acme 的 http_port）
    "cert_dir": "data/certs", // 相对路径 → 相对配置库所在目录
    "acme": { "email": "you@example.com",
              "staging": false,    // true = 用 Let's Encrypt 测试环境，不占正式额度
              "directory_url": "" } // 留空按 staging 自动选；也可指向自建 ACME（如 step-ca）
  },
  "routes": [
    { "id": "web", "listen_port": 443, "host": "app.example.com",
      "tls_mode": "auto", "target": "http://127.0.0.1:9001" },
    { "id": "legacy", "listen_port": 8443, "host": "old.example.com",
      "tls_mode": "manual", "cert_file": "data/certs/old.crt", "key_file": "data/certs/old.key",
      "redirect_http": false, "target": "http://127.0.0.1:9002" },
    { "id": "plain", "listen_port": 8080, "tls_mode": "off", "target": "http://127.0.0.1:9003" }
  ]
}
```

| `tls_mode` | 含义 | 证书来源 |
|---|---|---|
| `auto` | 自动申请 + 自动续期 | ACME（Let's Encrypt），走 HTTP-01 |
| `manual` | 用你自己指定的证书 | `cert_file` / `key_file`，**支持热更新** |
| `off` | 该路由纯明文 | 无 |

路由不写 `tls_mode` 时默认跟随全局：全局开了就是 `auto`，没开就是 `off`。

**TLS 是按端口决定的，不是按路由** —— **一个端口要么全明文、要么全 TLS**：如果同一个端口对某些请求加密、
对另一些不加密，攻击者只要构造一个走明文的请求就能把流量降级（TLS stripping）。所以路由的 `listen_port`
就是它跑不跑 TLS 的依据。

**HTTP→HTTPS 跳转**：开着 TLS 时，打到明文端口（默认 80）的请求会 **301 跳到 HTTPS**，路径和 query 原样保留。
不想要跳转就在路由上写 `redirect_http: false`；`tls_mode: "off"` 的路由天然不跳。判断「这个请求是不是已经走了 TLS」
靠的是监听端口本身而不是请求头，所以不存在 `X-Forwarded-Proto` 被伪造导致的重定向死循环。

**80 端口的三个职责**，按顺序判断：① `/.well-known/acme-challenge/*` 交给 autocert 应答；
② 其余请求 301 到 HTTPS（除非路由写了 `redirect_http: false`）；③ 该端口上的 `tls_mode: "off"` 路由照常提供明文服务。

**证书热更新**：`manual` 模式的证书文件**每 30 秒轮询一次 mtime**，变了就重新加载，不用重启
（`sudo cp new.crt /etc/goproxy/data/certs/old.crt`）。重新加载**失败会继续用旧证书** ——
轮换期间写错文件不至于把站点搞挂，但错误会通过 `/certs` 暴露出来。

### ACME 的硬约束

| 约束 | 说明 |
|---|---|
| **HTTP-01 固定走 80** | 申请时必须能从公网访问你域名的 80 端口。所以 `listen_port` 自定义的路由**拿不到自动证书**，只能 `manual` 或 `off` |
| **TLS-ALPN-01 固定走 443** | 同上，443 也必须是标准端口 |
| **不能给裸 IP 签发** | Let's Encrypt 拒绝为 IP 地址签发证书，`auto` 只认域名 |
| **不支持泛域名** | `*.example.com` 需要 DNS-01 验证，demo 没做。泛域名请用 `manual` 挂通配证书 |
| **有严格频率限制** | 同一域名重复签发有每周限额，所以 `data/`（ACME 缓存）**必须持久化**，重启不能丢 |

验证阶段建议先开 `staging: true` 跑通流程，确认没问题再切正式环境。

### 查看证书状态

```bash
curl -s -H "$T" http://127.0.0.1:9080/_goproxy/certs | jq .
```

```jsonc
{ "tls_enabled": true,
  "acme_dir": "https://acme-v02.api.letsencrypt.org/directory",
  "certs": [
    { "domain": "app.example.com", "source": "acme", "issuer": "Let's Encrypt",
      "not_after": "2026-12-14T08:30:00Z", "days_left": 89, "state": "valid" },
    { "domain": "old.example.com", "source": "manual", "issuer": "My CA",
      "not_after": "2026-10-01T00:00:00Z", "days_left": 15, "state": "expiring" } ] }
```

`state` 有四种：`valid` / `expiring`（**剩不到 20 天**）/ `expired` / `error`（加载失败）。
加载失败时 `days_left` 是 0，别把它误读成「还有很久」—— 所以 `error` 的判断优先级高于 `expiring`。
控制台的「证书」页就是这么显示的，外加当前监听的端口及各端口是否走 TLS。

### 与自带部署脚本的配合

`install.sh` 会：给 systemd 单元加 `AmbientCapabilities=CAP_NET_BIND_SERVICE`（**非 root 也能绑 80/443**）；
把配置目录加进 `ReadWritePaths` **并且** `chown` 给服务账号（两件都得做 —— `ReadWritePaths` 只改挂载属性、
不改 Unix 权限，否则管理接口写配置库时会报 `attempt to write a readonly database`）；
把 `$CONFIG_DIR/data` 软链到 `/var/lib/goproxy/certs`（证书是状态不是配置，混在配置目录里，备份配置会连私钥一起带走）。

> 换成 SQLite 之后这一条**更要留意**：写入时要在库文件旁边建 `goproxy.db-wal` / `goproxy.db-shm`，
> 所以需要可写的是**目录本身**（不只是库文件），`chown` 也要覆盖这两个临时文件 —— `install.sh` 已经把它们一起纳进去了。

---

## 已知限制（demo 边界）

| 不做 | 原因 / 何时做 |
|---|---|
| 泛域名（`*.example.com`）自动证书 | 需要 DNS-01 验证。要泛域名就用 `manual` 挂通配证书 |
| 客户端证书（mTLS） | 没做。需要双向认证的话建议在上一层网关终结 |
| 访问日志落盘 | 只往标准输出写，没有内置文件轮转。需要留存就接 journal 或外部 logrotate |
| 路由变更审计 | 写接口目前不记录「谁在什么时候改了哪条路由」。多人共用管理端时会需要。`config_history` 只留内容、不留操作者 |
| 多实例共享状态 | 限流和熔断都是进程内内存，多副本各算各的；**写配置也是单机行为**，两个实例各写各的会互相覆盖。多副本需换成共享存储 + 一致性协议 |
| 会话持久化 | 会话存在进程内存里，**重启即全部失效**。单机自托管可接受（换来的是不引入存储依赖） |
| 权限分级 | 有多个账号了，但**账号之间没有权限差别** —— 任一账号登录后都是全权 |
| 改密码要手工 | 没有「修改密码」界面。靠 `goproxy -hash-password` 生成哈希，再用 `-config-export` / `-config-import` 换掉 `admin_users` 里的哈希（导回后重启生效） |
| 账号数量无上限但也没约束 | `admin_users` 是配置库里的明文结构，适合 1~5 个运维账号，不是给终端用户用的用户体系 |
| CSP 的 `style-src` 内联 | 保留 `'unsafe-inline'`，因为 React 的 `style={{...}}` 产出内联样式属性。去掉需要把动态样式全改成 CSS 变量，收益不抵成本 |

---

## 在线编译（GitHub Actions）

仓库里带了 `.github/workflows/ci.yml`，**push 上去就自动编译**，不需要本地装 Go：

| 触发条件 | 做什么 |
|---|---|
| push / PR 到 main | 先跑**管理控制台构建与一致性**：`npm ci` → `typecheck` → `build`，再校验提交进仓库的 `web/dist` 与重新构建的结果一致 |
| 同上 | gofmt 检查、`go vet`、`go test -race`（依赖上面的 console 任务先通过） |
| 同上 | 交叉编译 **linux/amd64 + linux/arm64** 静态二进制 |
| ~~同上~~ | ~~构建多架构 Docker 镜像并推到 `ghcr.io/<owner>/<repo>`~~ —— **暂时停用** |
| 打 tag `v*` | 额外创建 GitHub Release，把两个平台的 tar.gz 挂上去 |

> **Docker 镜像任务已停用**：job 整段注释在 `ci.yml` 里（保留完整定义，恢复时去掉行首注释即可）。
> 停用的只是「CI 自动构建并推送镜像」这一步 —— **发布不受影响**（`release` job 只依赖 `build`），
> `Dockerfile` / `docker-compose.yml` 原样保留。停用期间 `docker pull ghcr.io/...` 拉不到镜像，要用容器就跑 `docker build -t goproxy .`。
>
> `web/dist` 是提交进仓库的，那道一致性校验就是为了挡住「改了前端却忘了重新构建」。本地改完前端记得 `npm run build` 再提交。

拿编译产物：仓库页面 → **Actions** → 点进最新 run → 页面底部 **Artifacts** 下载 `goproxy-linux-amd64`（含二进制与 `config.example.json`）。

### 发布版本与发布说明

```bash
git tag v0.8.0 && git push origin v0.8.0
```

**发布说明只手写一遍，写在 annotated tag 的 message 里** —— 不写在提交信息里，也不指望 auto changelog：

```bash
cat > notes.md <<'EOF'
v0.8.0：一句话说清这版干了什么

正文……可以带表格、代码块、反引号。
EOF
git tag -a v0.8.0 -F notes.md && git push origin v0.8.0
```

CI 取 message 的第二行起当正文（第一行是标题），auto changelog 只作附录落在末尾。这样发布说明跟着 tag 走：
有版本控制、可 diff、不依赖谁去网页上点编辑。

> ⚠ **CI 里不能用本地 git 读 tag 说明**：`actions/checkout` 在 tag 触发的 run 里会把本地 `refs/tags/<tag>`
> **重写成指向 commit 的轻量标签**，而 `%(contents:body)` 对轻量标签返回的是**提交信息**。脚本不报错，
> 只是安静地把提交信息当发布说明发出去 —— v0.6.1 和 v0.7.0 都这么发错过一版。
> 现在改走 GitHub API 读 tag 对象（服务端权威，不受本地 ref 改写影响）。

发布后可以核对一遍：

```bash
python scripts/check_release_notes.py
# 需要 git credential 里有 github.com 的凭据；逐版本对比 release / tag正文 / commit 三个长度，退出码表示是否全对
```

> 公开仓库的 Actions 时长**完全免费且无上限**，只有私有仓库才受每月 2000 分钟限制。

---

## 安装到 Linux

### 一键安装（推荐）

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/Janson-Fang/goproxy_test1@main/install.sh | sudo bash
sudo systemctl enable --now goproxy && sudo journalctl -u goproxy -f
```

> 用 jsdelivr 取脚本而不是 `raw.githubusercontent.com`，因为后者在国内经常连不上。

脚本做的事：自动识别 amd64/arm64 → 校验 sha256（对不上直接中止）→ 装到 `/usr/local/bin` →
**已存在的配置库不会被覆盖**（`config.json` 只在库为空时作为种子被导入一次）→ 创建 `goproxy` 系统用户并以非 root 运行 →
**交互式引导你设置一个管理员账号**。

设置账号那一步：**密码不回显、要输两次**；**哈希由二进制自己算**（调 `goproxy -hash-password`，
不在脚本里重新实现一遍 bcrypt —— 服务端用什么校验这里就生成什么，不可能出现「算出来的哈希验不过」这种极难排查的故障）；
非交互环境读不到 `/dev/tty`，会**跳过提问并打印手动补法**；**升级时只在「一个凭据都没有」才问**，不会被反复打扰。

装完的收尾提示会直接把控制台地址和「有没有账号能进去」写出来：

```
  二进制    /usr/local/bin/goproxy
  配置库    /etc/goproxy/goproxy.db
  控制台    http://127.0.0.1:9080/_goproxy/ui/

控制台登录：用刚才设置的用户名 + 密码。
```

> 库为空时脚本会把 `$CONFIG_DIR/config.json`（老部署沿用旧的、全新安装铺一份示例）**导入一次**，
> 导入交给 `goproxy -config-import` 走完整校验 —— 失败就中止，**库不会被改坏**。
> 导入完成后那份 `config.json` 只是种子，**以后不再被读取**，可以留作备份或自行删掉。
> 全新安装另外会放一份 `config.json.example` 方便对照新增字段。
>
> **`VERSION=v0.8.0` 这类历史版本照旧能用**：脚本会先探一下装出来的二进制支不支持 SQLite
> 配置源（看它有没有 `-config-import`），不支持就走原来的 JSON 文件流程 ——
> 那时配置就是 `config.json`，没有库可导。不这么分流的话，对着旧二进制调 `-config-import`
> 会报 `flag provided but not defined`，现象是「装不上」，原因却是版本不匹配。

起来之后浏览器打开 **`http://<服务器IP>:9080/`** 就是控制台（要先登录）。默认 `admin_addr` 是 `127.0.0.1:9080`
只有本机能连；要开放到局域网 / 公网就改它，并**建议同时配一个 `admin_token`** 给探针用 —— 探针不方便走账号登录。

### 无人值守安装 / 常用变体

```bash
curl -fsSL .../install.sh | sudo bash -s -- --no-admin-prompt      # CI / 容器 / 批量部署：跳过交互提问
curl -fsSL .../install.sh | sudo NO_ADMIN_PROMPT=1 bash            # 同上，另一种写法
curl -fsSL .../install.sh | sudo VERSION=v0.3.0 bash               # 指定版本（推荐，避免 latest 解析依赖网络）
curl -fsSL .../install.sh | sudo bash -s -- --no-service           # 容器里用：只装二进制，不碰 systemd
curl -fsSL .../install.sh | BIN_DIR=$HOME/.local/bin CONFIG_DIR=$HOME/.goproxy bash -s -- --no-service   # 装到家目录
```

无人值守装出来的环境**一个凭据都没有**，管理接口全部 403 —— 这是**预期行为**而不是坏了，
装完记得用 `goproxy -hash-password` 补账号，或者准备好 `admin_token`。

不想用脚本的话，手动下载 Release 附件也一样（国内记得套一层镜像前缀）：

```bash
VERSION=v0.3.0; MIRROR=https://gh-proxy.com/     # 能直连 GitHub 就去掉这个前缀
curl -fsSL -o goproxy.tar.gz \
  "${MIRROR}https://github.com/Janson-Fang/goproxy_test1/releases/download/$VERSION/goproxy-linux-amd64.tar.gz"
tar -xzf goproxy.tar.gz && sudo install -m 0755 goproxy /usr/local/bin/goproxy
```

### 国内网络：脚本会自动走加速镜像

实测国内直连 GitHub 下载 Release **基本下不动**，所以脚本内置了加速通道，`MIRROR` 默认 `auto`：

| 取值 | 行为 |
|---|---|
| `auto`（默认） | 先试直连，失败或过慢自动切镜像；顺序 gh-proxy.com → ghfast.top → ghproxy.net |
| `direct` | 强制直连，不碰任何第三方 |
| `https://你的镜像/` | 只用指定前缀的镜像 |

```bash
curl -fsSL .../install.sh | sudo MIRROR=direct bash                  # 能顺畅访问 GitHub 的机器（如海外 VPS）
curl -fsSL .../install.sh | sudo MIRROR=https://gh-proxy.com/ bash   # 指定镜像
```

选路有两处细节：**直连给短超时（35s）、镜像给长超时（90s）** —— 93 字节的校验和文件能秒下，
不代表 7MB 的包也下得动，不能因为探测通过就一直等直连；**下载慢于 2KB/s 持续 20 秒直接换通道**。

**安全性**：镜像是第三方服务，只负责加速传输；下载完会用 Release 里的 `SHA256SUMS` 校验，**对不上直接中止**。
**已知坑**：镜像有缓存，刚发布的版本可能还没同步过去（表现为「校验和不匹配」），换直连或显式指定 `VERSION=`。

### 升级

**再跑一遍同一条命令就是升级**，没有单独的 upgrade 子命令。脚本会识别出「已经装过」，然后：

| 东西 | 升级时怎么处理 |
|---|---|
| `$BIN_DIR/goproxy` | **就地替换**：先写成 `goproxy.new` 再 `mv` 覆盖（rename 原子），不会出现「路径短暂不存在」的窗口；服务正在运行也没问题 —— 运行中的进程继续持有旧 inode，不会 `Text file busy` |
| `$BIN_DIR/goproxy.old` | 升级前的二进制自动留一份，出问题能一键回滚 |
| `goproxy.db`（配置库） | **已存在就完全不动** —— 库才是配置的真源，升级绝不覆盖它 |
| `config.json` | **只在库为空时**（首次从旧版本升上来）被导入一次，之后不再被读取。新版本的示例另存为 `config.json.example`，方便对照新增字段 |
| systemd 单元 | **先备份再重写**（`.bak`），因为 `ExecStart` 里带着本次的 `BIN_DIR` / `CONFIG_DIR`；你手动加过的 `Environment=` 之类会从 `.bak` 里找回来 |
| 服务 | **原来在跑就自动重启**，并轮询确认真的起来了；原来没跑就保持不启动 |

> 从 **v0.8.x 及更早版本**升上来时，脚本会先导一次 `config.json` 再起服务，导入失败就中止（库不动、错在哪一行直接打在终端上）。
> 升级路径与破坏性变更见文末[升级](#升级四版都是破坏性变更)。

> 最容易踩的一条：**光替换文件不重启，进程还在跑旧代码**，看着升级成功了其实没生效。不想让它动服务就加 `--no-restart`。

```bash
sudo cp -p /usr/local/bin/goproxy.old /usr/local/bin/goproxy && sudo systemctl restart goproxy   # 回滚
/usr/local/bin/goproxy -version                                   # 确认版本
systemctl show -p ExecMainStartTimestamp goproxy                  # 重启时间应该是刚刚
```

服务重启后没起来，脚本会**以非 0 退出**并直接把回滚命令和 `journalctl` 查看方式打出来。
可覆盖的环境变量还有 `SYSTEMD_DIR`（默认 `/etc/systemd/system`）和 `STATE_DIR`（默认 `/var/lib/goproxy`）。

### 控制台里升级

控制台的「升级」页把上面这套流程搬进了网页，**约定完全一致**：同一个仓库、同一份资源命名
（`goproxy-<os>-<arch>.tar.gz` / `SHA256SUMS-<arch>.txt`）、同一批镜像通道、同一个回滚文件名
（`goproxy.old`）。所以界面里装出来的东西和再跑一遍 `install.sh` 是同一个，排障时两种路子可以互换。

两条更新源：

| 来源 | 适合 |
|---|---|
| **GitHub Releases** | 常规升级。默认走 `Janson-Fang/goproxy_test1`，先直连、不通再依次试 `gh-proxy.com` / `ghfast.top` / `ghproxy.net` |
| **上传文件** | 内网 / 离线。传 `goproxy` 二进制或发布用的 `.tar.gz` 都行（按文件头自动识别并解包） |

```text
GET  /_goproxy/upgrade           当前版本、升级能力、备份与暂存状态
POST /_goproxy/upgrade/check     检查新版本（body 可省略，或 {"version":"v0.9.1"}）
POST /_goproxy/upgrade/upload    上传二进制（multipart 的 file 字段，或直接把文件当请求体）
POST /_goproxy/upgrade/install   {"source":"github"|"upload", "version":"", "sha256":"", "force":false}
POST /_goproxy/upgrade/rollback  回退到 <exe>.old
```

几个刻意的行为：

| 行为 | 为什么 |
|---|---|
| 换二进制之前先执行一次 `新文件 -version` | 校验和只能证明字节没坏，证明不了它能在这台机器上跑（下错架构的包哈希也是对的）。跑得起来才允许替换 |
| 旧二进制先备份成 `<exe>.old` | 和 `install.sh` 同一个文件名，回滚命令可以直接照抄 |
| 拿不到 `SHA256SUMS` 时**标出来**但继续 | 与 `install.sh` 保持一致；区别只在于界面和响应里会明说「未校验」，不是默默跳过 |
| 下载到的二进制自述版本比发布 tag 还旧就拒绝 | 镜像缓存旧文件时的典型症状是「升级成功了但版本没变」，直接拦住比事后排查省事 |
| 直连优先、镜像兜底，并且会放弃「连得上但龟速」的通道 | 和 `install.sh` 相同的取舍：镜像有缓存，刚发布的版本可能还拉不到 |
| 响应写完再替换进程 | `syscall.Exec` 会把当前进程镜像整个换掉，先写响应才拿得到结果 |

重启方式按平台自动选：Linux/macOS 用 `syscall.Exec` 原地替换（PID 不变，不依赖服务管理器）；
Windows 起一个新进程再退出旧进程（这条路是**尽力而为**：新进程要等旧进程释放端口，万一没起来就手动重启一次（二进制已经换好了，界面上还有「回退上一版」）。

> **能不能自升级由运行环境决定，界面上会直接说明原因。** 用 `go run` 起的实例、
> 或二进制所在目录不可写（systemd 里最常见的是 `ReadWritePaths` 没带这个目录），
> 升级页会显示为不可用并给出原因，而不是让人点一个注定失败的按钮。
>
> **容器里不建议开自升级**：容器内的文件系统是临时的，换掉容器里的二进制会被下次拉起镜像冲掉，
> 正确做法是换镜像 tag。Docker 场景请继续用「上传文件」那条路临时救急，或直接改部署描述。

可覆盖的环境变量（都只在服务端读）：

| 变量 | 默认 | 作用 |
|---|---|---|
| `GOPROXY_UPGRADE_REPO` | `Janson-Fang/goproxy_test1` | 发布源仓库（`owner/name`） |
| `GOPROXY_UPGRADE_MIRROR` | `auto` | `auto` / `direct` / 具体镜像前缀 |
| `GOPROXY_UPGRADE_MIRRORS` | `https://gh-proxy.com/ https://ghfast.top/ https://ghproxy.net/` | `auto` 模式下按顺序尝试的镜像 |
| `GOPROXY_UPGRADE_GITHUB` | `https://github.com` | GitHub 基址（自建 / 企业版） |
| `GOPROXY_UPGRADE_API` | `https://api.github.com` | 只用来兜底解析版本和取发布说明 |
### 版本号从哪来

版本号不在源码里写死，编译时由 git 推导（`Makefile` 与 CI 用同一套规则）：正好打在 tag 上是 `v0.4.0`；
tag 之后又有提交是 `v0.4.0-9-gef38364`（距该 tag 9 个提交）；有未提交改动末尾追加 `-dirty`；裸 `go build` 是 `dev`。
能查到的位置：`goproxy -version`、启动日志第一行、`/_goproxy/stats` 的 `version` 字段，以及控制台顶栏。

> **装出来的版本一直是旧版？** `install.sh` 默认装的是「最新 Release」（`/releases/latest`）。
> 所以只要这个仓库还没打新 tag，无论 `main` 上有多少新提交，一键安装拿到的都还是上一个 tag 的内容 ——
> 这不是脚本的问题，是确实没发版。想用 `main` 上的最新代码就自己编译，或者先发一版。

---

## 命令行

```bash
goproxy [-c 配置库] [-log-level 级别] [-text-log] [-version] [-hash-password 密码]
        [-config-import JSON] [-config-export JSON]
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `-c <路径>` | `goproxy.db` | **配置数据库**（SQLite）路径（**是 `-c`，不是 `-config`**） |
| `-log-level <级别>` | `info` | `debug` / `info` / `warn` / `error` |
| `-text-log` | 关 | 输出人类可读的文本日志。默认是 JSON，方便接日志系统 |
| `-version` | — | 打印版本与 commit 后退出 |
| `-hash-password <密码>` | — | 把密码算成 bcrypt 哈希后退出，用于填进 `admin_users[].password_hash` |
| `-config-import <JSON>` | — | 把一份 JSON 配置导入数据库后退出（走完整校验，失败不动原库） |
| `-config-export <JSON>` | — | 把数据库里的配置导出成 JSON 后退出（人可读，适合 diff / 备份） |

> 后两个子命令**都需要同时给 `-c`**，例如 `goproxy -c goproxy.db -config-export config.json`。
> 它们的作用和用法见[配置存在哪儿](#配置存在哪儿sqlitev090-起)。

**`goproxy -hash-password` 是设置 / 修改管理密码的唯一入口**（stdout 只有哈希本身，提示语走 stderr，
所以可以直接 `$(...)` 取用）：

```bash
goproxy -hash-password '你的新密码'      # → $2a$10$...
```

```jsonc
// 把输出填进 admin_users，再 -config-import 导回并重启
{ "admin_users": [{ "username": "admin", "password_hash": "$2a$10$..." }] }
```

> 不教你装 `htpasswd` 或写段 Python 算 bcrypt，是因为 cost 参数、salt 生成、编码任意一处不一致，
> 症状都是「登录永远失败」而没有任何报错。用这个命令拿到的哈希，和服务端校验用的是同一个库、同一份实现。
> `install.sh` 走的也是这条路。

也可以直接写明文 `"password": "..."`（和路由的 Basic 认证一致），
启动时会打一条 WARN 并把算好的哈希打印出来 —— 明文会留在配置里，生产环境别这么干。

---

## 手动编译部署

```bash
# 交叉编译（无需 CGO，静态二进制）
VERSION=$(git describe --tags --always --dirty)
COMMIT=$(git rev-parse --short=7 HEAD)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT" \
  -o goproxy .                        # 这两行 -X 别省，少了它二进制只会自报 "dev"
./goproxy -version                    # goproxy v0.4.0-9-gabc1234 (commit abc1234)

scp goproxy config.json user@server:/opt/goproxy/
```

装了 `make` 的机器（Linux / macOS）可以省掉上面这串：`make build`（编译，版本号自动带上）/
`make release`（先重建控制台再编译）/ `make version`（只看当前会用什么版本串）。

systemd unit（`/etc/systemd/system/goproxy.service`）：

```ini
[Unit]
Description=goproxy reverse proxy
After=network.target

[Service]
User=goproxy                 # 降权运行，得给服务账号配置目录的写权限（见下面 ReadWritePaths）
Group=goproxy
ExecStart=/opt/goproxy/goproxy -c /opt/goproxy/goproxy.db
WorkingDirectory=/opt/goproxy
Restart=always
RestartSec=3

AmbientCapabilities=CAP_NET_BIND_SERVICE   # 允许绑定 80/443 而不用 root
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

# 这个目录必须同时可读**可写**：管理接口写配置库时会在库文件旁边建 -wal / -shm
# （回滚时还有 -journal），写不进去就报 "attempt to write a readonly database"。
# 只读的话「删除路由」这类操作会失败，而且只在真正操作时才暴露。
# 把配置放 /etc/goproxy 时同理 —— 要一起放行，并且把属主给服务账号：
# ReadWritePaths 只解除只读挂载，不改 Unix 权限，目录还是 root:root 0755 的话服务照样写不进。
ReadWritePaths=/opt/goproxy

[Install]
WantedBy=multi-user.target
```

> **管理接口报 `attempt to write a readonly database` 或 `permission denied`？** 都是上面这条没配对，跟接口本身无关
> （`read-only file system` 也可能是同一处，只是内核对只读挂载和权限不足的措辞不同）。
> `install.sh` 装的话重跑一次即可；手写单元的补两件事：`ReadWritePaths` 加上配置目录，并 `chown <服务账号> <配置目录>`。

Docker：

```bash
# 配置要挂「目录」不能挂单个文件，两个理由都是硬故障：
#   · 写配置库时要在库文件**旁边**建 -wal / -shm，单文件挂载会把它们丢在容器临时层里，
#     容器一重建库就可能不完整；挂目录才能让它们跟库待在一起。
#   · 单文件挂载会让它在容器里变成挂载点。v0.8.x 的写回最后一步是 rename 覆盖它，
#     而内核禁止 rename 到挂载点（EBUSY），改成 :rw 也没用，
#     只会把 read-only file system 换成 device or resource busy。
# 宿主目录的属主要给容器里的 uid 10001，否则同样写不进去。
mkdir -p config data && cp config.json config/ && sudo chown -R 10001:10001 config data
# config.json 只是种子：容器第一次启动、库还是空的时候被导入一次，之后不再被读取。

docker compose up -d --build
# 或
docker build -t goproxy:demo . && docker run --network host \
  -v $PWD/config:/etc/goproxy -v $PWD/data:/etc/goproxy/data goproxy:demo
```

---

## 源码结构与测试

| 文件 | 职责 |
|---|---|
| `main.go` / `config.go` | 组装、请求入口、管理端点注册、热重载、优雅停机；配置结构与校验、`revision` 计算、route 级默认值 |
| `configstore.go` | **配置持久化层（SQLite）**：建表与 schema 版本、整份配置在一个事务里读写、`config_history` 归档、`config.json` 首次导入、`-config-import` / `-config-export` 的落地实现 |
| `admin_api.go` | 管理接口：认证闸门、路由 CRUD、全局配置读写、命名列表库写入（改名连带改写引用、删除前查引用）、登录与会话端点 |
| `admin_users.go` / `session.go` / `secheaders.go` | 账号表（bcrypt、会话指纹、未知用户名恒定耗时）；登录会话（句柄哈希、过期、限流、CSRF）；安全响应头与 CSP |
| `router.go` / `proxy.go` / `listener.go` | 三级匹配表（端口 → host → path，不可变快照）；ReverseProxy 封装（连接池、超时、XFF）；多端口监听管理 |
| `tlsconfig.go` / `tls.go` | TLS/ACME 配置与校验；证书管理器（按 SNI 分发、manual 热加载、autocert、证书状态） |
| `ratelimit.go` / `circuitbreaker.go` | 按 IP 分桶的令牌桶；滑动窗口熔断器 |
| `acl.go` | 三层 IP 名单：`global_ip_deny` + 命名列表库（`IPListSet` 解析一次供多路由共享，`Resolve` 按引用展开成 allow / deny 两组），由 `decideIP` 判定并产出可回放的 `Steps`（含命中的是哪份名单） |
| `auth.go` / `jwt.go` | Basic（bcrypt + 校验缓存）与 JWT 认证（带算法白名单） |
| `metrics.go` / `accesslog.go` / `stats.go` | Prometheus 指标 + 每秒采样曲线；访问记录环形缓冲（兼 SSE 广播源）；三个监控接口 |
| `webui.go` / `web/` | 内嵌并托管控制台（`go:embed`、缓存策略、SPA 回落、根路径分流）；前端工程（React 19 + Vite + TypeScript），产物 `web/dist` 提交进仓库 |
| `*_test.go` | 单测：路由匹配、熔断/ACL/JWT/Basic（`governance_test`）、管理接口 CRUD 与并发冲突、环形缓冲与 SSE、控制台托管、TLS，**配置存储层（`configstore_test`：字节级往返稳定、事务回滚、外键 RESTRICT / CASCADE、历史封顶、导入校验）**，另有两个守卫测试（示例配置必须能加载、部署文件必须暴露 443 且 `ReadWritePaths`/`chown` 到位） |
| `scripts/e2e_console.py` | 端到端自检（见下） |
| `scripts/check_release_notes.py` | 发布后核对：Release 正文是否来自 annotated tag 说明 |

```bash
go test ./...   # 跑测试
go vet ./...    # 静态检查

# 端到端自检：真实二进制 + 真实反代 + 4 个测试后端，覆盖控制台依赖的全部接口（含认证、SSE、
# 路由 CRUD + ETag 并发、三层 IP 名单 + 命名列表库 + 命中测试、配置库的 export/import 逃生通道）。
# 需要 PATH 里有 go 和 python3，产物落在临时目录；最后一节会刻意把管理端口封掉再恢复，所以它跑在最后。
python scripts/e2e_console.py
```

TLS 另有两个实机端到端脚本（仓库外的开发目录，自签证书 + 真实进程）：**`e2e_tls.py`** 逐个 SNI 校验
**证书链和域名**（用自签证书当 CA 做完整校验，而不是只看握手成功）；**`e2e_tls_reload.py`** 比对
**DER 指纹**（PEM 解码后再哈希，直接哈希 PEM 文件比的是错的字节），替换磁盘证书后等 30 秒轮询周期，
断言服务端换上了新证书且**没有重启**。

> ACME 的签发流程没有端到端覆盖 —— 本地没有公网域名，HTTP-01 拿不到证书，这部分靠单测
> （`TestACMEEffectiveDirectoryURL`、`TestAutoCertRejectsIPAndWildcard`、`TestAutoCertRejectsCustomPort` 等）。

---

## 升级（四版都是破坏性变更）

配置里的旧字段**任何取值都会让进程拒绝启动**，日志里直接给出映射表 —— 静默忽略的话，防护会在升级的一瞬间全部消失。
从更早的版本升上来要**按顺序连做多步迁移**（v0.5.x → v0.6.0 → v0.7.0 → v0.8.0 → v0.9.0），每步都是硬错误、都有明确报错。

### v0.8.x → v0.9.0：配置源从 JSON 文件换成 SQLite

**配置文件不再被读取**，配置的真源是 `goproxy.db`。迁移不用手工搬字段（还是同一个 `Config` 结构，字段一个没变），
要做的是「把旧文件里的配置弄进库里」，而这一步**默认自动完成**：

```bash
sudo systemctl stop goproxy
sudo systemctl edit goproxy        # ExecStart 里的 -c .../config.json 改成 -c .../goproxy.db
sudo systemctl start goproxy
journalctl -u goproxy | grep 导入  # 看到「已把旧的 config.json 导入配置数据库（只导入这一次）」就成了
```

一键脚本装的话连单元都不用改：**重跑一遍 `install.sh`** —— 它会自己判断库在不在、该不该导。

| 现象 | 原因 | 怎么办 |
|---|---|---|
| 启动报 `…… 不是 SQLite 数据库（看起来还是旧版的 JSON 配置文件）` | `-c` 还指着 `config.json` | 报错里直接给了两条出路：把 `-c` 改成 `goproxy.db`，或显式 `-config-import` 一次 |
| 升级后「配置全没了」 | 上面那条被忽略，进程在旁边建了个**空库** | 别慌，`config.json` 还在：`goproxy -c goproxy.db -config-import config.json` 导进去再重启 |
| 改 `config.json` 没反应 | **预期行为** —— 导入只做一次，之后文件不再被读取 | 改配置走控制台，或 `-config-export` → 改 → `-config-import` → 重启 / `POST /_goproxy/reload` |
| `-wal` / `-shm` 写不进去 | 目录不可写（不只是库文件） | `chown` 整个配置目录给服务账号，并加进 `ReadWritePaths`；`install.sh` 已经处理 |

> 为什么不做「发现库为空就导入」：那样你哪天删光所有路由、重启，旧文件里的内容会**突然复活**，
> 比不导入更难排查（现象是「删掉的路由自己又回来了」）。

### v0.7.x → v0.8.0：IP 名单从「内联」改成「引用」

内联写法下同一段网段要在 N 条路由里各写一遍，改一处要改 N 处，漏一处就是一条路由的防护没跟上。

| 旧写法（v0.7.x，已移除） | 新写法（v0.8.0） |
|---|---|
| `"acl": { "allow": ["10.0.0.0/8"], "deny": ["10.0.0.66"] }` | 顶层建两份列表（见下），路由写 `"acl": { "lists": ["办公网", "异常机"] }` |
| `"acl": { "allow": [...] }`（只想收紧来源） | `"acl": { "lists": ["办公网"] }`（只引用 allow 类列表） |
| 把 `acl` 整个去掉 | 不变（仍然表示这条路由不做 IP 限制） |
| 顶层 `"global_ip_deny": [...]` | **不变**，仍是独立一份，不进 `ip_lists` |

```json
"ip_lists": [
  { "name": "办公网", "kind": "allow", "rules": ["10.0.0.0/8"] },
  { "name": "异常机", "kind": "deny",  "rules": ["10.0.0.66"] }
]
```

- **角色（`kind`）定义在列表自己身上**，引用点只写名字，同一份列表在所有路由里角色一致。
  想要「A 路由当白名单、B 路由当黑名单」，就建两条列表 —— 那本来就是两件事，该有两个名字。
- 空白名单与 v0.7.x 一致：空 `allow` 被拒（引用它只剩「只允许名单内」，会让路由拒绝所有请求），空 `deny` 放行。
- 引用不存在的名字拒绝保存 / 启动，并列出可用名字（fail-closed）。写错名字若被当成「不限制来源」，就是一次无声的放行。
- 控制台改名走 `ip_list_renames`，服务端在同一个请求里把所有引用一起改写（原子写，不会出现引用悬空的中间态）；
  **还被引用的列表删不掉**，返回 `409 list_in_use` 并点名是哪几条路由在用。

### v0.6.x → v0.7.0：`mode` 二选一 → `allow` / `deny` 并存

| 旧写法（v0.6.x，已移除） | 新写法（v0.7.0） |
|---|---|
| `"acl": { "mode": "deny", "cidrs": [...] }` | `"acl": { "deny": [...] }` |
| `"acl": { "mode": "allow", "cidrs": [...] }` | `"acl": { "allow": [...] }` |
| `"acl": { "mode": "none" }` | 把 `acl` 整个去掉 |
| （旧版没有这个能力） | 顶层 `"global_ip_deny": [...]`，对**所有**入口生效，含管理端口 |

唯一例外是 `{"mode":"none"}`（等价于没有名单，放行并打一条提示）。条目从「纯 CIDR 字符串数组」扩展成
「字符串或 `{cidr, note}` 对象」，两种可混写，老的纯字符串数组照抄即可。

> **启用全局黑名单前先想清楚**：它作用于管理端口，配错了会把自己关在门外。控制台保存前有自锁检查会拦住，
> 走 `-config-export` / `-config-import` 那条路则完全不受检查 —— 动手前确认你还有别的进路（SSH 等）。

### v0.5.x → v0.6.0：强制登录

| 变更 | 现象 | 怎么办 |
|---|---|---|
| 本机访问不再免认证 | 以前 `curl 127.0.0.1:9080/_goproxy/routes` 直接 200，现在 **401** | 一律要凭据：脚本用 `Bearer <admin_token>`，浏览器去登录 |
| 登录从「贴令牌」改成「用户名 + 密码」 | 原来的令牌输入框没了 | 加 `admin_users`（见下） |
| 三个探针也要认证 | 监控探针、compose 健康检查开始 401/403 | 探针带上 `Authorization`，见[探针与健康检查](#探针与健康检查) |

错误码也从 `admin_token_not_set` 改名为 **`admin_credentials_not_set`**，有脚本 / 告警在匹配它要一起改。

```jsonc
// 加进 admin_users，再 -config-import 导回并重启生效
{ "admin_users": [{ "username": "admin", "password_hash": "$2a$10$..." }] }
```

**只配了 `admin_token` 也能正常用**，两条凭据路径并列（浏览器可用令牌登录）。推荐两个都配 —— 给人走账号、给机器走令牌。
老会话不会被立刻踢掉（会话绑定「账号当前密码哈希 + 令牌指纹」，会自然超时）；想立刻把所有人下线，改一下 `admin_token` 即可。

### 升级二进制

```bash
# 还在 v0.8.x 及更早（配置是 JSON 文件）：先看里面有没有老写法
grep -n '"mode"\|"allow"\|"deny"' /etc/goproxy/config.json
# 懒得手工搬就把 acl 整段删掉（等于不限制），升级后在控制台「IP 名单」页重建列表、勾引用

# 已经在 v0.9.0 上：配置在库里，先导出来再检查
goproxy -c /etc/goproxy/goproxy.db -config-export /tmp/cfg.json

curl -fsSL https://cdn.jsdelivr.net/gh/Janson-Fang/goproxy_test1@main/install.sh | sudo bash
```

重跑安装脚本就是升级：**已存在的配置库不会被覆盖**，`config.json` 只在库为空时被导入一次。

---

## 下一步

已完成 M1–M5（含 TLS / ACME 自动证书）、管理写接口、监控数据源、控制台前端、登录 / 会话 / 安全加固、
多用户账号体系与强制登录、三层 IP 名单的统一管理、**命名地址列表库**（集中定义 + 路由引用），
以及 **M5 正式版：配置源换成 SQLite**（关系表 + 外键引用完整性 + 配置历史）。

- **把控制台里的「改 config.json」文案收尾** —— 界面和提示里还有若干处按旧存储模式写的字样
  （改的是文件、改完靠轮询生效），要跟着 SQLite 一起改掉；`SettingsPage` 的「配置来源」一处已经改了
- **审计日志**：记录「谁在什么时候改了哪条路由」（有了账号表之后，写接口已经知道是谁在操作，缺的只是记下来）
- **权限分级**：账号之间现在没有区别，任一账号都是全权

> 完整的架构方案、数据模型与里程碑计划不在这个仓库里。

## 许可

MIT
