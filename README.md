# goproxy —— 最小可跑版（demo）

一个用 Go 写的 L7 HTTP 反向代理，核心验证 **「同一 IP 不同端口 → 不同后端」**（场景 C）以及按域名/路径分流。

demo 已经做到 M4：转发、多端口分流、热重载、限流、**熔断**、**访问控制（IP 黑白名单 / Basic / JWT）**、
**TLS / ACME 自动证书**，外加**管理写接口、监控数据源和网页版管理控制台**。

仍然**故意不做**：SQLite（配置仍用 JSON 文件）、泛域名自动证书、mTLS。这些按正式方案的 M5–M7 迭代。

---

## 一分钟跑起来

```bash
# 1. 启动几个测试后端（另开终端，或用 & 放后台）
go run ./backend -port 9001 -name 服务A &
go run ./backend -port 9002 -name 服务B &
go run ./backend -port 9003 -name 服务C &
go run ./backend -port 9004 -name 服务D &

# 2. 启动反代
go run . -c config.json -text-log
```

看到这两行就说明起来了：

```
INFO 配置已生效 routes=5 ports=[8000 8081 8082 8083] admin=127.0.0.1:9080
INFO 管理端口已启动 addr=127.0.0.1:9080
```

注意 `ports` 里没有 9001–9004 —— 那是后端，不是监听端口。反代监听的是 **8000/8081/8082/8083**。

浏览器打开 **<http://127.0.0.1:9080/>** 就是管理控制台（路由增删改、实时日志、指标看板都在那里，
详见[管理控制台](#管理控制台网页版)）。

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

四个页签：

| 页签 | 能做什么 |
|---|---|
| **总览** | 请求量 / 5xx 错误率 / P95 / 在途 / 限流与拒绝计数；最近 5 分钟的 QPS 与错误曲线；熔断器概况；状态码分布；监听端口与运行信息 |
| **路由** | 路由列表（三级匹配规则、实时请求数、熔断状态），一键启停；新建 / 编辑 / 删除；表单分「基础 · 转发 · 限流 · 熔断 · 认证与 ACL」五组 |
| **日志** | 最近 500 条访问记录，按状态 / 路由 / 方法 / 关键字过滤，被拦截的请求单独标色；SSE 实时追加，可暂停、可跟随滚动 |
| **配置** | `default_ports` / `access_log` / `trusted_proxies` / `admin_token` 的读写与手动重载；`admin_addr` 只读并说明原因 |

几个和权限有关的点，部署前值得看一眼：

- **控制台的静态页面不鉴权。** 它只是一堆公开的前端代码，不含任何机密；但它必须能先加载出来，
  你才有机会输入 `admin_token`。如果连页面壳都要鉴权，就成了「要令牌才能打开页面、
  要页面才能填令牌」的死循环。真正敏感的操作全在 `/_goproxy/*` 接口上，那些**一律**受令牌保护。
- 管理端口监听在**非回环地址**时没有配 `admin_token`，后端会拒绝所有外部管理请求
  ——这是防止管理接口裸奔的闸门。控制台会识别这种情况并给出处理指引。
- 令牌只存在浏览器的 `localStorage` 里，以 `Authorization: Bearer` 发出，不发给任何第三方。

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
| `/_goproxy/ui/` | GET | 管理控制台（静态页面，**不需要令牌**；见上一节） |
| `/healthz` | GET | 存活探针 |
| `/readyz` | GET | 就绪探针（路由表未加载时 503） |
| `/metrics` | GET | Prometheus 文本格式指标 |
| `/_goproxy/routes` | GET | 路由列表，带实时观测值；响应带 `ETag` |
| `/_goproxy/routes` | POST | 新建路由，`id` 可省略（自动生成 `rt-xxxxxx`） |
| `/_goproxy/routes/{id}` | GET | 单条路由 |
| `/_goproxy/routes/{id}` | PUT | 全量替换（未提到的字段回默认值） |
| `/_goproxy/routes/{id}` | PATCH | 局部更新，启停路由就用它 |
| `/_goproxy/routes/{id}` | DELETE | 删除 |
| `/_goproxy/ports` | GET | 当前实际监听的端口，以及每个端口是否走 TLS |
| `/_goproxy/certs` | GET | 证书状态：域名、来源、签发者、到期时间、剩余天数、状态 |
| `/_goproxy/config` | GET | 全局配置（**不回传 `admin_token` 明文**） |
| `/_goproxy/config` | PATCH | 改 `default_ports` / `access_log` / `trusted_proxies` / `admin_token` / `admin_trust_loopback` |
| `/_goproxy/stats` | GET | 聚合状态：版本、uptime、指标汇总、熔断计数、采样曲线 |
| `/_goproxy/logs` | GET | 最近 N 条访问记录，`?limit=200`（上限 1000） |
| `/_goproxy/events` | GET | 实时访问日志，SSE 推送 |
| `/_goproxy/reload` | POST | 手动触发重载 |
| `/_goproxy/login` | POST | 用 `admin_token` 换取会话 Cookie（**在鉴权闸门之外**，见下节） |
| `/_goproxy/session` | GET | 当前会话状态：`authenticated` / `via` / `has_session` / `token_set` |
| `/_goproxy/session` | DELETE | 登出（吊销会话 + 清 Cookie；也接受 `POST`） |

### 认证

管理接口能改路由，等于能改流量走向，**不能裸奔**。

控制台是网页，让用户把 `admin_token` 贴在浏览器里既不安全也不好用，
所以管理端提供**三条**鉴权路径，任一通过即放行：

| 来源 | 要求 |
|---|---|
| 1. 回环地址（`127.0.0.1` / `::1`），且**不是经本进程代理转发进来的** | 免认证 |
| 2. `Authorization: Bearer <admin_token>` | curl / 脚本 / Prometheus 用 |
| 3. 会话 Cookie（控制台登录后拿到） | 浏览器用，`HttpOnly`，脚本读不到 |

`admin_addr` 监听了非回环地址但没配 `admin_token` 时，**所有外部请求一律 403** ——
宁可打不开，也不能让人随便改配置。

> 判断来源只认 `RemoteAddr`。`X-Forwarded-For` 是客户端随手就能写的头，
> 拿它判断「是不是本机」等于把认证决定权交给攻击者。这条有单测和端到端验证盯着。

#### 控制台登录（会话）

浏览器打开控制台时，如果没有会话，会看到一个令牌输入框：

1. `POST /_goproxy/login`，body `{"token":"<admin_token>"}`
2. 校验通过 → 下发 `HttpOnly` 会话 Cookie，**前端立刻丢弃内存里的令牌**
3. 之后所有请求靠 Cookie 鉴权；用户再也看不到、也不需要持有令牌

令牌本身**不落任何持久化存储**：前端只放在模块级内存变量里，
刷新页面即丢失，所以每次刷新都要重新登录（对单机自托管是可接受的取舍）。

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
| 绑定令牌指纹 | `sha256(admin_token)` | **改 `admin_token` 即全部会话立刻失效**，不需要额外的吊销机制 |

登出走 `DELETE /_goproxy/session`（也接受 `POST`），会吊销会话并清 Cookie。

##### 登录防爆破

| 机制 | 参数 |
|---|---|
| 单 IP 失败封禁 | 5 次 → 10 分钟 |
| 全局失败封禁 | 50 次 → 1 分钟（挡换 IP 池） |
| 响应时间 | 恒定 ~400ms，抹平时序侧信道 |
| 失败响应 | 空令牌与错令牌**完全一致**（否则等于告诉攻击者服务端有没有配令牌） |

`429` 会带 `Retry-After`（加了抖动，避免所有客户端同时重试）。

##### CSRF

`SameSite=Strict` 是第一层，显式校验是第二层（纵深防御，代价几乎为零）。
只对**写方法 + 会话鉴权**生效：`Bearer` 不随请求自动携带，本来就没有 CSRF 面，
不该给 curl 增加负担。

两种校验策略，差别只在「两个头都没有」时怎么办：

| 场景 | 策略 | 理由 |
|---|---|---|
| 会话写请求 | **fail-closed**：缺头即拒 | 能走到这里说明带了 Cookie，而浏览器跨站写请求**一定**会发 `Origin`；缺头就可疑 |
| 登录请求 | **fail-open**：缺头放行 | 登录本来就没有 Cookie，curl/脚本也不发这两个头。跨站攻击**一定**会发 `Origin`/`Sec-Fetch-Site`，所以放行的只是「本来就非浏览器」的请求，不构成 CSRF 面。一律 fail-closed 会让 `curl -d '{"token":...}' /_goproxy/login` 直接 403 |

##### 为什么 `/login` 必须在鉴权闸门**之外**

`POST /_goproxy/login` 和 `GET /_goproxy/session` 这两条路径**不经过** `adminGuard`。

这不是随手放行：登录接口的职责就是「在还没有凭据的时候拿到凭据」，
放在闸门之内等于把钥匙锁在屋里 —— 未登录的浏览器只会拿到 401，
永远走不到登录页。代码里由 `isAuthPath()` 单独列出，安全评审只需看这一个函数。

放行不等于不设防，两条路径各自带完整防护（见上面的防爆破与 CSRF 表）。
其余所有管理接口仍然一律经过 `adminGuard`，没有任何豁免。

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

#### 为什么「回环免认证」还要额外加一个条件

光看 `RemoteAddr` 是不够的，因为**代理转发到管理端口时，源地址就是 `127.0.0.1`**。
于是「把某条路由的 `target` 指向管理端口」就等于给外部客户端开了一道免认证的后门：

```jsonc
// 危险配置示例：外部访问 8081 就能白拿全部管理权限
{ "id": "bad", "listen_port": 8081, "path_prefix": "/",
  "target": "http://127.0.0.1:9080" }
```

实测确认过：这样经代理访问 `/_goproxy/config`、甚至 `POST /_goproxy/reload`
都是 `200`，等于完全接管（改路由 = 劫持全部流量）。

所以代理转发时会写入一个标记头，管理端**只要看到这个头就按外部请求处理**，
不再因为来源是回环而放行。这个头不需要保密，也不靠保密生效：

- 伪造它只会让判断更严，对攻击者不利；
- 省略它也躲不开 —— 经代理进来的请求，代理一定会写进去。

反过来，用一条 TLS 路由把管理面板发布出去（比如 `host: admin.example.com`）
**是完全可行的**，只是访问它时必须带令牌（或先登录）—— 因为那确实是一次外部访问。

#### `admin_trust_loopback`

```jsonc
{ "admin_trust_loopback": false }
```

默认 `true`（保持本机 curl / 脚本免令牌的习惯）。当管理端口前面**还挂着别的本地反向代理**
（nginx、Caddy 等）时应当设为 `false`：那种转发同样来自 `127.0.0.1`，
且不会带本进程的标记头，「回环 = 本机运维」这个前提就不成立了。

可以运行时改（`PATCH /_goproxy/config`），不用重启。

### 用法

```bash
A=http://127.0.0.1:9080

# 看路由（含熔断状态、请求数、在途数等实时值）
curl -s $A/_goproxy/routes | jq .

# 新建：同一个 IP 再开一个端口指向别的后端
curl -s -X POST $A/_goproxy/routes -d '{
  "id": "svc-e", "name": "服务E",
  "listen_port": 8090, "path_prefix": "/",
  "target": "http://127.0.0.1:9005"
}'
# → 端口 8090 立刻开始监听，不用重启也不用改启动参数

# 停用 / 启用（PATCH 只覆盖你写了的字段）
curl -s -X PATCH $A/_goproxy/routes/svc-e -d '{"enabled": false}'
curl -s -X PATCH $A/_goproxy/routes/svc-e -d '{"enabled": true}'

# 改限流，其它字段原样保留
curl -s -X PATCH $A/_goproxy/routes/svc-e -d '{"rate_limit": {"rps": 20, "burst": 40}}'

# 清掉某项嵌套配置：显式传 null
curl -s -X PATCH $A/_goproxy/routes/svc-e -d '{"rate_limit": null}'

# 删除
curl -s -X DELETE $A/_goproxy/routes/svc-e
```

管理端口开到外网时：

```bash
# config.json 里设置 admin_token 后
curl -s -H "Authorization: Bearer $TOKEN" http://10.0.0.5:9080/_goproxy/routes
```

### 并发安全：ETag / If-Match

两个浏览器标签同时编辑时，后保存的会覆盖前一个的改动（lost update）。
`GET /_goproxy/routes` 和 `GET /_goproxy/config` 都会返回 `ETag`，
写请求带上 `If-Match` 即可让服务端把过期写拒掉：

```bash
ETAG=$(curl -sI $A/_goproxy/routes | tr -d '\r' | awk '/^Etag:/ {print $2}')

curl -s -X POST $A/_goproxy/routes \
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

> **破坏性变更**：`GET /_goproxy/routes` 现在返回**完整路由配置**（加上 `live` 实时字段），
> 不再是早先那个只有几个计算字段的精简形状。编辑界面需要拿到可回写的完整字段。

```bash
curl -s http://127.0.0.1:9080/_goproxy/routes | jq .
curl -s http://127.0.0.1:9080/metrics | grep goproxy_requests_total
```

---

## 监控数据源（前端就靠这三个）

管理台需要的数据在这一层就取全了，前端不必去解析 Prometheus 文本。

### `GET /_goproxy/stats` —— 一次拿全所有看板数字

```bash
curl -s http://127.0.0.1:9080/_goproxy/stats | jq '{uptime_seconds, routes_active, ports, summary, circuit}'
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
curl -s "http://127.0.0.1:9080/_goproxy/logs?limit=20" | jq '.entries[] | {seq, status, path, blocked}'
```

返回结构化字段（不是格式化好的日志文本，省得前端再解析一遍）。`blocked` 非空表示
这条请求**没有被转发出去**，值是拦截原因：`acl` / `rate_limited` / `circuit_open` / `auth_*`。
被拦掉的请求也会进日志 —— 排查限流误伤、ACL 配错时全靠它。

### `GET /_goproxy/events` —— SSE 实时推送

```bash
curl -N http://127.0.0.1:9080/_goproxy/events
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
| 多用户 / 权限分级 | 只有「知道 `admin_token` 就能全权操作」这一档。没有只读账号、没有按路由授权 |
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

脚本做的事：自动识别 amd64/arm64、校验 sha256（对不上直接中止）、**已存在的 `config.json` 不会被覆盖**、创建 `goproxy` 系统用户并以非 root 运行。装完按提示改配置，然后：

```bash
sudo systemctl enable --now goproxy
sudo journalctl -u goproxy -f
```

起来之后浏览器打开 **`http://<服务器IP>:9080/`** 就是管理控制台。
如果要把控制台开放到非本机访问，记得先改 `admin_addr` 并设置 `admin_token`
（默认的 `127.0.0.1:9080` 只有本机能连，最安全）。

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
| `webui_test.go` | 控制台托管单测：内嵌资源、缓存头、SPA 回落、静态壳免鉴权但接口仍鉴权 |
| `tls_test.go` | TLS 单测：按 SNI 分发、通配匹配、热加载、续期告警阈值、跳转逻辑、ACME 约束 |
| `example_config_test.go` | 守卫测试：`config.example.json` 必须能加载，部署文件必须暴露 443 |
| `deploy_test.go` | 部署守卫：单元 `ReadWritePaths` 含配置目录、`install.sh` 改属主、Dockerfile `chown`、compose 挂目录而非单文件 |
| `session_test.go` | 会话与登录单测：存储哈希、过期、限流、Cookie 属性、CSRF、端点可达性、恒定耗时 |
| `scripts/e2e_console.py` | 端到端自检：真实后端 + 真实反代，107 项断言（含认证与会话一节） |

```bash
go test ./...   # 跑测试
go vet ./...    # 静态检查

# 端到端自检：会用真实二进制起 4 个测试后端 + 反代，
# 覆盖控制台依赖的全部接口（静态资源、根路径分流、限流/认证真实流量、
# stats/logs、SSE、路由 CRUD + ETag 并发、全局配置、Prometheus 指标、
# 以及三条鉴权路径 / 登录 / CSRF / 登出 / 安全响应头）。
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

已完成 M1–M4（含 TLS / ACME 自动证书）、管理写接口、监控数据源、管理控制台前端，
以及**登录 / 会话 / 安全加固**（三条鉴权路径、会话 Cookie、防爆破、CSRF、安全响应头）。

接下来：

- **配置源换成 SQLite（M5 正式版）** —— `loadConfig` 换掉即可，HTTP 层与前端不动
- 审计日志：记录「谁在什么时候改了哪条路由」
- 多用户与权限分级（现在只有「知道 `admin_token` 即全权」一档）

> 完整的架构方案、数据模型与里程碑计划不在这个仓库里。

## 许可

MIT
