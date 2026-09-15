# goproxy —— 最小可跑版（demo）

一个用 Go 写的 L7 HTTP 反向代理，核心验证 **「同一 IP 不同端口 → 不同后端」**（场景 C）以及按域名/路径分流。

demo 已经做到 M3：转发、多端口分流、热重载、限流、**熔断**、**访问控制（IP 黑白名单 / Basic / JWT）**。

仍然**故意不做**：TLS/ACME、Web 管理界面、SQLite。这些按正式方案的 M4–M7 迭代。

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

## 管理端点

默认只监听 `127.0.0.1:9080`（`admin_addr` 可改），**只有 API，没有界面**，
所以直接浏览器打开根路径只会看到几行纯文本。

| 路径 | 方法 | 说明 |
|---|---|---|
| `/healthz` | GET | 存活探针 |
| `/readyz` | GET | 就绪探针（路由表未加载时 503） |
| `/metrics` | GET | Prometheus 文本格式指标 |
| `/_goproxy/routes` | GET | 路由列表，带实时观测值；响应带 `ETag` |
| `/_goproxy/routes` | POST | 新建路由，`id` 可省略（自动生成 `rt-xxxxxx`） |
| `/_goproxy/routes/{id}` | GET | 单条路由 |
| `/_goproxy/routes/{id}` | PUT | 全量替换（未提到的字段回默认值） |
| `/_goproxy/routes/{id}` | PATCH | 局部更新，启停路由就用它 |
| `/_goproxy/routes/{id}` | DELETE | 删除 |
| `/_goproxy/ports` | GET | 当前实际监听的端口 |
| `/_goproxy/config` | GET | 全局配置（**不回传 `admin_token` 明文**） |
| `/_goproxy/config` | PATCH | 改 `default_ports` / `access_log` / `trusted_proxies` / `admin_token` |
| `/_goproxy/stats` | GET | 聚合状态：版本、uptime、指标汇总、熔断计数、采样曲线 |
| `/_goproxy/logs` | GET | 最近 N 条访问记录，`?limit=200`（上限 1000） |
| `/_goproxy/events` | GET | 实时访问日志，SSE 推送 |
| `/_goproxy/reload` | POST | 手动触发重载 |

### 认证

管理接口能改路由，等于能改流量走向，**不能裸奔**。

| 来源 | 要求 |
|---|---|
| 回环地址（`127.0.0.1` / `::1`） | 免认证 |
| 其它地址 | 必须 `Authorization: Bearer <admin_token>` |

`admin_addr` 监听了非回环地址但没配 `admin_token` 时，**所有外部请求一律 403** ——
宁可打不开，也不能让人随便改配置。

> 判断来源只认 `RemoteAddr`。`X-Forwarded-For` 是客户端随手就能写的头，
> 拿它判断「是不是本机」等于把认证决定权交给攻击者。这条有单测和端到端验证盯着。

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

## 已知限制（demo 边界）

| 不做 | 原因 / 何时做 |
|---|---|
| TLS / ACME 证书 | M4。且自定义端口拿不到自动证书（HTTP-01 固定走 80），只能跑明文或挂手动证书 |
| Web 管理界面 | **后端接口已全部就绪**（路由 CRUD + `stats` + `logs` + SSE `events`），前端待做。现在只能用 curl / 脚本操作 |
| 访问日志落盘 | 只往标准输出写，没有内置文件轮转。需要留存就接 `systemd` 的 journal 或外部 logrotate |
| SQLite | M1 正式版。现在用 JSON 文件，`loadConfig` 换掉即可，下游不动 |
| 路由变更审计 | 写接口目前不记录「谁在什么时候改了哪条路由」。多人共用管理端时会需要 |
| 多实例共享状态 | 限流和熔断都是进程内内存，多副本各算各的。另外**写配置也是单机行为**，两个实例各写各的会互相覆盖，多副本场景需要换成共享存储 + 一致性协议。预留了接口，后续换 Redis / SQLite |

---

## 在线编译（GitHub Actions）

仓库里带了 `.github/workflows/ci.yml`，**push 上去就自动编译**，不需要本地装 Go：

| 触发条件 | 做什么 |
|---|---|
| push / PR 到 main | gofmt 检查、`go vet`、`go test -race` |
| 同上 | 交叉编译 **linux/amd64 + linux/arm64** 静态二进制 |
| 同上 | 构建多架构 Docker 镜像并推到 `ghcr.io/<owner>/<repo>` |
| 打 tag `v*` | 额外创建 GitHub Release，把两个平台的 tar.gz 挂上去 |

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

---

## 手动编译部署

```bash
# 交叉编译（无需 CGO，静态二进制）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o goproxy .

# 放到服务器
scp goproxy config.json user@server:/opt/goproxy/
```

systemd unit（`/etc/systemd/system/goproxy.service`）：

```ini
[Unit]
Description=goproxy reverse proxy
After=network.target

[Service]
ExecStart=/opt/goproxy/goproxy -c /opt/goproxy/config.json
WorkingDirectory=/opt/goproxy
Restart=always
RestartSec=3

# 允许绑定 80/443 而不用 root，比直接跑 root 安全
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/goproxy

[Install]
WantedBy=multi-user.target
```

Docker：

```bash
docker compose up -d --build
# 或
docker build -t goproxy:demo . && docker run --network host -v $PWD/config.json:/etc/goproxy/config.json:ro goproxy:demo
```

---

## 源码结构

| 文件 | 职责 |
|---|---|
| `main.go` | 组装、请求入口、管理端点注册、配置热重载、优雅停机 |
| `config.go` | 配置结构与校验、配置文件的原子写入与 revision |
| `admin_api.go` | 管理接口：认证闸门、路由 CRUD、全局配置读写 |
| `router.go` | 三级匹配表（端口 → host → path），不可变快照 |
| `proxy.go` | ReverseProxy 封装：连接池、超时、XFF、真实 IP 解析 |
| `listener.go` | 多端口监听管理，按路由表变化自动增删 |
| `ratelimit.go` | 按 IP 分桶的令牌桶（带过期清理） |
| `circuitbreaker.go` | 滑动窗口熔断器（closed / open / half-open） |
| `acl.go` | IP 黑白名单（CIDR） |
| `auth.go` | Basic（bcrypt + 校验缓存）与 JWT 认证器 |
| `jwt.go` | JWT 校验：HS256/384/512、RS256，带算法白名单 |
| `metrics.go` | Prometheus 指标 + 实时观测值 + 每秒采样曲线 |
| `accesslog.go` | 访问记录的定长环形缓冲，兼作 SSE 广播源 |
| `stats.go` | `stats` / `logs` / `events` 三个监控接口 |
| `router_test.go` | 路由匹配单测 |
| `governance_test.go` | 熔断、ACL、JWT、Basic 单测 |
| `admin_api_test.go` | 管理接口单测：CRUD、并发写冲突、认证、坏配置不落盘 |
| `stats_test.go` | 环形缓冲、采样序列、SSE、并发重载单测 |

```bash
go test ./...   # 跑测试
go vet ./...    # 静态检查
```

---

## 下一步

已完成到 M3，外加管理写接口与监控数据源（原本属于 M6 的后端部分）。
接下来：**React 管理台前端**（消费这些接口）→ TLS/ACME。

> 完整的架构方案、数据模型与里程碑计划不在这个仓库里。

## 许可

MIT
