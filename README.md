# goproxy —— 最小可跑版（demo）

一个用 Go 写的 L7 HTTP 反向代理，核心验证 **「同一 IP 不同端口 → 不同后端」**（场景 C）以及按域名/路径分流。

demo 的目的是**先把转发和多端口分流跑通**，所以它**故意不做**：TLS/ACME、Web 管理界面、SQLite、熔断、访问控制（JWT/Basic）。这些在正式方案里按 M3–M7 迭代。

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

| 路径 | 说明 |
|---|---|
| `GET /healthz` | 存活探针 |
| `GET /readyz` | 就绪探针（路由表未加载时返回 503） |
| `GET /metrics` | Prometheus 文本格式指标 |
| `GET /_goproxy/routes` | 当前生效的路由表 |
| `GET /_goproxy/ports` | 当前实际监听的端口 |
| `POST /_goproxy/reload` | 手动触发重载 |

```bash
curl -s http://127.0.0.1:9080/_goproxy/routes | jq .
curl -s http://127.0.0.1:9080/metrics | grep goproxy_requests_total
```

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

## 已知限制（demo 边界）

| 不做 | 原因 / 何时做 |
|---|---|
| TLS / ACME 证书 | M4。且自定义端口拿不到自动证书（HTTP-01 固定走 80），只能跑明文或挂手动证书 |
| Web 管理界面 | M6。现在只有管理 API |
| SQLite | M1 正式版。现在用 JSON 文件，`loadConfig` 换掉即可，下游不动 |
| 熔断 | M3。单后端无法切流，只能快速失败 |
| 访问控制（JWT/Basic/IP 黑白名单） | M3。目前只有按 IP 的限流 |
| 多实例共享限流 | 现在是进程内内存，多副本各算各的。预留了接口，后续换 Redis |

---

## 部署到 Linux

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
| `main.go` | 组装、请求入口、管理 API、配置热重载、优雅停机 |
| `config.go` | 配置结构与校验 |
| `router.go` | 三级匹配表（端口 → host → path），不可变快照 |
| `proxy.go` | ReverseProxy 封装：连接池、超时、XFF、真实 IP 解析 |
| `listener.go` | 多端口监听管理，按路由表变化自动增删 |
| `ratelimit.go` | 按 IP 分桶的令牌桶（带过期清理） |
| `metrics.go` | Prometheus 指标 |
| `router_test.go` | 匹配逻辑单测 |

```bash
go test ./...   # 跑测试
go vet ./...    # 静态检查
```

---

## 下一步

demo 跑通后按 M3 → M7 推进：熔断与访问控制 → TLS/ACME → 可观测性补全 → SQLite + Web 管理界面。

> 完整的架构方案、数据模型与里程碑计划不在这个仓库里。

## 许可

MIT
