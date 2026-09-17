# Go 版本必须与 go.mod 里声明的一致，否则构建阶段会报
# "go.mod requires go >= X"。升级 go.mod 时记得同步改这里。
ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src

# go.mod 和 go.sum 一起 COPY：只拷 go.mod 的话 go mod download 缺校验文件会失败
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# 管理控制台的资源来自 web/dist（由 web/ 下的 React+Vite 工程构建）。
# 它随仓库一起提交，所以这个镜像不需要 Node —— go:embed 在编译期直接把它打进二进制。
# 改了前端记得先在本地 `cd web && npm run build`，CI 里有一步专门挡这个。
#
# CGO 关闭 + 静态链接：得到的二进制可以直接扔进 scratch/alpine，不依赖 glibc
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/goproxy .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 goproxy
COPY --from=builder /out/goproxy /usr/local/bin/goproxy

# 配置目录必须归 goproxy 所有。管理接口改配置走的是原子写
# （写 config.json.tmp 再 rename 覆盖），容器又是以 uid 10001 跑的，
# /etc/goproxy 保持 root:root 0755 的话，点「删除路由」会 permission denied。
# 挂载了宿主机目录时以宿主目录的属主为准，compose 里有说明。
COPY config.example.json /etc/goproxy/config.json
RUN chown -R goproxy:goproxy /etc/goproxy

# 注意：业务端口由路由的 listen_port 动态决定，镜像里声明多少都不全。
# 用 bridge 网络时需要在 docker run -p 里逐个映射，或者直接用 --network host。
# 443 同理 —— 开了 tls.enabled 后 HTTPS 端口由 tls.https_port 决定，默认 443。
EXPOSE 80 443 8081 8082 8083 9080

# 容器内以非 root 运行（uid 10001）。Linux 上绑定 <1024 的特权端口需要
# CAP_NET_BIND_SERVICE；Docker 默认会给容器这个 capability，但 compose 里若显式
# 收窄了 cap_drop，就要把它加回来，否则 80/443 会 listen 失败。
# 若改用 `--user` 覆盖成别的 uid，或跑在更严格的运行时（K8s + restricted PSP），
# 就把 tls.http_port / tls.https_port 改成高端口，由外层 LB 做 443→8443 的转发。

# ACME 证书缓存目录（tls.acme.cache_dir 默认 data/certs）必须挂持久卷：
# Let's Encrypt 对重复签发有严格限流，容器重启后如果缓存丢了会反复申请，很容易被限流。
# 用 --network host 时挂到容器的 /var/lib/goproxy 即可，参考 docker-compose.yml。
VOLUME ["/var/lib/goproxy"]

USER goproxy
ENTRYPOINT ["goproxy", "-c", "/etc/goproxy/config.json"]
