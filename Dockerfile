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
COPY config.example.json /etc/goproxy/config.json

# 注意：业务端口由路由的 listen_port 动态决定，镜像里声明多少都不全。
# 用 bridge 网络时需要在 docker run -p 里逐个映射，或者直接用 --network host。
EXPOSE 80 8081 8082 8083 9080

USER goproxy
ENTRYPOINT ["goproxy", "-c", "/etc/goproxy/config.json"]
