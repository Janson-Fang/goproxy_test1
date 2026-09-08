FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
# CGO 关闭 + 静态链接：得到的二进制可以直接扔进 scratch/alpine，不依赖 glibc
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/goproxy .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 goproxy
COPY --from=builder /out/goproxy /usr/local/bin/goproxy
COPY config.example.json /etc/goproxy/config.json

# 注意：业务端口由路由的 listen_port 动态决定。
# 用 bridge 网络时，需要在 docker run -p 里逐个映射，或者直接用 --network host。
EXPOSE 80 8081 8082 8083 9080

USER goproxy
ENTRYPOINT ["goproxy", "-c", "/etc/goproxy/config.json"]
