# goproxy 构建入口。
#
# 版本号不写死在源码里，一律由 git 推导：
#   正好在 tag 上        → v0.4.0
#   tag 之后又有提交     → v0.4.0-9-gef38364
#   改了但没提交         → 末尾追加 -dirty
# 这样任何二进制都能一眼看出它对应哪段代码，不用去猜、也不会所有版本
# 都显示成同一个数字。CI 用的是同一套规则（见 .github/workflows/ci.yml）。
#
# 想看当前会用什么版本串：make version

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo none)

# -s -w 去掉符号表与 dwarf，体积能小一半
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

BIN := goproxy

.PHONY: all build release console test vet fmt e2e version clean

all: build

# 编译 Go 二进制。假定 web/dist 已是最新 —— CI 里有一步硬校验它和源码一致。
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) .

# 从源码完整走一遍：先重建控制台，再编译。
release: console build

console:
	cd web && npm ci --no-audit --no-fund && npm run build

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# 端到端自检。它会自己 go build 出临时二进制，跑完即回收。
e2e:
	python3 scripts/e2e_console.py

version:
	@echo $(VERSION)

clean:
	rm -f $(BIN) goproxy-test.exe backend-test.exe
