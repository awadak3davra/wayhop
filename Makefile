BIN     := wayhop
PKG     := wayhop
VERSION ?= 0.2.0-dev
LDFLAGS := -s -w -X $(PKG)/internal/version.Version=$(VERSION)

.PHONY: build run demo clean tidy vet mipsle mips arm arm64 all-arch

build:
	go build -ldflags "$(LDFLAGS)" -o dist/$(BIN) ./cmd/wayhop

# Run locally in demo mode (no sing-box needed) on :8088.
demo:
	go run ./cmd/wayhop --config ./dev-config.json --demo --listen :8088

run: build
	./dist/$(BIN) --config ./dev-config.json --demo --listen :8088

vet:
	go vet ./...

# --- Cross-compiles for common Entware targets ---
mipsle:
	GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-mipsle ./cmd/wayhop

mips:
	GOOS=linux GOARCH=mips GOMIPS=softfloat go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-mips ./cmd/wayhop

arm:
	GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-arm ./cmd/wayhop

arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-arm64 ./cmd/wayhop

amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-amd64 ./cmd/wayhop

all-arch: mipsle mips arm arm64 amd64

# Per-arch deploy tarballs:
#   wayhop-<ver>-<arch>.tar.gz          Entware /opt: binary + install/uninstall + sysvinit S99 script
#   wayhop-<ver>-<arch>-openwrt.tar.gz  OpenWrt native: binary + install/uninstall + procd init
package: all-arch
	@for a in mipsle mips arm arm64 amd64; do \
	  d="dist/pkg-$$a"; rm -rf $$d; mkdir -p $$d; \
	  cp dist/$(BIN)-$$a $$d/$(BIN)-$$a; \
	  cp packaging/install.sh packaging/uninstall.sh packaging/S99wayhop $$d/; \
	  tar -C $$d -czf dist/$(BIN)-$(VERSION)-$$a.tar.gz .; rm -rf $$d; \
	  echo "packaged dist/$(BIN)-$(VERSION)-$$a.tar.gz"; \
	  o="dist/pkg-$$a-openwrt"; rm -rf $$o; mkdir -p $$o; \
	  cp dist/$(BIN)-$$a $$o/$(BIN)-$$a; \
	  cp packaging/openwrt/install.sh packaging/openwrt/uninstall.sh packaging/openwrt/wayhop.init $$o/; \
	  tar -C $$o -czf dist/$(BIN)-$(VERSION)-$$a-openwrt.tar.gz .; rm -rf $$o; \
	  echo "packaged dist/$(BIN)-$(VERSION)-$$a-openwrt.tar.gz"; \
	done

clean:
	rm -rf dist
