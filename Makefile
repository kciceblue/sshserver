PYTHON ?= python3
GO ?= go
DIST_DIR ?= dist
VERSION ?= dev
RUNTIME_GOOS ?=
RUNTIME_GOARCH ?=

.PHONY: all check crypto-evidence-check crypto-go-check go-check kat license-check runtime-build-one runtime-go-check runtime-release runtime-release-check runtime-vendor-check test

all: check

check: license-check runtime-vendor-check crypto-evidence-check crypto-go-check go-check runtime-go-check runtime-release-check test

crypto-evidence-check:
	$(PYTHON) scripts/check_crypto_kats.py --verify-evidence

crypto-go-check:
	$(PYTHON) scripts/check_crypto_kats.py --run-go

kat:
	$(PYTHON) scripts/check_crypto_kats.py --run

go-check:
	$(GO) mod verify
	$(GO) vet -mod=readonly ./...
	$(GO) test -mod=readonly ./...

license-check:
	$(PYTHON) scripts/check_dependency_licenses.py

runtime-vendor-check:
	$(PYTHON) scripts/check_runtime_vendor.py

runtime-go-check:
	cd runtime && $(GO) mod verify
	cd runtime && $(GO) vet -mod=readonly ./...
	cd runtime && $(GO) test -mod=readonly ./...

runtime-build-one:
	test -n "$(RUNTIME_GOOS)"
	test -n "$(RUNTIME_GOARCH)"
	mkdir -p "$(DIST_DIR)"
	cd runtime && CGO_ENABLED=0 GOOS="$(RUNTIME_GOOS)" GOARCH="$(RUNTIME_GOARCH)" $(GO) build -mod=readonly -trimpath -ldflags "-X github.com/kciceblue/sshserver/runtime/internal/cli.Version=$(VERSION)" -o "../$(DIST_DIR)/sshserver-$(RUNTIME_GOOS)-$(RUNTIME_GOARCH)" ./cmd/sshserver

runtime-release:
	$(MAKE) runtime-build-one RUNTIME_GOOS=linux RUNTIME_GOARCH=amd64
	$(MAKE) runtime-build-one RUNTIME_GOOS=linux RUNTIME_GOARCH=arm64
	$(MAKE) runtime-build-one RUNTIME_GOOS=darwin RUNTIME_GOARCH=amd64
	$(MAKE) runtime-build-one RUNTIME_GOOS=darwin RUNTIME_GOARCH=arm64

runtime-release-check: runtime-release
	$(PYTHON) scripts/check_runtime_release.py --dist "$(DIST_DIR)" --version "$(VERSION)" --execute-native

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v
