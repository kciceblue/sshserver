PYTHON ?= python3
GO ?= go
DIST_DIR ?= dist
RELEASE_ARTIFACT_DIR ?= $(DIST_DIR)/.release-artifacts/$(VERSION)
RELEASE_BUNDLE_DIR ?= $(DIST_DIR)/releases/$(VERSION)
VERSION ?= dev
SOURCE_REVISION ?= dev
BUILD_TOOLCHAIN ?= $(shell GOENV=off GOTOOLCHAIN=local $(GO) env GOVERSION)
BUILD_ATTESTATION ?= dev
DOWNLOAD_ORIGIN ?=
RUNTIME_GOOS ?=
RUNTIME_GOARCH ?=

.PHONY: all check crypto-evidence-check crypto-go-check go-check kat license-check runtime-build-one runtime-fuzz-smoke runtime-go-check runtime-release runtime-release-bundle runtime-release-bundle-check runtime-release-bundle-one runtime-release-check runtime-release-source-check runtime-vendor-check test

all: check

check: license-check runtime-vendor-check crypto-evidence-check crypto-go-check go-check runtime-go-check runtime-fuzz-smoke runtime-release-check test

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

runtime-fuzz-smoke:
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzDecodeStrictJSON$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/store
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzStoredJSONShapes$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/store
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzStoreScalarAndStoredParsers$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/store
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzPathIdentifier$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/store
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzOperationReceiptKey$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/store
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzParsePinnedManifest$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/deployment
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzParseDeploymentPreview$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/deployment
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzDecodeDeploymentMetadata$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/deployment
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzParseBuildIdentityJSON$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/deployment
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzDeploymentScalarParsers$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/deployment
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzDecodeAdminRequest$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/server
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzDecodeConfigJSON$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/config
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzDecodeCLIResponses$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/cli
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzParseAttestation$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/buildinfo
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzParseUUIDv4$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/uuidv4
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzReleaseIdentifier$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/releaseid
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzInstallCommandInput$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/releasebundle
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzValidLocalMainVersion$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/releasebundle
	cd runtime && $(GO) test -mod=readonly -run '^$$' -fuzz '^FuzzHeaderContainsToken$$' -fuzztime=64x -fuzzminimizetime=64x -parallel=1 ./internal/httpapi

runtime-build-one:
	test -n "$(RUNTIME_GOOS)"
	test -n "$(RUNTIME_GOARCH)"
	if test "$(VERSION)" != dev; then test "$(BUILD_ATTESTATION)" != dev; fi
	mkdir -p "$(DIST_DIR)"
	@set -eu; \
		output_dir="$$( $(PYTHON) -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "$(DIST_DIR)")"; \
		cd runtime; \
		GOENV=off GOWORK=off GOFLAGS= GOEXPERIMENT= GOTOOLCHAIN=local GOAMD64=v1 GOARM64=v8.0 CGO_ENABLED=0 GOOS="$(RUNTIME_GOOS)" GOARCH="$(RUNTIME_GOARCH)" $(GO) build -mod=readonly -buildmode=exe -buildvcs=true -tags="" -trimpath -ldflags "-X github.com/kciceblue/sshserver/runtime/internal/buildinfo.EncodedIdentity=$(BUILD_ATTESTATION)" -o "$$output_dir/sshserver-$(RUNTIME_GOOS)-$(RUNTIME_GOARCH)" ./cmd/sshserver

runtime-release:
	$(MAKE) runtime-build-one RUNTIME_GOOS=linux RUNTIME_GOARCH=amd64
	$(MAKE) runtime-build-one RUNTIME_GOOS=linux RUNTIME_GOARCH=arm64
	$(MAKE) runtime-build-one RUNTIME_GOOS=darwin RUNTIME_GOARCH=amd64
	$(MAKE) runtime-build-one RUNTIME_GOOS=darwin RUNTIME_GOARCH=arm64

runtime-release-bundle-one:
	test -n "$(RUNTIME_GOOS)"
	test -n "$(RUNTIME_GOARCH)"
	@set -eu; \
		build_attestation="$$(cd runtime && GOENV=off GOWORK=off GOFLAGS= GOEXPERIMENT= GOTOOLCHAIN=local $(GO) run -mod=readonly ./cmd/releasebundle attestation --release "$(VERSION)" --source-revision "$(SOURCE_REVISION)" --build-toolchain "$(BUILD_TOOLCHAIN)" --os "$(RUNTIME_GOOS)" --architecture "$(RUNTIME_GOARCH)")"; \
		test -n "$$build_attestation"; \
		$(MAKE) runtime-build-one RUNTIME_GOOS="$(RUNTIME_GOOS)" RUNTIME_GOARCH="$(RUNTIME_GOARCH)" BUILD_ATTESTATION="$$build_attestation"

runtime-release-source-check:
	$(PYTHON) scripts/check_release_source.py --root "$(CURDIR)" --revision "$(SOURCE_REVISION)"

runtime-release-bundle: runtime-release-source-check
	test -n "$(DOWNLOAD_ORIGIN)"
	$(MAKE) runtime-release-bundle-one RUNTIME_GOOS=linux RUNTIME_GOARCH=amd64 DIST_DIR="$(RELEASE_ARTIFACT_DIR)"
	$(MAKE) runtime-release-bundle-one RUNTIME_GOOS=linux RUNTIME_GOARCH=arm64 DIST_DIR="$(RELEASE_ARTIFACT_DIR)"
	$(MAKE) runtime-release-bundle-one RUNTIME_GOOS=darwin RUNTIME_GOARCH=amd64 DIST_DIR="$(RELEASE_ARTIFACT_DIR)"
	$(MAKE) runtime-release-bundle-one RUNTIME_GOOS=darwin RUNTIME_GOARCH=arm64 DIST_DIR="$(RELEASE_ARTIFACT_DIR)"
	@set -eu; \
		repository_root="$$(pwd -P)"; \
		artifact_dir="$$( $(PYTHON) -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "$(RELEASE_ARTIFACT_DIR)")"; \
		bundle_dir="$$( $(PYTHON) -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "$(RELEASE_BUNDLE_DIR)")"; \
		cd runtime; \
		GOENV=off GOWORK=off GOFLAGS= GOEXPERIMENT= GOTOOLCHAIN=local $(GO) run -mod=readonly ./cmd/releasebundle generate --artifacts "$$artifact_dir" --dist "$$bundle_dir" --license "$$repository_root/LICENSE" --notice "$$repository_root/NOTICE" --release "$(VERSION)" --source-revision "$(SOURCE_REVISION)" --build-toolchain "$(BUILD_TOOLCHAIN)" --download-origin "$(DOWNLOAD_ORIGIN)"

runtime-release-bundle-check: runtime-release-bundle
	$(PYTHON) scripts/check_runtime_release.py --dist "$(RELEASE_BUNDLE_DIR)" --version "$(VERSION)" --execute-native

runtime-release-check: runtime-release
	$(PYTHON) scripts/check_runtime_release.py --dist "$(DIST_DIR)" --version "$(VERSION)" --execute-native

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v
