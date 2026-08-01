PYTHON ?= python3
GO ?= go

.PHONY: all check crypto-evidence-check crypto-go-check go-check kat license-check test

all: check

check: license-check crypto-evidence-check crypto-go-check go-check test

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

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v
