PYTHON ?= python3

.PHONY: all check license-check test

all: check

check: license-check test

license-check:
	$(PYTHON) scripts/check_dependency_licenses.py

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v
