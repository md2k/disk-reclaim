PY     ?= python3
# Oldest Python we support; macOS ships 3.9 as /usr/bin/python3.
PY_MIN ?= /usr/bin/python3
PREFIX ?= $(HOME)/bin

.PHONY: test check install uninstall clean

test: ## run the unit tests
	$(PY) -m unittest discover -s tests -v

check: ## compile and test with the oldest supported Python
	$(PY_MIN) --version
	$(PY_MIN) -m py_compile reclaim.py tests/test_reclaim.py
	$(PY_MIN) -m unittest discover -s tests

install: ## link reclaim into PREFIX (default ~/bin)
	mkdir -p $(PREFIX)
	chmod +x reclaim.py
	ln -sf $(CURDIR)/reclaim.py $(PREFIX)/reclaim

uninstall:
	rm -f $(PREFIX)/reclaim

clean:
	rm -rf build __pycache__ tests/__pycache__
