#-------------------- ONLY MODIFY CODE IN THIS SECTION --------------------#
PACKAGE_DIR := adb_shell
TEST_DIR := tests
DOCS_DIR := docs

# Change to false if you don't want to use pytest
USE_PYTEST := true

# Change this to false if you don't want to run linting checks on the tests
LINT_TEST_DIR := false
#-------------------- DO NOT MODIFY CODE BELOW!!!!!!!! --------------------#

export PATH := $(abspath venv)/bin:${PATH}

# Whether to include "*_async.py" files
INCLUDE_ASYNC = $(shell python --version | grep -q "Python 3.[7891]" && echo "true" || echo "false")

# Async vs. Sync files
PACKAGE_ASYNC_FILES = $(shell ls -m $(PACKAGE_DIR)/*_async.py 2>/dev/null)
TEST_ASYNC_FILES = $(shell ls -m $(TEST_DIR)/*_async.py 2>/dev/null)
TEST_SYNC_FILES = $(shell cd $(TEST_DIR) && ls test*.py | grep -v async)

# Target prerequisites that may or may not exist
VENV_REQUIREMENTS_TXT := $(wildcard venv_requirements.txt)
SETUP_PY := $(wildcard setup.py)

# A prerequisite for forcing targets to run
FORCE:

# Help!
help:  ## Show this help menu
	@echo "\n\033[1mUsage:\033[0m"; \
	awk -F ':|##' '/^[^\t].+?:.*?##/ { printf "\033[36m  make %-20s\033[0m %s\n", $$1, $$NF }' $(MAKEFILE_LIST) | grep -v "make venv/\." | sort
	@echo ""
	@echo "NOTES:"
	@echo "- The 'venv/.bin' target may fail because newer Python versions include the 'venv' package.  Follow the instructions to create the virtual environment manually."
ifneq ("$(wildcard scripts/pre-commit.sh)", "")
	@echo "- To install the git pre-commit hook:\n\n    scripts/pre-commit.sh\n"
endif
	@echo "- You may need to activate the virtual environment prior to running any Make commands:\n\n    source venv/bin/activate\n"


# Virtual environment targets
.PHONY: clean-venv
clean-venv:  ## Remove the virtual environment
	rm -rf venv

venv: venv/.bin venv/.requirements venv/.setup .git/hooks/pre-commit  ## Create the virtual environment and install all necessary packages

venv/.bin:  ## Create the virtual environment
	if [ -z "$$ENV_GITHUB_ACTIONS" ]; then \
	  echo -e "If this target fails, you can perform this action manually via:\n\n    make clean-venv && python3 -m venv venv && source venv/bin/activate && pip install -U setuptools && echo -e '*.*\n**/' > venv/.gitignore && touch venv/.bin\n\n"; \
	  apt list -a --installed python3-venv 2>&1 | grep -q installed || (sudo apt update && sudo apt install python3-venv); \
	  python3 -m venv venv; \
	  pip install -U setuptools; \
	fi
	mkdir -p venv
	echo '*.*\n**/' > venv/.gitignore
	touch venv/.bin

venv/.requirements: venv/.bin $(VENV_REQUIREMENTS_TXT)  ## Install the requirements from 'venv_requirements.txt' in the virtual environment
ifneq ("$(wildcard venv_requirements.txt)", "")
	pip install -U -r venv_requirements.txt
endif
	touch venv/.requirements

# Install the package in the virtual environment
venv/.setup: venv/.bin $(SETUP_PY)
ifneq ("$(wildcard setup.py)", "")
	pip install .
endif
	touch venv/.setup

.PHONY: uninstall
uninstall:
	rm -f venv/.setup

.PHONY: install
install: uninstall venv/.setup  ## Install the package in the virtual environment

# Create the pre-commit hook
.git/hooks/pre-commit:
	./scripts/pre-commit.sh MAKE_PRECOMMIT_HOOK

.PHONY: pre-commit
pre-commit: .git/hooks/pre-commit  ## Create the pre-commit hook

# Linting and code analysis
.PHONY: black
black: venv  ## Format the code using black
	black --safe --line-length 120 --target-version py35 $(PACKAGE_DIR)
	black --safe --line-length 120 --target-version py35 $(TEST_DIR)
ifneq ("$(wildcard setup.py)", "")
	black --safe --line-length 120 --target-version py35 setup.py
endif

.PHONY: lint-black
lint-black: venv  ## Check that the code is formatted using black
	black --check --line-length 120 --safe --target-version py35 $(PACKAGE_DIR)
	black --check --line-length 120 --safe --target-version py35 $(TEST_DIR)
ifneq ("$(wildcard setup.py)", "")
	black --check --line-length 120 --safe --target-version py35 setup.py
endif

.PHONY: lint-flake8
lint-flake8: venv  ## Check the code using flake8
ifeq ($(INCLUDE_ASYNC), true)
	flake8 $(PACKAGE_DIR)
ifeq ($(LINT_TEST_DIR), true)
	flake8 $(TEST_DIR)
endif
else
	flake8 $(PACKAGE_DIR) --exclude="$(PACKAGE_ASYNC_FILES)"
ifeq ($(LINT_TEST_DIR), true)
	flake8 $(TEST_DIR) --exclude="$(TEST_ASYNC_FILES)"
endif
endif
ifneq ("$(wildcard setup.py)", "")
	flake8 setup.py
endif

.PHONY: lint-pylint
lint-pylint: venv  ## Check the code using pylint
ifeq ($(INCLUDE_ASYNC), true)
	pylint $(PACKAGE_DIR)
ifeq ($(LINT_TEST_DIR), true)
	pylint $(TEST_DIR)
endif
else
	pylint $(PACKAGE_DIR) --ignore="$(PACKAGE_ASYNC_FILES)"
ifeq ($(LINT_TEST_DIR), true)
	pylint $(TEST_DIR) --ignore="$(TEST_ASYNC_FILES)"
endif
endif
ifneq ("$(wildcard setup.py)", "")
	pylint setup.py
endif

.PHONY: lint
lint: lint-black lint-flake8 lint-pylint  ## Run all linting checks on the code


# Testing and coverage.
.PHONY: test
test: venv  ## Run the unit tests
ifeq ($(INCLUDE_ASYNC), true)
ifeq ($(USE_PYTEST), true)
	pytest $(TEST_DIR)
else
	python -m unittest discover -s $(TEST_DIR)/ -t .
endif
else
ifeq ($(USE_PYTEST), true)
	pytest $(TEST_DIR) --ignore-glob="*async.py"
else
	for synctest in $(TEST_SYNC_FILES); do echo "\033[1;32m$(TEST_DIR)/$$synctest\033[0m" && python -m unittest "$(TEST_DIR)/$$synctest"; done
endif
endif

.PHONY: coverage
coverage: venv  ## Run the unit tests and produce coverage info
ifeq ($(INCLUDE_ASYNC), true)
ifeq ($(USE_PYTEST), true)
	coverage run --source $(PACKAGE_DIR) -m pytest $(TEST_DIR)/ && coverage report -m
else
	coverage run --source $(PACKAGE_DIR) -m unittest discover -s $(TEST_DIR) -t . && coverage report -m
endif
else
ifeq ($(USE_PYTEST), true)
	coverage run --source $(PACKAGE_DIR) -m pytest $(TEST_DIR)/ --ignore-glob="*async.py" && coverage report -m
else
	for synctest in $(TEST_SYNC_FILES); do echo "\033[1;32m$(TEST_DIR)/$$synctest\033[0m" && coverage run --source $(PACKAGE_DIR) -m unittest "$(TEST_DIR)/$$synctest"; done
	coverage report -m
endif
endif

.PHONY: htmlcov
htmlcov: coverage  ## Produce a coverage report
	coverage html


# Documentation
.PHONY: docs
docs: venv  ## Build the documentation
	rm -rf $(DOCS_DIR)/build
	@cd $(DOCS_DIR) && sphinx-apidoc -f -e -o source/ $(CURDIR)/$(PACKAGE_DIR)/
	@cd $(DOCS_DIR) && make html && make html


.PHONY: release
release:  ## Make a release and upload it to pypi
	rm -rf dist
	scripts/git_tag.sh
	python setup.py sdist bdist_wheel
	twine upload dist/*


.PHONY: all
all: lint htmlcov  ## Run all linting checks and unit tests and produce a coverage report
