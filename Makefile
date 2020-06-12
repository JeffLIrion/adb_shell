.PHONY: release
release:
	rm -rf dist
	scripts/git_tag.sh
	python setup.py sdist bdist_wheel
	twine upload dist/*

.PHONY: docs
docs:
	rm -rf docs/build/html
	@cd docs && sphinx-apidoc -f -e -o source/ ../adb_shell/
	@cd docs && make html && make html

.PHONY: doxygen
doxygen:
	rm -rf docs/html
	doxygen Doxyfile

SYNCTESTS := $(shell cd tests && ls test*.py | grep -v async)

.PHONY: test
test:
	#python --version 2>&1 | grep -q "Python 2" && $(shell for synctest in $(cd tests && ls test*.py | grep -v async); do python -m unittest discover -s tests/ -t . -p "$synctest"; done)
	python --version 2>&1 | grep -q "Python 2" && (for synctest in $(SYNCTESTS); do python -m unittest discover -s tests/ -t . -p "$$synctest"; done) || true
	#python --version 2>&1 | grep -q "Python 2" && (for synctest in $(cd tests && ls test*.py | grep -v async); do python -m unittest discover -s tests/ -t . -p "$synctest" || exit 1; done) || true
	python --version 2>&1 | grep -q "Python 3" && python -m unittest discover -s tests/ -t . || true

.PHONY: coverage
coverage:
	coverage run --source adb_shell setup.py test && coverage html && coverage report -m

.PHONY: tdd
tdd:
	coverage run --source adb_shell setup.py test && coverage report -m

.PHONY: lint
lint:
	python --version 2>&1 | grep -q "Python 2" && (flake8 adb_shell/ --exclude="adb_shell/adb_device_async.py,adb_shell/handle/base_handle_async.py,adb_shell/handle/tcp_handle_async.py" && pylint --ignore="adb_device_async.py,base_handle_async.py,tcp_handle_async.py" adb_shell/) || (flake8 adb_shell/ && pylint adb_shell/)

.PHONY: alltests
alltests:
	flake8 adb_shell/ && pylint adb_shell/ && coverage run --source adb_shell setup.py test && coverage report -m
