.PHONY: release
release:
	rm -rf dist
	rm -rf build
	scripts/git_tag.sh
	python setup.py sdist bdist_wheel
	twine upload dist/*

.PHONY: docs
docs:
	rm -rf docs/build/html
	@cd docs && sphinx-apidoc -f -e -o source/ ../adb_shell/
	@cd docs && make html && make html

SYNCTESTS := $(shell cd tests && ls test*.py | grep -v async)

.PHONY: test
test:
	python --version 2>&1 | grep -q "Python 2" && (for synctest in $(SYNCTESTS); do python -m unittest discover -s tests/ -t . -p "$$synctest"; done) || true
	python --version 2>&1 | grep -q "Python 3" && python -m unittest discover -s tests/ -t . || true

.PHONY: coverage
coverage:
	coverage run --source adb_shell -m unittest discover -s tests/ -t . && coverage html && coverage report -m

.PHONY: tdd
tdd:
	coverage run --source adb_shell -m unittest discover -s tests/ -t . && coverage report -m

.PHONY: lint
lint:
	python --version 2>&1 | grep -q "Python 2" && (flake8 adb_shell/ --exclude="adb_shell/adb_device_async.py,adb_shell/transport/base_transport_async.py,adb_shell/transport/tcp_transport_async.py" && pylint --ignore="adb_device_async.py,base_transport_async.py,tcp_transport_async.py" adb_shell/) || (flake8 adb_shell/ && pylint adb_shell/)

.PHONY: alltests
alltests:
	flake8 adb_shell/ && pylint adb_shell/ && coverage run --source adb_shell -m unittest discover -s tests/ -t . && coverage report -m
