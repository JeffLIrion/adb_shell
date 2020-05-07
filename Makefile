.PHONY: release
release:
	rm -rf dist
	scripts/git_tag.sh
	python setup.py sdist bdist_wheel
	twine upload dist/*

.PHONY: docs
docs:
	rm -rf docs/build/html
	@cd docs && sphinx-apidoc -f -e -o source/ ../aio_adb_shell/
	@cd docs && make html && make html

.PHONY: doxygen
doxygen:
	rm -rf docs/html
	doxygen Doxyfile

.PHONY: test
test:
	python setup.py test

.PHONY: coverage
coverage:
	coverage run --source aio_adb_shell setup.py test && coverage html && coverage report -m

.PHONY: tdd
tdd:
	coverage run --source aio_adb_shell setup.py test && coverage report -m

.PHONY: lint
lint:
	flake8 aio_adb_shell/ && pylint aio_adb_shell/

.PHONY: alltests
alltests:
	flake8 aio_adb_shell/ && pylint aio_adb_shell/ && coverage run --source aio_adb_shell setup.py test && coverage report -m
