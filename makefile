SRC_DIR = HackRequests
MAKE = make


.PHONY: prebuildclean install build pypimeta pypi publish clean


prebuildclean:
	@+python -c "import shutil; shutil.rmtree('build', True)"
	@+python -c "import shutil; shutil.rmtree('dist', True)"
	@+python -c "import shutil; shutil.rmtree('HackRequests.egg-info', True)"

install:
	python3 setup.py install

build:
	@make prebuildclean
	python3 setup.py sdist --formats=zip bdist_wheel

pypimeta:
	twine register

pypi:
	twine upload dist/*

publish:
	@make build
	#@make pypimeta
	@make pypi

clean:
	rm -rf *.egg-info dist build .tox
	find $(SRC_DIR) tests -type f -name '*.pyc' -delete