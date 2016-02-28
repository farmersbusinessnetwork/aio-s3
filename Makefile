all:
	python setup.py clean
	python setup.py build

clean:
	python setup.py clean
	rm -fr build dist *.egg-info

upload:
	python setup.py sdist upload -r https://pypi.fbn.internal/simple

develop:
	python3 install -e .
