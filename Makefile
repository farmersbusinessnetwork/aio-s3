all:
	python setup.py clean
	python setup.py build

clean:
	python setup.py clean
	rm -fr build dist *.egg-info

upload:
	python setup.py sdist upload -r http://repos.fbn.internal:8080/pypi

develop:
	python3 install -e .
