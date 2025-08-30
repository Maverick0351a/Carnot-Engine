PYTHON ?= python

.PHONY: aws-test deps

deps:
	$(PYTHON) -m pip install -r integrations/aws/requirements-dev.txt

aws-test: deps
	$(PYTHON) -m pytest integrations/aws/tests -q
