# Lightweight IDS Makefile

.PHONY: install test clean run package help

install:
	pip install -r requirements.txt

test:
	python test_ids.py

run:
	python simple_ids.py --list-interfaces

clean:
	rm -f test_traffic.pcap
	rm -f *.pyc
	rm -rf __pycache__
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/

package:
	python setup.py sdist bdist_wheel

help:
	@echo "Available targets:"
	@echo "  install  - Install dependencies"
	@echo "  test     - Run test suite"
	@echo "  run      - Show available interfaces"
	@echo "  clean    - Clean build artifacts"
	@echo "  package  - Create distribution package"
	@echo "  help     - Show this help"
