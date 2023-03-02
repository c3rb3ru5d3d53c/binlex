.PHONY: all
.PHONY: docs

threads=1
config=Release
PWD=$(shell pwd)

all: build docs

check-config:
	@echo "---check-config---"
	@if [ -z `echo ${config} | grep 'Release\|Debug'` ]; then \
		echo "[x] config parameter ${config} is invalid" 1>&2; \
		exit 1; \
	fi

build: check-config
	cmake -B build ${args}
	cmake --build build --config ${config} --parallel
	cmake --install build --prefix build/install --config ${config}

python-whl:
	python3 -m pip wheel -v -w ${PWD}/build/ .

docs:
	mkdir -p build/docs/html/docs/
	cp -r docs/img/ build/docs/html/docs/
	(cat Doxyfile; echo "NUM_PROC_THREADS=${threads}") | doxygen -

docs-update:
	rm -rf docs/html/
	cp -r build/docs/html/ docs/

pkg:
	cd build/ && \
		cpack

dist:
	cd build/ && \
		make package_source

install:
	cd build/ && \
		make install && \
		ldconfig

uninstall:
	cd build/ && \
		make uninstall

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf pybinlex.egg-info/
	rm -f *.so
	rm -f *.whl
	rm -f docker-compose.yml
	rm -rf config/
	rm -rf venv/

clean-docker:
	@docker stop $(shell docker ps -a -q) 2>/dev/null || echo > /dev/null
	@docker rm $(shell docker ps -a -q) 2>/dev/null || echo > /dev/null
	@docker rmi $(shell docker images -a -q) 2>/dev/null || echo > /dev/null
