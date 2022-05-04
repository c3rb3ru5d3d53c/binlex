.PHONY: all
.PHONY: docs
.PHONY: docker

threads=1
admin_user=admin
admin_pass=changeme
user=binlex
pass=changeme
config=Release

all: python docs

cli: git-unsafe
	mkdir -p build/
	cd build/ && \
		cmake -S ../ \
			-B . \
			${args} && \
		cmake --build . --config ${config} -- -j ${threads}

python: git-unsafe
	mkdir -p build/
	cd build/ && \
		cmake -S ../ \
			-B . \
			-DBUILD_PYTHON_BINDINGS=true \
			-DPYBIND11_PYTHON_VERSION=`python -c "import platform; print(platform.python_version())"` \
			${args} && \
		cmake --build . --config ${config} -- -j ${threads}

python-whl:
	python3 -m pip wheel -v -w build/ .

docs:
	mkdir -p build/docs/html/docs/
	cp -r docs/img/ build/docs/html/docs/
	(cat Doxyfile; echo "NUM_PROC_THREADS=${threads}") | doxygen -

docs-update:
	rm -rf docs/html/
	cp -r build/docs/html/ docs/

docker:
	@./docker.sh

docker-build:
	@docker-compose build

docker-start:
	@docker-compose up -d

docker-logs:
	@docker-compose logs -f -t --tail 32

docker-stop:
	@docker-compose stop

docker-init:
	@cd scripts/ && \
		./init-all.sh

docker-clean:
	@docker stop $(shell docker ps -a -q) 2>/dev/null || echo > /dev/null
	@docker rm $(shell docker ps -a -q) 2>/dev/null || echo > /dev/null
	@docker rmi $(shell docker images -a -q) 2>/dev/null || echo > /dev/null

docker-restart-blapi:
	@docker stop $(shell docker container list --all -aqf name="blapi1")
	@docker rm $(shell docker container list --all -aqf name="blapi1")
	@docker-compose build blapi1
	@docker-compose up -d blapi1

mongodb-shell:
	@cd scripts/ && \
		./mongodb-shell.sh mongodb-router1

pkg:
	cd build/ && \
		cpack

dist:
	cd build/ && \
		make package_source

git-unsafe:
	@git config --global --add safe.directory `pwd`/build/capstone/src/capstone
	@git config --global --add safe.directory `pwd`/build/LIEF/src/LIEF
	@git config --global --add safe.directory `pwd`/build/tlsh/src/tlsh

install: git-unsafe
	cd build/ && \
		make install && \
		ldconfig

uninstall:
	cd build/ && \
		make uninstall

traits: check-parameter-source check-parameter-dest check-parameter-type check-parameter-format check-parameter-arch
	@echo "[-] building traits..."
	@find ${source} -type f | while read i; do \
		mkdir -p ${dest}/${type}/${format}/${arch}/; \
		filename=`basename $${i}`; \
		echo "binlex -m ${format}:${arch} -i $${i} | jq '.[] | .trait' > ${dest}/${type}/${format}/${arch}/$${filename}.traits"; \
	done | parallel -u --progress -j ${threads} {}
	@echo "[*] trait build complete"

traits-combine: check-parameter-source check-parameter-dest check-parameter-type check-parameter-format check-parameter-arch
	@find ${source}/${type}/${format}/${arch}/ -type f -name "*.traits" | while read i; do \
		echo "cat $${i} && rm -f $${i}"; \
	done | parallel --halt 1 -u -j ${threads} {} | sort | uniq > ${dest}/${type}.${format}.${arch}.traits

traits-clean: check-parameter-remove check-parameter-source check-parameter-dest
	awk 'NR==FNR{a[$$0];next} !($$0 in a)' ${remove} ${source} | sort | uniq | grep -Pv '^(\?\?\s?)+$$' > ${dest}

check-parameter-remove:
	@if [ -z ${remove} ]; then \
		echo "[x] missing remove parameter"; \
		exit 1; \
	fi

check-parameter-source:
	@if [ -z ${source} ]; then \
		echo "[x] missing source parameter"; \
		exit 1; \
	fi

check-parameter-dest:
	@if [ -z ${dest} ]; then \
		echo "[x] missing dest parameter"; \
		exit 1; \
	fi

check-parameter-type:
	@if [ -z ${type} ]; then \
		echo "[x] missing type parameter"; \
		exit 1; \
	fi

check-parameter-arch:
	@if [ -z ${arch} ]; then \
		echo "[x] missing arch parameter"; \
		exit 1; \
	fi

check-parameter-format:
	@if [ -z ${format} ]; then \
		echo "[x] missing format parameter"; \
		exit 1; \
	fi

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf pybinlex.egg-info/
	rm -f *.so
	rm -f *.whl
	rm -f docker-compose.yml
	rm -rf scripts/
	rm -rf config/
	rm -rf venv/

clean-data:
	rm -rf data/
