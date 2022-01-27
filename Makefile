.PHONY: docs

threads=1
admin_user=admin
admin_pass=changeme
user=binlex
pass=changeme
config=Release

all:
	mkdir -p build/
	cd build/ && \
		cmake -S ../ \
			-B . \
			${args} && \
		cmake --build . --config ${config} -- -j ${threads}

python:
	mkdir -p build/
	cd build/ && \
		cmake -S ../ \
			-B . \
			-DBUILD_PYTHON_BINDINGS=true \
			-DPYBIND11_PYTHON_VERSION=`python -c "import platform; print(platform.python_version())"` \
			${args} && \
		cmake --build . --config ${config} -- -j ${threads}

docs:
	mkdir -p build/docs/html/docs/
	cp -r docs/img/ build/docs/html/docs/
	(cat Doxyfile; echo "NUM_PROC_THREADS=${threads}") | doxygen -

docs-update:
	rm -rf docs/html/
	cp -r build/docs/html/ docs/

database:
	@cd docker/ && \
		echo "MONGO_ROOT_USER=${admin_user}" > .env && \
		echo "MONGO_ROOT_PASSWORD=${admin_pass}" >> .env && \
		echo "MONGOEXPRESS_LOGIN=${admin_user}" >> .env && \
		echo "MONGOEXPRESS_PASSWORD=${admin_pass}" >> .env && \
		echo "REDIS_PASSWORD=${admin_pass}" >> .env && \
		echo "db.createUser({user:\"${user}\",pwd:\"${pass}\",roles:[{role:\"readWrite\",db:\"binlex\"}],mechanisms:[\"SCRAM-SHA-1\"]});" > .init.js && \
		cat schema.js >> .init.js && \
		docker-compose up --no-start

database-start:
	cd docker/ && \
		docker-compose up -d

database-stop:
	cd docker && \
		docker-compose down

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
	rm -rf data/
	rm -f docker-compose.yml
	rm -f replica.key
	rm -rf scripts/
	rm -rf ssl/
	rm -rf sslusr/
	rm -rf config/