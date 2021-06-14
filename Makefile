all:
	mkdir -p build/
	cd build/ && \
		cmake -S ../ -B . && \
		make

clean:
	rm -rf build/
