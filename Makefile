OUTPUT_DIRECTORY = target
BUILD_WORKSPACE = cargo build --release --workspace --exclude binlex-python
TEST_WORKSPACE = cargo test --workspace --exclude binlex-python

all: prepare
	@$(BUILD_WORKSPACE)

prepare:
	@cargo run --manifest-path xtask/Cargo.toml

deps:
	@cargo fetch

test: prepare
	@$(TEST_WORKSPACE) -- --nocapture

test-vex: prepare
	@cargo test --test vex_lifter -- --nocapture

build: prepare
	@$(BUILD_WORKSPACE)

wheel: prepare
	virtualenv -p python3 venv/
	. venv/bin/activate && \
		cd bindings/python/ && \
		pip install maturin[patchelf] && \
		maturin build --release

clean:
	@rm -rf pkg/
	@cargo clean

clean-config:
	cd ~/.config/ && \
		rm -rf binlex/
	cd ~/.local/share/ && \
		rm -rf binlex/

clean-deps:
	@cargo clean

clean-all: clean clean-deps
