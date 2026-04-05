OUTPUT_DIRECTORY = target
BUILD_WORKSPACE = cargo build --release --workspace --exclude binlex-python
TEST_WORKSPACE = cargo test --workspace --exclude binlex-python

all:
	@$(BUILD_WORKSPACE)

deps:
	@cargo fetch

test:
	@$(TEST_WORKSPACE) -- --nocapture

test-vex:
	@cargo test --test vex_lifter -- --nocapture

build:
	@$(BUILD_WORKSPACE)

zst:
	@$(BUILD_WORKSPACE)
	@makepkg
	@mkdir -p $(OUTPUT_DIRECTORY)/zst/
	@for file in *.pkg.tar.zst; do \
		echo "Moving $$file to $(OUTPUT_DIRECTORY)/zst/..."; \
		mv "$$file" $(OUTPUT_DIRECTORY)/zst/; \
	done

deb:
	@cargo install cargo-deb
	@$(BUILD_WORKSPACE)
	@cargo deb -p binlex-cli --no-build

wheel:
	virtualenv -p python3 venv/
	. venv/bin/activate && \
		cd bindings/python/ && \
		pip install maturin[patchelf] && \
		maturin build --release

ida-plugin:
	virtualenv -p python3 venv/
	. venv/bin/activate && \
		cd plugins/ida/ && \
		pip install . build && \
		python -m build && \
		python -m binlex_ida archive --output ../../target/binlex-ida.zip

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
