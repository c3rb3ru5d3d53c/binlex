OUTPUT_DIRECTORY = target

all:
	@cargo build --release

deps:
	@cargo fetch

test:
	@cargo test -- --nocapture

test-vex:
	@cargo test --test vex_lifter -- --nocapture

build:
	@cargo build --release

zst:
	@cargo build --release
	@makepkg
	@mkdir -p $(OUTPUT_DIRECTORY)/zst/
	@for file in *.pkg.tar.zst; do \
		echo "Moving $$file to $(OUTPUT_DIRECTORY)/zst/..."; \
		mv "$$file" $(OUTPUT_DIRECTORY)/zst/; \
	done

deb:
	@cargo install cargo-deb
	@cargo deb

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

clean-deps:
	@cargo clean

clean-all: clean clean-deps
