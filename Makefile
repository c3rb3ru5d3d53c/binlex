OUTPUT_DIRECTORY = target
SETUP_VEX = scripts/setup-vex.sh

all:
	@cargo build --release

deps:
	@bash $(SETUP_VEX)

test: deps
	@eval "$$(bash $(SETUP_VEX) --env)" && cargo test -- --nocapture

test-vex: deps
	@eval "$$(bash $(SETUP_VEX) --env)" && cargo test --test vex_lifter -- --nocapture

build: deps
	@eval "$$(bash $(SETUP_VEX) --env)" && cargo build --release

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
		cd src/bindings/python/ && \
		pip install maturin[patchelf] && \
		maturin build --release

clean:
	@rm -rf pkg/
	@cargo clean

clean-deps:
	@bash $(SETUP_VEX) --clean

clean-all: clean clean-deps
