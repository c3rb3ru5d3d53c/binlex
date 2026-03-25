pkgname=binlex
pkgver=$(grep '^version =' Cargo.toml | awk -F\" '{print $2}')
pkgrel=1
pkgdesc="A Binary Genetic Trait Lexer Framework"
arch=('x86_64')
license=('MIT')
makedepends=('rust' 'pkgconf' 'clang' 'openssl' 'zstd' 'lz4')

build() {
  local builddir="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
  cd "$builddir"
  # Arch's makepkg injects -Wl,--as-needed into the linker driver flags.
  # Appending --no-as-needed via RUSTFLAGS is too late because Cargo places
  # those arguments at the end of the link line, after zstd's native linkage
  # has already been discarded. Wrap the linker so the injected flag is
  # rewritten before the final gcc invocation is assembled.
  local linker_wrapper="$srcdir/binlex-arch-linker-wrapper"
  cat > "$linker_wrapper" <<'EOF'
#!/bin/bash
set -euo pipefail

args=()
for arg in "$@"; do
  if [[ "$arg" == "-Wl,--as-needed" ]]; then
    args+=("-Wl,--no-as-needed")
  else
    args+=("$arg")
  fi
done

exec x86_64-linux-gnu-gcc "${args[@]}"
EOF
  chmod +x "$linker_wrapper"
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$linker_wrapper"
  # Prefer Arch's system compression libraries during makepkg's link phase so
  # native dependencies are resolved consistently under Arch's injected linker flags.
  export ZSTD_SYS_USE_PKG_CONFIG=1
  export LIBRARY_PATH="/usr/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
  export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C link-arg=-llz4"
  : "${CARGO_BUILD_JOBS:=2}"
  export CARGO_BUILD_JOBS
  cargo build --release --workspace --exclude binlex-python
}

package() {
  local builddir="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
  install -Dm755 "$builddir/target/release/binlex" "$pkgdir/usr/bin/binlex"
  install -Dm755 "$builddir/target/release/binlex-symbols" "$pkgdir/usr/bin/binlex-symbols"
  install -Dm755 "$builddir/target/release/binlex-hash" "$pkgdir/usr/bin/binlex-hash"
  install -Dm755 "$builddir/target/release/binlex-image" "$pkgdir/usr/bin/binlex-image"
  install -Dm755 "$builddir/target/release/binlex-yara" "$pkgdir/usr/bin/binlex-yara"
  install -Dm755 "$builddir/target/release/binlex-server" "$pkgdir/usr/bin/binlex-server"
  install -Dm755 "$builddir/target/release/binlex-processor-vex" "$pkgdir/usr/bin/binlex-processor-vex"
  install -Dm755 "$builddir/target/release/binlex-processor-embeddings" "$pkgdir/usr/bin/binlex-processor-embeddings"
}
