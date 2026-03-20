pkgname=binlex
pkgver=$(grep '^version =' Cargo.toml | awk -F\" '{print $2}')
pkgrel=1
pkgdesc="A Binary Genetic Trait Lexer Framework"
arch=('x86_64')
license=('MIT')

build() {
  local builddir="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
  cd "$builddir"
  cargo build --release
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
