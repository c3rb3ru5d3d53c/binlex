pkgname=binlex
pkgver=$(grep '^version =' Cargo.toml | awk -F\" '{print $2}')
pkgrel=1
pkgdesc="A Binary Genetic Trait Lexer Framework"
arch=('x86_64')
license=('LGPL')

build() {
  local builddir="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
}

package() {
    local builddir="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    install -Dm755 "$builddir/target/release/binlex" "$pkgdir/usr/bin/binlex"
    install -Dm755 "$builddir/target/release/binlex-elf-symbols" "$pkgdir/usr/bin/binlex-elf-symbols"
    install -Dm755 "$builddir/target/release/binlex-hash" "$pkgdir/usr/bin/binlex-hash"
    install -Dm755 "$builddir/target/release/binlex-image" "$pkgdir/usr/bin/binlex-image"
    install -Dm755 "$builddir/target/release/binlex-macho-symbols" "$pkgdir/usr/bin/binlex-macho-symbols"
    install -Dm755 "$builddir/target/release/binlex-pdb" "$pkgdir/usr/bin/binlex-pdb"
    install -Dm755 "$builddir/target/release/binlex-rizin" "$pkgdir/usr/bin/binlex-rizin"
    install -Dm755 "$builddir/target/release/binlex-yara" "$pkgdir/usr/bin/binlex-yara"
}
