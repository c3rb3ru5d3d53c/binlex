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
    install -Dm755 "$builddir/target/release/blhash" "$pkgdir/usr/bin/blhash"
    install -Dm755 "$builddir/target/release/blimage" "$pkgdir/usr/bin/blimage"
    install -Dm755 "$builddir/target/release/blmachosym" "$pkgdir/usr/bin/blmachosym"
    install -Dm755 "$builddir/target/release/blpdb" "$pkgdir/usr/bin/blpdb"
    install -Dm755 "$builddir/target/release/blrizin" "$pkgdir/usr/bin/blrizin"
    install -Dm755 "$builddir/target/release/blscaler" "$pkgdir/usr/bin/blscaler"
    install -Dm755 "$builddir/target/release/blyara" "$pkgdir/usr/bin/blyara"
}
