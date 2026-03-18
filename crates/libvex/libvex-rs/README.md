[![crates.io](https://img.shields.io/crates/v/libvex.svg)](https://crates.io/crates/libvex)
[![docs.rs](https://docs.rs/libvex/badge.svg)](https://docs.rs/libvex/)

# `LibVEX`

`LibVEX` provides bindings to valgrind's IR, `VEX`.

# Quick Start

Add `LibVEX` to your `Cargo.toml`:
```toml
[dependencies]
libvex = "0.1"
```

Lift some code to an IRSB:
```rust
fn foo() {
    let mut vta = VexTranslateArgs::new(
        Arch::VexArchAMD64,
        Arch::VexArchAMD64,
        VexEndness::VexEndnessLE,
    );
    let irsb = vta.front_end(foo as *const _, foo as _).unwrap();
}
```

Or translate:
```rust
fn translate() {
    let mut buf = [0; 1000];

    let size = vta.translate(
        translate as *const _,
        translate as _,
        &mut buf,
    ).unwrap();
}
```
