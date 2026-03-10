use libvex::{Arch, VexEndness, TranslateArgs, IRSB};

fn main() {
    let mut vta = TranslateArgs::new(
        Arch::VexArchAMD64,
        Arch::VexArchAMD64,
        VexEndness::VexEndnessLE,
    );

    let irsb = vta.front_end(main as *const _, main as _).unwrap();
    println!("{}", irsb);

    // print an custom irsb:
    let irsb = IRSB! {
        t0:I32 t1:I32 t36:I32 t12:I32
        
            -- IMark(0xF16B11B2, 6, 0) --
            t0 = LDle:I32(0xf00baba:I32)
            STle(0xf00abba:I32) = Sub32(Add32(t0, t0), 0x20:I32)
            t1 = GET:I32(48)
            IR-NoOp
            == AbiHint(t36, 128, t12) ==
            PUT(184) = t1; exit-Call
    };

    println!("{}", irsb);
}
