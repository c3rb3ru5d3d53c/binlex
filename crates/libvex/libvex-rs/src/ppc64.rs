use libvex_macros::{import_hwcaps, import_offsets};

pub struct State(pub vex_sys::VexGuestPPC64State);

impl Default for State {
    fn default() -> Self {
        let mut this = std::mem::MaybeUninit::uninit();
        Self(unsafe {
            vex_sys::LibVEX_GuestPPC64_initialise(this.as_mut_ptr());
            this.assume_init()
        })
    }
}

import_offsets! {
    ppc64 => { CIA, CR0_0, GPR0, GPR1, GPR10, GPR2, GPR3, GPR4, GPR5, GPR6, GPR7, GPR8, GPR9 }
}

import_hwcaps! { ppc64 => { DFP, FX, GX, ISA2_07, ISA3_0, ISA3_1, V, VX } }
