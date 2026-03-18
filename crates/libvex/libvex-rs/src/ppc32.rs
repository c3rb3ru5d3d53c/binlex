use libvex_macros::{import_hwcaps, import_offsets};

pub struct State(pub vex_sys::VexGuestPPC32State);

impl Default for State {
    fn default() -> Self {
        let mut this = std::mem::MaybeUninit::uninit();
        Self(unsafe {
            vex_sys::LibVEX_GuestPPC32_initialise(this.as_mut_ptr());
            this.assume_init()
        })
    }
}

import_offsets! {
    ppc32 => { CIA, CR0_0, GPR0, GPR1, GPR10, GPR2, GPR3, GPR4, GPR5, GPR6, GPR7, GPR8, GPR9 }
}

import_hwcaps! { ppc32 => { DFP, F, FX, GX, ISA2_07, ISA3_0, ISA3_1, V, VX } }
