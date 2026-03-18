use libvex_macros::{import_hwcaps, import_offsets};

pub struct State(pub vex_sys::VexGuestARM64State);

impl Default for State {
    fn default() -> Self {
        let mut this = std::mem::MaybeUninit::uninit();
        Self(unsafe {
            vex_sys::LibVEX_GuestARM64_initialise(this.as_mut_ptr());
            this.assume_init()
        })
    }
}

import_offsets! { arm64 => { PC, X0, X1, X2, X3, X4, X5, X6, X7, X8, XSP } }

import_hwcaps! {
    arm64 => { ATOMICS, BF16, DPBCVADP, DPBCVAP, FHM, FP16, I8MM, RDM, SHA3, SM3, SM4, VFP16 }
}
