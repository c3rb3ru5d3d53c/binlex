use libvex_macros::{import_hwcaps, import_offsets};

pub struct State(pub vex_sys::VexGuestARMState);

impl Default for State {
    fn default() -> Self {
        let mut this = std::mem::MaybeUninit::uninit();
        Self(unsafe {
            vex_sys::LibVEX_GuestARM_initialise(this.as_mut_ptr());
            this.assume_init()
        })
    }
}

import_offsets! { arm => { R0, R1, R13, R14, R15T, R2, R3, R4, R5, R7 } }

import_hwcaps! { arm => { NEON, VFP, VFP2, VFP3 } }
