use libvex_macros::{import_hwcaps, import_offsets};

pub struct State(pub vex_sys::VexGuestAMD64State);

impl Default for State {
    fn default() -> Self {
        let mut this = std::mem::MaybeUninit::uninit();
        Self(unsafe {
            vex_sys::LibVEX_GuestAMD64_initialise(this.as_mut_ptr());
            this.assume_init()
        })
    }
}

import_offsets! {
    amd64 => { R10, R11, R12, R13, R14, R15, R8, R9, RAX, RBP, RBX, RCX, RDI, RDX, RIP, RSI, RSP }
}

import_hwcaps! {
    amd64 => { AVX, AVX2, BMI, CX16, F16C, LZCNT, RDRAND, RDSEED, RDTSCP, SSE3, SSSE3 }
}
