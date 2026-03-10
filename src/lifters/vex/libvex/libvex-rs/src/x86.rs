use libvex_macros::{import_hwcaps, import_offsets};

pub struct State(pub vex_sys::VexGuestX86State);

impl Default for State {
    fn default() -> Self {
        let mut this = std::mem::MaybeUninit::uninit();
        Self(unsafe {
            vex_sys::LibVEX_GuestX86_initialise(this.as_mut_ptr());
            this.assume_init()
        })
    }
}

import_offsets! { x86 => { EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP, EIP, CS, DS, ES, FS, GS, SS } }

import_hwcaps! { x86 => { LZCNT, MMXEXT, SSE1, SSE2, SSE3 } }
