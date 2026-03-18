use libvex_macros::import_offsets;

pub struct State(pub vex_sys::VexGuestMIPS64State);

impl Default for State {
    fn default() -> Self {
        let mut this = std::mem::MaybeUninit::uninit();
        Self(unsafe {
            vex_sys::LibVEX_GuestMIPS64_initialise(this.as_mut_ptr());
            this.assume_init()
        })
    }
}

import_offsets! {
    mips64 => {
        HI, LO, PC, r0, r1, r10, r11, r12, r13, r14, r15, r17, r18, r19, r2, r20, r21, r22, r23,
        r24, r25, r26, r27, r28, r29, r3, r30, r31, r4, r5, r6, r7, r8, r9,
    }
}
