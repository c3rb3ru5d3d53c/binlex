use libvex_macros::{import_hwcaps, import_offsets};

pub struct State(pub vex_sys::VexGuestS390XState);

impl Default for State {
    fn default() -> Self {
        let mut this = std::mem::MaybeUninit::uninit();
        Self(unsafe {
            vex_sys::LibVEX_GuestS390X_initialise(this.as_mut_ptr());
            this.assume_init()
        })
    }
}

import_offsets! {
    s390x => {
        CC_DEP1, CC_DEP2, CC_NDEP, CC_OP, IA, IP_AT_SYSCALL, SYSNO,
        fpc, r15, r2, r3, r4, r5, r6, r7,
    }
}

import_hwcaps! {
    s390x => {
        ALL, DFP, EIMM, ETF2, ETF3, FGX, FPEXT, GIE, LDISP, LSC, LSC2, MI2, MSA5, PFPO, STCKF,
        STFLE, VX, VXE
    }
}

pub mod model {
    pub use vex_sys::{
        VEX_S390X_MODEL_MASK, VEX_S390X_MODEL_UNKNOWN, VEX_S390X_MODEL_Z10_BC,
        VEX_S390X_MODEL_Z10_EC, VEX_S390X_MODEL_Z114, VEX_S390X_MODEL_Z13, VEX_S390X_MODEL_Z13S,
        VEX_S390X_MODEL_Z14, VEX_S390X_MODEL_Z14_ZR1, VEX_S390X_MODEL_Z15, VEX_S390X_MODEL_Z196,
        VEX_S390X_MODEL_Z800, VEX_S390X_MODEL_Z890, VEX_S390X_MODEL_Z900, VEX_S390X_MODEL_Z990,
        VEX_S390X_MODEL_Z9_BC, VEX_S390X_MODEL_Z9_EC, VEX_S390X_MODEL_ZBC12, VEX_S390X_MODEL_ZEC12,
    };
}
