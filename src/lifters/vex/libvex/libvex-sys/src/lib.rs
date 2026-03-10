#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]


include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[repr(C)]
pub struct _IRStmt__bindgen_ty_1__bindgen_ty_1(());

#[test]
fn bindgen_test_layout__IRStmt__bindgen_ty_1__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<_IRStmt__bindgen_ty_1__bindgen_ty_1>(),
        0usize,
        concat!(
            "Size of: ",
            stringify!(_IRStmt__bindgen_ty_1__bindgen_ty_1)
        )
    );
    assert_eq!(
        ::std::mem::align_of::<_IRStmt__bindgen_ty_1__bindgen_ty_1>(),
        1usize,
        concat!(
            "Alignment of ",
            stringify!(_IRStmt__bindgen_ty_1__bindgen_ty_1)
        )
    );
}

#[cfg(test)]
mod test {

    use libc::{c_char, c_void};
    use std::mem::{self, MaybeUninit};

    use crate::*;

    unsafe extern "C" fn failure_exit() -> ! {
        panic!("LibVEX encountered a critical error.")
    }

    unsafe extern "C" fn failure_disp() {
        panic!("LibVEX called the display function.")
    }

    #[cfg(log_bytes)]
    unsafe extern "C" fn log_bytes(chars: *const c_char, nbytes: u64) {
        use std::ffi::CString;
        use libc::printf;

        let format = CString::new("%*s").unwrap();
        printf(format.as_ptr(), nbytes, chars);
    }

    #[cfg(not(log_bytes))]
    unsafe extern "C" fn log_bytes(_: *const c_char, _: u64) {}

    unsafe extern "C" fn return_0(
        _cb: *mut c_void,
        _addr: *mut u32,
        _vge: *const VexGuestExtents,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn self_check(
        _cb: *mut c_void,
        _addr: *mut VexRegisterUpdates,
        _vge: *const VexGuestExtents,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn return_false(_cb: *mut c_void, _addr: u64) -> u8 {
        0
    }

    // This was shamelessly copied from LibVEX's own tests/libvex_test.c
    #[test]
    fn sanity() {
        let mut host_bytes: [u8; 10000] = [0; 10000];
        let mut host_bytes_used = 0;

        let mut vcon = mem::MaybeUninit::<VexControl>::uninit();
        let mut vcon = unsafe {
            LibVEX_default_VexControl(vcon.as_mut_ptr());
            vcon.assume_init()
        };
        unsafe {
            LibVEX_Init(Some(failure_exit), Some(log_bytes), 3, &mut vcon);
        };
        let va: VexArch = VexArch::VexArchAMD64;
        let ve: VexEndness = VexEndness::VexEndnessLE;

        let mut vta: VexTranslateArgs = unsafe {
            MaybeUninit::zeroed().assume_init()
        };
        let mut vge: VexGuestExtents = unsafe {
            MaybeUninit::zeroed().assume_init()
        };
        unsafe {
            LibVEX_default_VexArchInfo(&mut vta.archinfo_guest);
            LibVEX_default_VexArchInfo(&mut vta.archinfo_host);
        }
        vta.guest_extents = &mut vge;

        // Use some values that makes AMD64 happy.
        vta.abiinfo_both.guest_stack_redzone_size = 128;

        // Use some values that makes ARM64 happy.
        vta.archinfo_guest.arm64_dMinLine_lg2_szB = 6;
        vta.archinfo_guest.arm64_iMinLine_lg2_szB = 6;

        // Prepare first for a translation where guest == host
        // We will translate the get_guest_arch function
        vta.arch_guest = va;
        vta.archinfo_guest.endness = ve;
        vta.archinfo_guest.hwcaps = 0;
        vta.arch_host = va;
        vta.archinfo_host.endness = ve;
        vta.archinfo_host.hwcaps = 0;
        vta.callback_opaque = 0 as *mut c_void;
        vta.guest_bytes = sanity as *const u8;
        vta.guest_bytes_addr = sanity as Addr;
        vta.chase_into_ok = Some(return_false);
        vta.host_bytes = host_bytes.as_mut_ptr();
        vta.host_bytes_size = host_bytes.len() as i32;
        vta.host_bytes_used = &mut host_bytes_used;
        vta.instrument1 = None;
        vta.instrument2 = None;
        vta.finaltidy = None;
        vta.needs_self_check = Some(self_check);
        vta.preamble_function = None;
        vta.traceflags = -1;
        vta.sigill_diag = 0;
        vta.addProfInc = 0;
        vta.disp_cp_chain_me_to_slowEP = failure_disp as *const c_void;
        vta.disp_cp_chain_me_to_fastEP = failure_disp as *const c_void;
        vta.disp_cp_xindir = failure_disp as *const c_void;
        vta.disp_cp_xassisted = failure_disp as *const c_void;

        let vtr = unsafe { LibVEX_Translate(&mut vta) };

        assert!(vtr.status == VexTranslateResult_VexTransOK);
    }
}
