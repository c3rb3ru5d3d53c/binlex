use std::cell::RefCell;

use lazy_static::lazy_static;
use parking_lot::{ReentrantMutex, ReentrantMutexGuard};

use vex_sys;

pub use vex_sys::{Addr, VexArch as Arch, VexEndness};
pub use libvex_macros::IRSB;

pub mod ir;
mod logger;

// arch specific data:
pub mod amd64;
pub mod arm;
pub mod arm64;
pub mod mips32;
pub mod mips64;
pub mod ppc32;
pub mod ppc64;
pub mod s390x;
pub mod x86;

unsafe extern "C" fn failure_exit() -> ! {
    panic!("LibVEX encountered a critical error.")
}

unsafe extern "C" fn log_bytes(bytes: *const libc::c_char, nbytes: u64) {
    let bytes = std::slice::from_raw_parts(bytes as *const u8, nbytes as usize);
    let log = logger::VEX_LOG.lock();
    let _ = std::io::Write::write(&mut *log.borrow_mut(), bytes);
}

fn init() {
    use std::sync::Once;
    use vex_sys::LibVEX_Init;

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let mut vcon = crate::VexControl::default();
        unsafe {
            LibVEX_Init(Some(failure_exit), Some(log_bytes), 3, &mut vcon.0);
        }
    })
}

pub struct ArchInfo(pub vex_sys::VexArchInfo);

impl Default for ArchInfo {
    fn default() -> Self {
        let mut this = std::mem::MaybeUninit::uninit();
        Self(unsafe {
            vex_sys::LibVEX_default_VexArchInfo(this.as_mut_ptr());
            this.assume_init()
        })
    }
}

pub struct AbiInfo(pub vex_sys::VexAbiInfo);

impl Default for AbiInfo {
    fn default() -> Self {
        let mut this = std::mem::MaybeUninit::uninit();
        Self(unsafe {
            vex_sys::LibVEX_default_VexAbiInfo(this.as_mut_ptr());
            this.assume_init()
        })
    }
}

pub struct VexControl(pub vex_sys::VexControl);

impl Default for VexControl {
    fn default() -> Self {
        let mut this = std::mem::MaybeUninit::uninit();
        Self(unsafe {
            vex_sys::LibVEX_default_VexControl(this.as_mut_ptr());
            this.assume_init()
        })
    }
}

use libc::c_void;
unsafe extern "C" fn return_0(
    _cb: *mut c_void,
    _px_control: *mut vex_sys::VexRegisterUpdates,
    _vge: *const vex_sys::VexGuestExtents,
) -> u32 {
    0
}

unsafe extern "C" fn return_false(_cb: *mut c_void, _addr: u64) -> u8 {
    0
}

unsafe extern "C" fn failure_disp() {
    panic!("LibVEX called the display function.")
}

#[derive(Copy, Clone, Debug)]
pub enum TranslateError {
    AccessFail,
    OutputFull,
    LockError(LockError),
}

impl From<LockError> for TranslateError {
    fn from(err: LockError) -> Self {
        Self::LockError(err)
    }
}

pub type TranslateResult<T> = Result<T, TranslateError>;

pub struct TranslateArgs(pub vex_sys::VexTranslateArgs);

impl TranslateArgs {
    pub fn new(arch_guest: Arch, arch_host: Arch, endness: VexEndness) -> Self {
        let abiinfo_both = AbiInfo::default();
        let archinfo_guest = ArchInfo::default();

        Self(vex_sys::VexTranslateArgs {
            abiinfo_both: vex_sys::VexAbiInfo {
                // Use some values that makes AMD64 happy.
                guest_stack_redzone_size: 128,
                ..abiinfo_both.0
            },

            // Prepare first for a translation where guest == host
            // We will translate the sanity test function
            arch_guest: arch_guest.into(),
            arch_host: arch_host.into(),

            archinfo_guest: vex_sys::VexArchInfo {
                // Use some values that makes ARM64 happy.
                arm64_dMinLine_lg2_szB: 6,
                arm64_iMinLine_lg2_szB: 6,
                endness,
                hwcaps: 0,
                ..archinfo_guest.0
            },
            archinfo_host: vex_sys::VexArchInfo {
                endness,
                hwcaps: 0,
                ..archinfo_guest.0
            },
            callback_opaque: std::ptr::null_mut(),
            guest_bytes: std::ptr::null(),
            guest_bytes_addr: 0,
            guest_extents: std::ptr::null_mut(),
            chase_into_ok: Some(return_false),
            host_bytes: std::ptr::null_mut(),
            host_bytes_size: 0,
            host_bytes_used: std::ptr::null_mut(),
            instrument1: None,
            instrument2: None,
            finaltidy: None,
            needs_self_check: Some(return_0),
            preamble_function: None,
            traceflags: 0,
            sigill_diag: 0,
            addProfInc: 0,
            // When only calling the FrontEnd, these can be null
            disp_cp_chain_me_to_slowEP: std::ptr::null(),
            disp_cp_chain_me_to_fastEP: std::ptr::null(),
            disp_cp_xindir: std::ptr::null(),
            disp_cp_xassisted: failure_disp as *const _,
        })
    }

    /// Call VEX's front-end method, LibVEX_FrontEnd.
    ///
    /// The IRSB returned doesn't actually need the same lifetime as `self`,
    /// but this helps prevent calling the front-end in a way that would
    /// invalidate IRSBs that are still in use, with a compile time check.
    pub fn front_end(
        &mut self,
        guest_bytes: *const u8,
        guest_bytes_addr: u64,
    ) -> TranslateResult<ir::IRSB> {
        use std::mem::MaybeUninit;
        init();

        let mut vtr = MaybeUninit::<vex_sys::VexTranslateResult>::uninit();
        let mut ge = MaybeUninit::<vex_sys::VexGuestExtents>::uninit();
        self.0.guest_extents = ge.as_mut_ptr();
        let mut host_bytes: [u8; 100] = [0; 100];
        let mut host_bytes_used = 0;
        self.0.host_bytes = host_bytes.as_mut_ptr();
        self.0.host_bytes_size = host_bytes.len() as i32;
        self.0.host_bytes_used = &mut host_bytes_used;
        self.0.guest_bytes = guest_bytes;
        self.0.guest_bytes_addr = guest_bytes_addr;

        let _lock = LIFT_LOCK.exclusive_lock()?;
        let irsb = unsafe {
            vex_sys::LibVEX_FrontEnd(
                &mut self.0,
                vtr.as_mut_ptr(),
                #[allow(const_item_mutation)]
                &mut vex_sys::VexRegisterUpdates::VexRegUpd_INVALID,
            )
        };
        let vtr = unsafe { vtr.assume_init() };

        match vtr.status {
            vex_sys::VexTranslateResult_VexTransOK => Ok(ir::IRSB { inner: irsb, _lock }),
            vex_sys::VexTranslateResult_VexTransAccessFail => Err(TranslateError::AccessFail),
            vex_sys::VexTranslateResult_VexTransOutputFull => Err(TranslateError::OutputFull),
        }
    }

    /// Call VEX's translate method, LibVEX_Translate.
    pub fn translate(
        &mut self,
        guest_bytes: *const u8,
        guest_bytes_addr: u64,
        host_bytes: &mut [u8],
    ) -> TranslateResult<i32> {
        use std::mem::MaybeUninit;
        init();

        let mut ge = MaybeUninit::<vex_sys::VexGuestExtents>::uninit();
        self.0.guest_extents = ge.as_mut_ptr();
        let mut host_bytes_used = 0;
        self.0.host_bytes = host_bytes.as_mut_ptr();
        self.0.host_bytes_size = host_bytes.len() as i32;
        self.0.host_bytes_used = &mut host_bytes_used;
        self.0.guest_bytes = guest_bytes;
        self.0.guest_bytes_addr = guest_bytes_addr;

        let _lock = LIFT_LOCK.exclusive_lock()?;
        let vtr = unsafe { vex_sys::LibVEX_Translate(&mut self.0) };

        match vtr.status {
            vex_sys::VexTranslateResult_VexTransOK => Ok(host_bytes_used),
            vex_sys::VexTranslateResult_VexTransAccessFail => Err(TranslateError::AccessFail),
            vex_sys::VexTranslateResult_VexTransOutputFull => Err(TranslateError::OutputFull),
        }
    }
}

// VEX uses a static buffer (named `temporary`, in main_globals.c) for the
// allocation of all IR objects. It is cleared at the begining/end of every
// *translation*. This means an IRSB is only valid until the next call to
// `front_end` or `translate`. We use a Mutex to ensure that these methods are not
// called while an IRSB is still active.
// However, if a user wants to allocate a new IRSB, the lock still needs to be
// acquired, but doesn't need to be exclusive (e.g. call front_end() -> create another
// IRSB -> compare the two).
struct LiftLock(ReentrantMutex<RefCell<u8>>);

#[derive(Copy, Clone, Debug)]
pub enum LockError {
    AlreadyAllocated,
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::AlreadyAllocated => "Some VEX objects are already allocated".fmt(f),
        }
    }
}

impl std::error::Error for LockError {}

impl LiftLock {
    fn new() -> Self {
        Self(ReentrantMutex::new(RefCell::new(0)))
    }

    fn exclusive_lock(&self) -> Result<LiftGuard, LockError> {
        let guard = self.0.lock();
        if *guard.borrow() != 0 {
            return Err(LockError::AlreadyAllocated);
        }
        *guard.borrow_mut() = 1;
        Ok(LiftGuard(guard))
    }

    fn lock(&self) -> LiftGuard {
        let guard = self.0.lock();
        *guard.borrow_mut() += 1;
        LiftGuard(guard)
    }
}

struct LiftGuard<'a>(ReentrantMutexGuard<'a, RefCell<u8>>);

impl Drop for LiftGuard<'_> {
    fn drop(&mut self) {
        *self.0.borrow_mut() -= 1;
    }
}

lazy_static! {
    static ref LIFT_LOCK: LiftLock = LiftLock::new();
}

#[cfg(test)]
mod test {
    use super::{Arch, TranslateArgs, VexEndness};

    #[test]
    fn sanity() {
        let mut vta = TranslateArgs::new(
            Arch::VexArchAMD64,
            Arch::VexArchAMD64,
            VexEndness::VexEndnessLE,
        );

        let irsb = vta.front_end(sanity as *const _, sanity as _).unwrap();

        println!("{}", irsb);

        for mut stmt in irsb.iter_stmts() {
            if let super::ir::StmtEnum::Put(put) = stmt.as_enum() {
                println!("Got put with data: {}", put.data());
            }
        }
    }

    #[test]
    #[should_panic]
    fn double_lift() {
        let mut vta = TranslateArgs::new(
            Arch::VexArchAMD64,
            Arch::VexArchAMD64,
            VexEndness::VexEndnessLE,
        );

        let irsb = vta.front_end(sanity as *const _, sanity as _).unwrap();

        // get another irsb
        let next = match irsb.next().as_enum() {
            super::ir::ExprEnum::Const(c) => match c.as_enum() {
                super::ir::ConstEnum::U64(addr) => addr,
                _ => panic!(),
            },
            _ => panic!(),
        };

        let mut vta2 = TranslateArgs::new(
            Arch::VexArchAMD64,
            Arch::VexArchAMD64,
            VexEndness::VexEndnessLE,
        );
        let _irsb2 = vta2.front_end(next as *const _, next as _).unwrap();
    }

    #[test]
    fn translate() {
        let mut vta = TranslateArgs::new(
            Arch::VexArchAMD64,
            Arch::VexArchAMD64,
            VexEndness::VexEndnessLE,
        );

        let mut buf = [0; 1000];

        let size = vta
            .translate(translate as *const _, translate as _, &mut buf)
            .unwrap();

        assert!(size > 300);
    }

    mod lock_correctly {
        use super::*;
        use crate::ir::IRSB;

        // create 2 IRSBs, drop 1, then lift
        #[test]
        fn case1() {
            let _irsb1 = IRSB::new();
            {
                let _irsb2 = IRSB::new();
            }
            let mut vta = TranslateArgs::new(
                Arch::VexArchAMD64,
                Arch::VexArchAMD64,
                VexEndness::VexEndnessLE,
            );

            assert!(vta.front_end(case1 as *const _, case1 as _,).is_err());
        }

        // lift, then create 1 IRSB
        #[test]
        fn case2() {
            use crate::ir::IREndness::Iend_LE as LE;
            use crate::ir::Type::Ity_I64 as I64;
            use crate::ir::{Const, Expr, JumpKind, Op, Stmt};
            let mut vta = TranslateArgs::new(
                Arch::VexArchAMD64,
                Arch::VexArchAMD64,
                VexEndness::VexEndnessLE,
            );

            let lifted = vta
                .front_end(
                    [0xb8, 0, 0, 0, 0, 0xe8, 0x5b, 0xfd, 0xff, 0xff].as_ptr(),
                    0x12eb,
                )
                .unwrap();

            let mut expected = IRSB::new();
            unsafe {
                expected.set_next(Expr::const_(Const::u64(0x1050)));
                expected.set_jump_kind(JumpKind::Ijk_Call);
                expected.set_offs_ip(184);
                expected.add_stmt(Stmt::imark(0x12eb, 5, 0));
                expected.add_stmt(Stmt::put(16, Expr::const_(Const::u64(0))));
                expected.add_stmt(Stmt::put(184, Expr::const_(Const::u64(0x12f0))));
                expected.add_stmt(Stmt::imark(0x12f0, 5, 0));
                let _ = expected.type_env().new_tmp(I64);
                let _ = expected.type_env().new_tmp(I64);
                let _ = expected.type_env().new_tmp(I64);
                let t3 = expected.type_env().new_tmp(I64);
                let t4 = expected.type_env().new_tmp(I64);
                let t5 = expected.type_env().new_tmp(I64);
                let _ = expected.type_env().new_tmp(I64);

                expected.add_stmt(Stmt::wr_tmp(t4, Expr::get(48, I64)));
                expected.add_stmt(Stmt::wr_tmp(
                    t3,
                    Expr::binop(Op::Iop_Sub64, Expr::rd_tmp(t4), Expr::const_(Const::u64(8))),
                ));
                expected.add_stmt(Stmt::put(48, Expr::rd_tmp(t3)));
                expected.add_stmt(Stmt::store(
                    LE,
                    Expr::rd_tmp(t3),
                    Expr::const_(Const::u64(0x12f5)),
                ));
                expected.add_stmt(Stmt::wr_tmp(
                    t5,
                    Expr::binop(
                        Op::Iop_Sub64,
                        Expr::rd_tmp(t3),
                        Expr::const_(Const::u64(0x80)),
                    ),
                ));
                expected.add_stmt(Stmt::abi_hint(
                    Expr::rd_tmp(t5),
                    128,
                    Expr::const_(Const::u64(0x1050)),
                ));
            }

            assert_eq!(lifted, expected);
        }
    }
}
