use std::ffi::{CStr, CString};
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;
use std::slice;

use libc::c_void;

use vex_sys::*;
// Rename some imports
use vex_sys::{
    _IRExpr__bindgen_ty_1__bindgen_ty_1 as IRBinder,
    _IRExpr__bindgen_ty_1__bindgen_ty_11 as IRCCall, _IRExpr__bindgen_ty_1__bindgen_ty_12 as IRITE,
    _IRExpr__bindgen_ty_1__bindgen_ty_2 as IRGet, _IRExpr__bindgen_ty_1__bindgen_ty_3 as IRGetI,
    _IRExpr__bindgen_ty_1__bindgen_ty_4 as IRRdTmp, _IRExpr__bindgen_ty_1__bindgen_ty_7 as IRBinop,
    _IRExpr__bindgen_ty_1__bindgen_ty_8 as IRUnop, _IRExpr__bindgen_ty_1__bindgen_ty_9 as IRLoad,
    _IRStmt__bindgen_ty_1__bindgen_ty_10 as IRCAS, _IRStmt__bindgen_ty_1__bindgen_ty_11 as IRLLSC,
    _IRStmt__bindgen_ty_1__bindgen_ty_12 as IRDirty, _IRStmt__bindgen_ty_1__bindgen_ty_13 as IRMBE,
    _IRStmt__bindgen_ty_1__bindgen_ty_14 as IRExit, _IRStmt__bindgen_ty_1__bindgen_ty_2 as IRIMark,
    _IRStmt__bindgen_ty_1__bindgen_ty_3 as IRAbiHint, _IRStmt__bindgen_ty_1__bindgen_ty_4 as IRPut,
    _IRStmt__bindgen_ty_1__bindgen_ty_5 as IRPutI, _IRStmt__bindgen_ty_1__bindgen_ty_6 as IRWrTmp,
    _IRStmt__bindgen_ty_1__bindgen_ty_7 as IRStore,
};

use super::logger;

// Re-exports: we (usually) want to remove the IR prefix, since we're in the `ir` module.
// Note: we don't want to export any struct that we also assume lives in VEX's heap, such
//       as IRConst. Otherwise, a user could easily cause UB by running code such as:
// ```rust
// let co = IRConst { .. }; // let's ignore that this needs an unsafe block..
// let expr = Expr::const_(co); // this is assumed to be safe, since `co` must have been
//                              // constructed safely.
// ```
pub use vex_sys::{
    IREndness, // don't remove the IR prefix, to differentiate from VexEndness.
    IRJumpKind as JumpKind,
    IRLoadGOp as LoadGOp,
    IROp as Op,
    IRTemp as Temp,
    IRType as Type,
};

macro_rules! wrapper {
    ($wrapper_name:ident, $vex_name:ty) => {
        #[derive(Copy, Clone)]
        #[allow(dead_code)]
        pub struct $wrapper_name<'a>(*mut $vex_name, PhantomData<&'a $vex_name>);

        impl From<*mut $vex_name> for $wrapper_name<'_> {
            fn from(ptr: *mut $vex_name) -> Self {
                Self(ptr, PhantomData)
            }
        }

        impl From<&mut $vex_name> for $wrapper_name<'_> {
            fn from(ptr: &mut $vex_name) -> Self {
                Self::from(ptr as *mut _)
            }
        }
    };
}

#[derive(Copy, Clone)]
pub enum ConstEnum {
    U1(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(U128),
    F32(f32),
    F16i(u16),
    F32i(u32),
    F64(f64),
    F64i(u64),
    V128(V128),
    V256(V256),
}

wrapper!(Const, IRConst);

impl Const<'_> {
    pub fn as_enum(&self) -> ConstEnum {
        let co = unsafe { &*self.0 };
        let tag = co.tag as u32;

        if tag == IRConstTag::Ico_U1 as u32 {
            ConstEnum::U1(unsafe { co.Ico.U1 != 0 })
        } else if tag == IRConstTag::Ico_U8 as u32 {
            ConstEnum::U8(unsafe { co.Ico.U8 })
        } else if tag == IRConstTag::Ico_U16 as u32 {
            ConstEnum::U16(unsafe { co.Ico.U16 })
        } else if tag == IRConstTag::Ico_U32 as u32 {
            ConstEnum::U32(unsafe { co.Ico.U32 })
        } else if tag == IRConstTag::Ico_U64 as u32 {
            ConstEnum::U64(unsafe { co.Ico.U64 })
        } else if tag == 4869 {
            ConstEnum::U128(unsafe { *(&co.Ico as *const _ as *const U128) })
        } else if tag == IRConstTag::Ico_F32 as u32 {
            ConstEnum::F32(unsafe { co.Ico.F32 })
        } else if tag == 4870 {
            ConstEnum::F16i(unsafe { *(&co.Ico as *const _ as *const UShort) })
        } else if tag == IRConstTag::Ico_F32i as u32 {
            ConstEnum::F32i(unsafe { co.Ico.F32i })
        } else if tag == IRConstTag::Ico_F64 as u32 {
            ConstEnum::F64(unsafe { co.Ico.F64 })
        } else if tag == IRConstTag::Ico_F64i as u32 {
            ConstEnum::F64i(unsafe { co.Ico.F64i })
        } else if tag == IRConstTag::Ico_V128 as u32 {
                let val = unsafe { co.Ico.V128 };
                let vec = V128 {
                    w16: [val, val, val, val, val, val, val, val],
                };
            ConstEnum::V128(vec)
        } else if tag == IRConstTag::Ico_V256 as u32 {
            let val = unsafe { co.Ico.V256 };
            let vec = V256 {
                w32: [val, val, val, val, val, val, val, val],
            };
            ConstEnum::V256(vec)
        } else {
            panic!("Unimplemented IRConstTag variant value: {}", tag)
        }
    }

    pub unsafe fn u1(val: bool) -> Self {
        IRConst_U1(val as Bool).into()
    }

    pub unsafe fn u8(val: u8) -> Self {
        IRConst_U8(val).into()
    }

    pub unsafe fn u16(val: u16) -> Self {
        IRConst_U16(val).into()
    }

    pub unsafe fn u32(val: u32) -> Self {
        IRConst_U32(val).into()
    }

    pub unsafe fn u64(val: u64) -> Self {
        IRConst_U64(val).into()
    }

    pub unsafe fn f32(val: f32) -> Self {
        IRConst_F32(val).into()
    }

    pub unsafe fn f32i(val: u32) -> Self {
        IRConst_F32i(val).into()
    }

    pub unsafe fn f64(val: f64) -> Self {
        IRConst_F64(val).into()
    }

    pub unsafe fn f64i(val: u64) -> Self {
        IRConst_F64i(val).into()
    }

    pub unsafe fn v128(val: u16) -> Self {
        IRConst_V128(val).into()
    }

    pub unsafe fn v256(val: u32) -> Self {
        IRConst_V256(val).into()
    }
}

wrapper!(Callee, IRCallee);

impl Callee<'_> {
    pub unsafe fn new(regparms: Int, name: &str, addr: *mut c_void) -> Self {
        let name = CString::new(name).unwrap();
        mkIRCallee(regparms, name.into_raw(), addr).into()
    }

    pub fn name(&self) -> &str {
        unsafe { CStr::from_ptr((*self.0).name) }.to_str().unwrap()
    }

    pub fn regparms(&self) -> i32 {
        unsafe { *self.0 }.regparms
    }

    pub fn addr(&self) -> *const libc::c_void {
        unsafe { *self.0 }.addr as *const _
    }

    pub fn mcx_mask(&self) -> u32 {
        unsafe { *self.0 }.mcx_mask
    }
}

impl Display for Callee<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let ((), pp) = logger::with(|| unsafe { ppIRCallee(self.0) });
        pp.unwrap().fmt(f)
    }
}

wrapper!(RegArray, IRRegArray);

pub enum ExprEnum<'a> {
    Binder(Binder<'a>),
    Get(Get<'a>),
    GetI(GetI<'a>),
    RdTmp(RdTmp<'a>),
    Qop(Qop<'a>),
    Triop(Triop<'a>),
    Binop(Binop<'a>),
    Unop(Unop<'a>),
    Load(Load<'a>),
    Const(Const<'a>),
    CCall(CCall<'a>),
    ITE(ITE<'a>),
}

wrapper!(Binder, IRBinder);

wrapper!(Get, IRGet);

impl Get<'_> {
    pub fn offset(&self) -> Int {
        unsafe { (*self.0).offset }
    }

    pub fn ty(&self) -> Type {
        unsafe { (*self.0).ty }
    }
}

wrapper!(GetI, IRGetI);

impl GetI<'_> {
    pub fn descr(&self) -> RegArray<'_> {
        unsafe { (*self.0).descr }.into()
    }

    pub fn ix(&mut self) -> Expr<'_> {
        unsafe { (*self.0).ix }.into()
    }

    pub fn bias(&self) -> i32 {
        unsafe { *self.0 }.bias
    }

    pub fn bias_mut(&mut self) -> &mut i32 {
        unsafe { &mut (*self.0).bias }
    }
}

wrapper!(RdTmp, IRRdTmp);

impl RdTmp<'_> {
    pub fn tmp(&self) -> Temp {
        unsafe { (*self.0).tmp }
    }
}

wrapper!(Qop, IRQop);

impl Qop<'_> {
    pub fn op(&self) -> IROp {
        unsafe { (*self.0).op }
    }

    pub fn arg1(&self) -> Expr<'_> {
        unsafe { (*self.0).arg1 }.into()
    }

    pub fn arg2(&self) -> Expr<'_> {
        unsafe { (*self.0).arg2 }.into()
    }

    pub fn arg3(&self) -> Expr<'_> {
        unsafe { (*self.0).arg3 }.into()
    }

    pub fn arg4(&self) -> Expr<'_> {
        unsafe { (*self.0).arg4 }.into()
    }
}

wrapper!(Triop, IRTriop);

impl Triop<'_> {
    pub fn op(&self) -> IROp {
        unsafe { (*self.0).op }
    }

    pub fn arg1(&self) -> Expr<'_> {
        unsafe { (*self.0).arg1 }.into()
    }

    pub fn arg2(&self) -> Expr<'_> {
        unsafe { (*self.0).arg2 }.into()
    }

    pub fn arg3(&self) -> Expr<'_> {
        unsafe { (*self.0).arg3 }.into()
    }
}

wrapper!(Binop, IRBinop);

impl Binop<'_> {
    pub fn op(&self) -> IROp {
        unsafe { (*self.0).op }
    }

    pub fn arg1(&self) -> Expr<'_> {
        unsafe { (*self.0).arg1 }.into()
    }

    pub fn arg2(&self) -> Expr<'_> {
        unsafe { (*self.0).arg2 }.into()
    }
}

wrapper!(Unop, IRUnop);

impl Unop<'_> {
    pub fn op(&self) -> IROp {
        unsafe { (*self.0).op }
    }

    pub fn arg(&self) -> Expr<'_> {
        unsafe { (*self.0).arg }.into()
    }
}

wrapper!(Load, IRLoad);

impl Load<'_> {
    pub fn end(&self) -> IREndness {
        unsafe { (*self.0).end }
    }

    pub fn ty(&self) -> IRType {
        unsafe { (*self.0).ty }
    }

    pub fn addr(&self) -> Expr<'_> {
        unsafe { (*self.0).addr }.into()
    }
}

wrapper!(CCall, IRCCall);

impl CCall<'_> {
    pub fn callee(&self) -> Callee<'_> {
        unsafe { (*self.0).cee }.into()
    }

    pub fn ret_ty(&self) -> Type {
        unsafe { (*self.0).retty }
    }

    pub fn args(&self) -> ExprVec<'_> {
        unsafe { (*self.0).args }.into()
    }
}

wrapper!(ITE, IRITE);

impl ITE<'_> {
    pub fn cond(&self) -> Expr<'_> {
        unsafe { (*self.0).cond }.into()
    }

    pub fn if_true(&self) -> Expr<'_> {
        unsafe { (*self.0).iftrue }.into()
    }

    pub fn if_false(&self) -> Expr<'_> {
        unsafe { (*self.0).iffalse }.into()
    }
}

wrapper!(ExprVec, *mut IRExpr);

impl ExprVec<'_> {
    pub fn new0() -> Self {
        unsafe { mkIRExprVec_0() }.into()
    }

    pub fn new1(arg1: Expr) -> Self {
        unsafe { mkIRExprVec_1(arg1.0) }.into()
    }

    pub fn new2(arg1: Expr, arg2: Expr) -> Self {
        unsafe { mkIRExprVec_2(arg1.0, arg2.0) }.into()
    }

    pub fn new3(arg1: Expr, arg2: Expr, arg3: Expr) -> Self {
        unsafe { mkIRExprVec_3(arg1.0, arg2.0, arg3.0) }.into()
    }

    pub fn new4(arg1: Expr, arg2: Expr, arg3: Expr, arg4: Expr) -> Self {
        unsafe { mkIRExprVec_4(arg1.0, arg2.0, arg3.0, arg4.0) }.into()
    }

    pub fn new5(arg1: Expr, arg2: Expr, arg3: Expr, arg4: Expr, arg5: Expr) -> Self {
        unsafe { mkIRExprVec_5(arg1.0, arg2.0, arg3.0, arg4.0, arg5.0) }.into()
    }

    pub fn new6(arg1: Expr, arg2: Expr, arg3: Expr, arg4: Expr, arg5: Expr, arg6: Expr) -> Self {
        unsafe { mkIRExprVec_6(arg1.0, arg2.0, arg3.0, arg4.0, arg5.0, arg6.0) }.into()
    }

    pub fn new7(
        arg1: Expr,
        arg2: Expr,
        arg3: Expr,
        arg4: Expr,
        arg5: Expr,
        arg6: Expr,
        arg7: Expr,
    ) -> Self {
        unsafe { mkIRExprVec_7(arg1.0, arg2.0, arg3.0, arg4.0, arg5.0, arg6.0, arg7.0) }.into()
    }

    pub fn new8(
        arg1: Expr,
        arg2: Expr,
        arg3: Expr,
        arg4: Expr,
        arg5: Expr,
        arg6: Expr,
        arg7: Expr,
        arg8: Expr,
    ) -> Self {
        unsafe {
            mkIRExprVec_8(
                arg1.0, arg2.0, arg3.0, arg4.0, arg5.0, arg6.0, arg7.0, arg8.0,
            )
        }
        .into()
    }

    pub fn new9(
        arg1: Expr,
        arg2: Expr,
        arg3: Expr,
        arg4: Expr,
        arg5: Expr,
        arg6: Expr,
        arg7: Expr,
        arg8: Expr,
        arg9: Expr,
    ) -> Self {
        unsafe {
            mkIRExprVec_9(
                arg1.0, arg2.0, arg3.0, arg4.0, arg5.0, arg6.0, arg7.0, arg8.0, arg9.0,
            )
        }
        .into()
    }

    pub fn new13(
        arg1: Expr,
        arg2: Expr,
        arg3: Expr,
        arg4: Expr,
        arg5: Expr,
        arg6: Expr,
        arg7: Expr,
        arg8: Expr,
        arg9: Expr,
        arg10: Expr,
        arg11: Expr,
        arg12: Expr,
        arg13: Expr,
    ) -> Self {
        unsafe {
            mkIRExprVec_13(
                arg1.0, arg2.0, arg3.0, arg4.0, arg5.0, arg6.0, arg7.0, arg8.0, arg9.0, arg10.0,
                arg11.0, arg12.0, arg13.0,
            )
        }
        .into()
    }
}

wrapper!(Expr, IRExpr);

impl Display for Expr<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let ((), pp) = logger::with(|| unsafe { ppIRExpr(self.0) });
        pp.unwrap().fmt(f)
    }
}

impl Expr<'_> {
    pub fn as_enum(&self) -> ExprEnum<'_> {
        let this = unsafe { &mut *self.0 };
        match this.tag {
            // Note: Binder expressions should never be returned by VEX, but we do allow
            // creating them, so we may as well export them here too.
            IRExprTag::Iex_Binder => ExprEnum::Binder(unsafe { &mut this.Iex.Binder }.into()),
            IRExprTag::Iex_Get => ExprEnum::Get(unsafe { &mut this.Iex.Get }.into()),
            IRExprTag::Iex_GetI => ExprEnum::GetI(unsafe { &mut this.Iex.GetI }.into()),
            IRExprTag::Iex_RdTmp => ExprEnum::RdTmp(unsafe { &mut this.Iex.RdTmp }.into()),
            IRExprTag::Iex_Qop => ExprEnum::Qop(unsafe { this.Iex.Qop.details }.into()),
            IRExprTag::Iex_Triop => ExprEnum::Triop(unsafe { this.Iex.Triop.details }.into()),
            IRExprTag::Iex_Binop => ExprEnum::Binop(unsafe { &mut this.Iex.Binop }.into()),
            IRExprTag::Iex_Unop => ExprEnum::Unop(unsafe { &mut this.Iex.Unop }.into()),
            IRExprTag::Iex_Load => ExprEnum::Load(unsafe { &mut this.Iex.Load }.into()),
            IRExprTag::Iex_Const => ExprEnum::Const(unsafe { this.Iex.Const.con }.into()),
            IRExprTag::Iex_ITE => ExprEnum::ITE(unsafe { &mut this.Iex.ITE }.into()),
            IRExprTag::Iex_CCall => ExprEnum::CCall(unsafe { &mut this.Iex.CCall }.into()),
            IRExprTag::Iex_VECRET => unreachable!("VECRET should never be returned by VEX"),
            IRExprTag::Iex_GSPTR => unreachable!("GSPTR should never be returned by VEX"),
        }
    }

    // Reimplemented, since the original is a 'static inline' function, and isn't linked
    // into libvex.a
    pub fn is_atom(&self) -> bool {
        matches!(
            unsafe { (*self.0).tag },
            IRExprTag::Iex_RdTmp | IRExprTag::Iex_Const
        )
    }

    pub unsafe fn binder(binder: Int) -> Self {
        IRExpr_Binder(binder).into()
    }

    pub unsafe fn get(off: Int, ty: IRType) -> Self {
        IRExpr_Get(off, ty).into()
    }

    pub unsafe fn get_i(descr: RegArray, ix: Expr, bias: Int) -> Self {
        IRExpr_GetI(descr.0, ix.0, bias).into()
    }

    pub unsafe fn rd_tmp(tmp: Temp) -> Self {
        IRExpr_RdTmp(tmp).into()
    }

    pub fn qop(op: Op, arg1: Expr, arg2: Expr, arg3: Expr, arg4: Expr) -> Self {
        unsafe { IRExpr_Qop(op, arg1.0, arg2.0, arg3.0, arg4.0) }.into()
    }

    pub fn triop(op: Op, arg1: Expr, arg2: Expr, arg3: Expr) -> Self {
        unsafe { IRExpr_Triop(op, arg1.0, arg2.0, arg3.0) }.into()
    }

    pub fn binop(op: Op, arg1: Expr, arg2: Expr) -> Self {
        unsafe { IRExpr_Binop(op, arg1.0, arg2.0) }.into()
    }

    pub fn unop(op: Op, arg: Expr) -> Self {
        unsafe { IRExpr_Unop(op, arg.0) }.into()
    }

    pub fn load(end: IREndness, ty: Type, addr: Expr) -> Self {
        unsafe { IRExpr_Load(end, ty, addr.0) }.into()
    }

    pub fn const_(co: Const) -> Self {
        unsafe { IRExpr_Const(co.0) }.into()
    }

    pub fn ite(cond: Expr, if_true: Expr, if_false: Expr) -> Self {
        unsafe { IRExpr_ITE(cond.0, if_true.0, if_false.0) }.into()
    }

    pub fn ccall(cee: Callee, ret_ty: Type, args: ExprVec) -> Self {
        unsafe { IRExpr_CCall(cee.0, ret_ty, args.0) }.into()
    }

    pub unsafe fn vecret() -> Self {
        IRExpr_VECRET().into()
    }

    pub unsafe fn gsptr() -> Self {
        IRExpr_GSPTR().into()
    }
}

wrapper!(Stmt, IRStmt);

pub enum StmtEnum<'a> {
    NoOp,
    IMark(IMark<'a>),
    AbiHint(AbiHint<'a>),
    Put(Put<'a>),
    PutI(PutI<'a>),
    WrTmp(WrTmp<'a>),
    Store(Store<'a>),
    LoadG(LoadG<'a>),
    StoreG(StoreG<'a>),
    CAS(CAS<'a>),
    LLSC(LLSC<'a>),
    Dirty(Dirty<'a>),
    MBE(MBE<'a>),
    Exit(Exit<'a>),
}

impl Display for Stmt<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let ((), pp) = logger::with(|| unsafe { ppIRStmt(self.0) });
        pp.unwrap().fmt(f)
    }
}

impl Stmt<'_> {
    pub fn kind(&self) -> IRStmtTag {
        unsafe { (*self.0).tag }
    }

    pub fn is_flat(&self) -> bool {
        (unsafe { isFlatIRStmt(self.0) }) != 0
    }

    pub fn as_enum(&mut self) -> StmtEnum<'_> {
        let (tag, st) = unsafe { ((*self.0).tag, &mut (*self.0).Ist) };
        match tag {
            IRStmtTag::Ist_NoOp => StmtEnum::NoOp,
            IRStmtTag::Ist_IMark => StmtEnum::IMark(unsafe { st.IMark.as_mut() }.into()),
            IRStmtTag::Ist_AbiHint => StmtEnum::AbiHint(unsafe { st.AbiHint.as_mut() }.into()),
            IRStmtTag::Ist_Put => StmtEnum::Put(unsafe { st.Put.as_mut() }.into()),
            IRStmtTag::Ist_PutI => StmtEnum::PutI(unsafe { st.PutI.as_mut() }.into()),
            IRStmtTag::Ist_WrTmp => StmtEnum::WrTmp(unsafe { st.WrTmp.as_mut() }.into()),
            IRStmtTag::Ist_Store => StmtEnum::Store(unsafe { st.Store.as_mut() }.into()),
            IRStmtTag::Ist_LoadG => StmtEnum::LoadG(unsafe { st.LoadG.as_ref().details }.into()),
            IRStmtTag::Ist_StoreG => StmtEnum::StoreG(unsafe { st.StoreG.as_ref().details }.into()),
            IRStmtTag::Ist_CAS => StmtEnum::CAS(unsafe { st.CAS.as_mut() }.into()),
            IRStmtTag::Ist_LLSC => StmtEnum::LLSC(unsafe { st.LLSC.as_mut() }.into()),
            IRStmtTag::Ist_Dirty => StmtEnum::Dirty(unsafe { st.Dirty.as_mut() }.into()),
            IRStmtTag::Ist_MBE => StmtEnum::MBE(unsafe { st.MBE.as_mut() }.into()),
            IRStmtTag::Ist_Exit => StmtEnum::Exit(unsafe { st.Exit.as_mut() }.into()),
        }
    }

    // Safe, since VEX uses a static variable.
    pub fn no_op() -> Self {
        unsafe { IRStmt_NoOp() }.into()
    }

    // Unsafe, since VEX allocates, and the user needs to make sure VEX won't clear the
    // internal heap.
    pub unsafe fn imark(addr: Addr, len: UInt, delta: UChar) -> Self {
        IRStmt_IMark(addr, len, delta).into()
    }

    pub unsafe fn abi_hint(base: Expr, len: u32, nia: Expr) -> Self {
        IRStmt_AbiHint(base.0, len as Int, nia.0).into()
    }

    pub fn put(off: Int, data: Expr) -> Self {
        unsafe { IRStmt_Put(off, data.0) }.into()
    }

    // pub fn put_i() -> Self {
    //     IRStmt_NoOp().into()
    // }

    pub fn wr_tmp(tmp: Temp, data: Expr) -> Self {
        unsafe { IRStmt_WrTmp(tmp, data.0) }.into()
    }

    pub fn store(end: IREndness, addr: Expr, data: Expr) -> Self {
        unsafe { IRStmt_Store(end, addr.0, data.0) }.into()
    }

    // pub fn load_g() -> Self {
    //     IRStmt_NoOp().into()
    // }
    // pub fn store_g() -> Self {
    //     IRStmt_NoOp().into()
    // }
    // pub fn cas() -> Self {
    //     IRStmt_NoOp().into()
    // }
    // pub fn llsc() -> Self {
    //     IRStmt_NoOp().into()
    // }
    // pub fn dirty() -> Self {
    //     IRStmt_NoOp().into()
    // }
    // pub fn mbe() -> Self {
    //     IRStmt_NoOp().into()
    // }

    pub fn exit(guard: Expr, jk: JumpKind, dst: Const, offs_ip: Int) -> Self {
        unsafe { IRStmt_Exit(guard.0, jk, dst.0, offs_ip) }.into()
    }
}

wrapper!(IMark, IRIMark);

wrapper!(AbiHint, IRAbiHint);

wrapper!(Put, IRPut);

impl Put<'_> {
    pub fn offset(&self) -> i32 {
        unsafe { *self.0 }.offset
    }

    pub fn data(&self) -> Expr<'_> {
        Expr(unsafe { (*self.0).data }, PhantomData)
    }
}

wrapper!(PutI, IRPutI);

wrapper!(WrTmp, IRWrTmp);

impl WrTmp<'_> {
    pub fn tmp(&self) -> Temp {
        unsafe { (*self.0).tmp }
    }

    pub fn data(&self) -> Expr<'_> {
        unsafe { (*self.0).data }.into()
    }
}

wrapper!(Store, IRStore);

impl Store<'_> {
    pub fn addr(&self) -> Expr<'_> {
        unsafe { (*self.0).addr }.into()
    }

    pub fn data(&self) -> Expr<'_> {
        unsafe { (*self.0).data }.into()
    }
}

wrapper!(StoreG, IRStoreG);

impl StoreG<'_> {
    pub fn end(&self) -> IREndness {
        unsafe { (*self.0).end }
    }

    pub fn addr(&self) -> Expr<'_> {
        unsafe { (*self.0).addr }.into()
    }

    pub fn data(&self) -> Expr<'_> {
        unsafe { (*self.0).data }.into()
    }

    pub fn guard(&self) -> Expr<'_> {
        unsafe { (*self.0).guard }.into()
    }
}

wrapper!(LoadG, IRLoadG);

impl LoadG<'_> {
    pub fn end(&self) -> IREndness {
        unsafe { (*self.0).end }
    }

    pub fn cvt(&self) -> LoadGOp {
        unsafe { (*self.0).cvt }
    }

    pub fn dst(&self) -> Temp {
        unsafe { (*self.0).dst }
    }

    pub fn addr(&self) -> Expr<'_> {
        unsafe { (*self.0).addr }.into()
    }

    pub fn alt(&self) -> Expr<'_> {
        unsafe { (*self.0).alt }.into()
    }

    pub fn guard(&self) -> Expr<'_> {
        unsafe { (*self.0).guard }.into()
    }
}

wrapper!(CAS, IRCAS);

wrapper!(LLSC, IRLLSC);

wrapper!(Dirty, IRDirty);

wrapper!(MBE, IRMBE);

wrapper!(Exit, IRExit);

impl Exit<'_> {
    pub fn guard(&self) -> Expr<'_> {
        unsafe { (*self.0).guard }.into()
    }

    pub fn dst(&self) -> Const<'_> {
        unsafe { (*self.0).dst }.into()
    }

    pub fn jump_kind(&self) -> JumpKind {
        unsafe { (*self.0).jk }
    }

    pub fn offs_ip(&self) -> i32 {
        unsafe { (*self.0).offsIP }
    }
}

wrapper!(TypeEnv, IRTypeEnv);

impl<'a> TypeEnv<'a> {
    /// Create a new type environment.
    ///
    /// # Safety
    /// The instance returned from this method is only valid until the next call to
    /// to [TranslateArgs::translate](super::TranslateArgs::translate) or
    /// [TranslateArgs::front_end](super::TranslateArgs::front_end).
    pub unsafe fn new() -> Self {
        emptyIRTypeEnv().into()
    }

    pub fn new_tmp(&self, ty: Type) -> Temp {
        unsafe { newIRTemp(self.0, ty) }
    }

    pub fn type_of_tmp(&self, tmp: Temp) -> IRType {
        unsafe { typeOfIRTemp(self.0, tmp) }
    }

    pub fn type_of_expr(&self, expr: Expr) -> IRType {
        unsafe { typeOfIRExpr(self.0, expr.0) }
    }
}

impl Display for TypeEnv<'_> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let ((), pp) = logger::with(|| unsafe { ppIRTypeEnv(self.0) });
        pp.unwrap().fmt(f)
    }
}

pub struct IRSB<'a> {
    pub(crate) inner: *mut vex_sys::IRSB,
    pub(crate) _lock: super::LiftGuard<'a>,
}

impl Default for IRSB<'_> {
    fn default() -> Self {
        let _lock = super::LIFT_LOCK.lock();
        Self {
            inner: unsafe { emptyIRSB() },
            _lock,
        }
    }
}

// Note: can panic if `next` is not set.
impl Display for IRSB<'_> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if unsafe { (*self.inner).next }.is_null() {
            write!(f, "IRSB<UNINIT?>")
        } else {
            let ((), pp) = logger::with(|| unsafe { ppIRSB(self.inner) });
            pp.unwrap().fmt(f)
        }
    }
}

impl IRSB<'_> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn type_env(&self) -> TypeEnv<'_> {
        unsafe { (*self.inner).tyenv }.into()
    }

    pub fn iter_stmts(&self) -> impl Iterator<Item = Stmt<'_>> {
        unsafe { slice::from_raw_parts((*self.inner).stmts, (*self.inner).stmts_used as usize) }
            .iter()
            .map(|stmt| (*stmt).into())
    }

    pub fn add_stmt(&self, stmt: Stmt) {
        unsafe { addStmtToIRSB(self.inner, stmt.0) }
    }

    pub fn next(&self) -> Expr<'_> {
        unsafe { (*self.inner).next }.into()
    }

    pub fn set_next(&mut self, next: Expr) {
        unsafe { (*self.inner).next = next.0 };
    }

    pub fn jump_kind(&self) -> JumpKind {
        unsafe { (*self.inner).jumpkind }
    }

    pub fn set_jump_kind(&mut self, jk: JumpKind) {
        unsafe { (*self.inner).jumpkind = jk }
    }

    pub fn offs_ip(&mut self) -> Int {
        unsafe { (*self.inner).offsIP }
    }

    pub fn set_offs_ip(&mut self, offs_ip: Int) {
        unsafe { (*self.inner).offsIP = offs_ip }
    }

    pub fn truncate(&mut self, stmts: u32) {
        let this = unsafe { &mut *self.inner };
        assert!(this.stmts_used <= stmts as i32);
        this.stmts_used = stmts as i32;
    }

    pub fn is_flat(&self) -> bool {
        (unsafe { isFlatIRSB(self.inner) }) != 0
    }

    pub fn sanity_check(&self, caller: &str, require_flatness: bool, guest_word_size: Type) {
        let caller = CString::new(caller).unwrap();
        unsafe {
            sanityCheckIRSB(
                self.inner,
                caller.as_ptr(),
                require_flatness as Bool,
                guest_word_size,
            )
        }
    }
}

impl std::fmt::Debug for IRSB<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl PartialEq for IRSB<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}
impl Eq for IRSB<'_> {}

#[cfg(test)]
mod test {
    use super::*;

    // Ensure that multiple irsbs can be created in the same thread.
    #[test]
    fn multiple_irsbs() {
        use crate::x86::offset::EDX;
        use IREndness::Iend_LE as LE;
        use Type::Ity_I32 as I32;

        let irsb1 = IRSB::default();
        let tmp1 = irsb1.type_env().new_tmp(I32);
        let tmp2 = irsb1.type_env().new_tmp(I32);
        // All the calls to unsafe methods are safe because an IRSB is already in
        // scope, and we're transferring ownership directly to it.
        irsb1.add_stmt(Stmt::wr_tmp(
            tmp1,
            Expr::const_(unsafe { Const::u32(0xdeadbeef) }),
        ));

        let irsb2 = IRSB::default();
        let tmp3 = irsb2.type_env().new_tmp(I32);
        unsafe {
            irsb2.add_stmt(Stmt::wr_tmp(tmp3, Expr::const_(Const::u32(0xdeadbeef))));

            irsb1.add_stmt(Stmt::wr_tmp(tmp2, Expr::load(LE, I32, Expr::rd_tmp(tmp1))));

            irsb2.add_stmt(Stmt::put(EDX, Expr::rd_tmp(tmp2)));
        }
    }
}
