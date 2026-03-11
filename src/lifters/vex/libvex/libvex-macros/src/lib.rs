use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::Brace;
use syn::{braced, parenthesized, parse_macro_input, token, Ident, LitInt, Result, Token};

struct ImportArgs {
    arch: Ident,
    _arrow: Token![=>],
    _brace: Brace,
    items: Punctuated<Ident, Token![,]>,
}

impl Parse for ImportArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let items;
        Ok(Self {
            arch: input.parse()?,
            _arrow: input.parse()?,
            _brace: braced!(items in input),
            items: items.parse_terminated(Ident::parse)?,
        })
    }
}

#[proc_macro]
pub fn import_offsets(item: TokenStream) -> TokenStream {
    let offsets = parse_macro_input!(item as ImportArgs);
    let mut output = quote!(
        use vex_sys::Int;
    );
    for reg in &offsets.items {
        // switch order of arguments to make the span of the output depend on the register.
        let offset = format_ident!("OFFSET_{1}_{0}", reg, offsets.arch);
        output = quote!(
            #output
            pub const #reg: Int = vex_sys::#offset as Int;
        );
    }
    // Some arches (MIPS) have lowercase register names.
    quote!(
        #[allow(non_upper_case_globals)]
        pub mod offset {
            #output
        }
    )
    .into()
}

#[proc_macro]
pub fn import_hwcaps(item: TokenStream) -> TokenStream {
    let hwcaps = parse_macro_input!(item as ImportArgs);
    let arch = hwcaps.arch.to_string().to_uppercase();
    let mut output = quote!();
    for hwcap in &hwcaps.items {
        let offset = format_ident!("VEX_HWCAPS_{}_{}", arch, hwcap);
        output = quote!(
            #output
            pub use vex_sys::#offset as #hwcap;
        );
    }
    quote!(
        pub mod hwcap {
            #output
        }
    )
    .into()
}

struct TypeEnv {
    tmps: Vec<(Ident, Token![:], Ident)>,
}

impl Parse for TypeEnv {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut tmps = Vec::new();
        while input.peek(Ident) && input.peek2(Token![:]) {
            tmps.push((input.parse()?, input.parse()?, input.parse()?));
        }
        Ok(TypeEnv { tmps })
    }
}

mod kw {
    syn::custom_keyword!(IR); // currently only used for IR-NoOp
    syn::custom_keyword!(NoOp);
    syn::custom_keyword!(IMark);
    syn::custom_keyword!(AbiHint);
    syn::custom_keyword!(CCall);
    syn::custom_keyword!(PUT);
    syn::custom_keyword!(GET);
    syn::custom_keyword!(STbe);
    syn::custom_keyword!(STle);
    syn::custom_keyword!(LDbe);
    syn::custom_keyword!(LDle);
    syn::custom_keyword!(exit);
}

enum LoadEndness {
    Big,
    Little,
}

enum StoreEndness {
    Big,
    Little,
}

impl quote::ToTokens for LoadEndness {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.extend(match self {
            Self::Big => quote!(IREndness::Iend_BE),
            Self::Little => quote!(IREndness::Iend_LE),
        })
    }
}

impl quote::ToTokens for StoreEndness {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.extend(match self {
            Self::Big => quote!(IREndness::Iend_BE),
            Self::Little => quote!(IREndness::Iend_LE),
        })
    }
}

impl Parse for LoadEndness {
    fn parse(input: ParseStream) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(kw::LDbe) {
            input.parse::<kw::LDbe>()?;
            Ok(Self::Big)
        } else if lookahead.peek(kw::LDle) {
            input.parse::<kw::LDle>()?;
            Ok(Self::Little)
        } else {
            Err(lookahead.error())
        }
    }
}

impl Parse for StoreEndness {
    fn parse(input: ParseStream) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(kw::STbe) {
            input.parse::<kw::STbe>()?;
            Ok(Self::Big)
        } else if lookahead.peek(kw::STle) {
            input.parse::<kw::STle>()?;
            Ok(Self::Little)
        } else {
            Err(lookahead.error())
        }
    }
}

enum Expr {
    Get(ExprGet),
    Op(ExprOp),
    Load(ExprLoad),
    Const(ExprConst),
    RdTmp(Ident),
}

struct ExprGet {
    _get: kw::GET,
    _colon: Token![:],
    size: Ident,
    _paren: token::Paren,
    offset: LitInt,
}

struct ExprOp {
    op: Ident,
    _paren: token::Paren,
    args: Punctuated<Expr, Token![,]>,
}

struct ExprLoad {
    end: LoadEndness,
    _colon: Token![:],
    ty: Ident,
    _paren: token::Paren,
    addr: Box<Expr>,
}

struct ExprConst {
    co: LitInt,
    _colon: Token![:],
    ty: Ident,
}

impl Parse for Expr {
    fn parse(input: ParseStream) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(kw::GET) {
            input.parse().map(Self::Get)
        } else if lookahead.peek(kw::LDle) || lookahead.peek(kw::LDbe) {
            input.parse().map(Self::Load)
        } else if lookahead.peek(LitInt) {
            input.parse().map(Self::Const)
        } else if lookahead.peek(Ident) && input.peek2(token::Paren) {
            input.parse().map(Self::Op)
        } else if lookahead.peek(Ident) {
            input.parse().map(Self::RdTmp)
        } else {
            Err(lookahead.error())
        }
    }
}

impl Parse for ExprGet {
    fn parse(input: ParseStream) -> Result<Self> {
        let offset;
        Ok(Self {
            _get: input.parse()?,
            _colon: input.parse()?,
            size: input.parse()?,
            _paren: parenthesized!(offset in input),
            offset: offset.parse()?,
        })
    }
}

impl Parse for ExprLoad {
    fn parse(input: ParseStream) -> Result<Self> {
        let addr;
        Ok(Self {
            end: input.parse()?,
            _colon: input.parse()?,
            ty: input.parse()?,
            _paren: parenthesized!(addr in input),
            addr: addr.parse()?,
        })
    }
}

impl Parse for ExprConst {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(Self {
            co: input.parse()?,
            _colon: input.parse()?,
            ty: input.parse()?,
        })
    }
}

impl Parse for ExprOp {
    fn parse(input: ParseStream) -> Result<Self> {
        let args;
        Ok(Self {
            op: input.parse()?,
            _paren: parenthesized!(args in input),
            args: args.parse_terminated(Expr::parse)?,
        })
    }
}

impl quote::ToTokens for Expr {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        match self {
            Self::Get(get) => get.to_tokens(tokens),
            Self::Op(op) => op.to_tokens(tokens),
            Self::Const(co) => co.to_tokens(tokens),
            Self::RdTmp(tmp) => tokens.extend(quote!(Expr::rd_tmp(#tmp))),
            Self::Load(load) => load.to_tokens(tokens),
        }
    }
}

impl quote::ToTokens for ExprGet {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let offset = &self.offset;
        let ty = format_ident!("Ity_{}", self.size);
        tokens.extend(quote!(Expr::get(#offset, Type::#ty)))
    }
}

impl quote::ToTokens for ExprOp {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let op = format_ident!("Iop_{}", &self.op);
        let args = &self.args;
        match self.args.len() {
            1 => tokens.extend(quote!(Expr::unop(Op::#op, #args))),
            2 => tokens.extend(quote!(Expr::binop(Op::#op, #args))),
            3 => tokens.extend(quote!(Expr::triop(Op::#op, #args))),
            4 => tokens.extend(quote!(Expr::qop(Op::#op, #args))),
            _ => panic!(),
        }
    }
}

impl quote::ToTokens for ExprLoad {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let (end, addr) = (&self.end, &self.addr);
        let ty = format_ident!("Ity_{}", self.ty);
        tokens.extend(quote!(Expr::load(#end, Type::#ty, #addr)))
    }
}

impl quote::ToTokens for ExprConst {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.extend(match self.ty.to_string().as_str() {
            "I1" => match self.co.base10_parse() {
                Ok(0) => quote!(Expr::const_(Const::u1(false))),
                Ok(1) => quote!(Expr::const_(Const::u1(true))),
                _ => quote!(compile_error!("Const of type I1 must be 0 or 1")),
            },
            "I8" => {
                let co = &self.co;
                quote!(Expr::const_(Const::u8(#co)))
            }
            "I16" => {
                let co = &self.co;
                quote!(Expr::const_(Const::u16(#co)))
            }
            "I32" => {
                let co = &self.co;
                quote!(Expr::const_(Const::u32(#co)))
            }
            "I64" => {
                let co = &self.co;
                quote!(Expr::const_(Const::u64(#co)))
            }
            _ => quote!(compile_error!("Invalid type")),
        });
    }
}

enum Stmt {
    NoOp,
    IMark(StmtIMark),
    AbiHint(StmtAbiHint),
    WrTmp(StmtWrTmp),
    Put(StmtPut),
    Store(StmtStore),
}

struct StmtNoOp {
    _ir: kw::IR,
    _dash: Token![-],
    _no_op: kw::NoOp,
}

struct StmtIMark {
    _imark: kw::IMark,
    _paren: token::Paren,
    info: Punctuated<LitInt, Token![,]>,
}

struct StmtAbiHint {
    base: Expr,
    len: LitInt,
    nia: Expr,
}

struct StmtWrTmp {
    tmp: Ident,
    _eq: Token![=],
    data: Expr,
}

struct StmtPut {
    _put: kw::PUT,
    _paren: token::Paren,
    offset: LitInt,
    _eq: Token![=],
    data: Expr,
}

struct StmtStore {
    store: StoreEndness,
    _paren: token::Paren,
    addr: Expr,
    _eq: Token![=],
    data: Expr,
}

impl Parse for Stmt {
    fn parse(input: ParseStream) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(kw::IR) {
            input.parse::<StmtNoOp>()?;
            Ok(Self::NoOp)
        } else if lookahead.peek(Token![-]) || lookahead.peek(kw::IMark) {
            input.parse().map(Self::IMark)
        } else if lookahead.peek(Token![=]) || lookahead.peek(kw::AbiHint) {
            input.parse().map(Self::AbiHint)
        } else if lookahead.peek(kw::PUT) {
            input.parse().map(Self::Put)
        } else if lookahead.peek(kw::STbe) || lookahead.peek(kw::STle) {
            input.parse().map(Self::Store)
        } else if lookahead.peek(Ident) {
            input.parse().map(Self::WrTmp)
        } else {
            Err(lookahead.error())
        }
    }
}

impl Parse for StmtNoOp {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(Self {
            _ir: input.parse()?,
            _dash: input.parse()?,
            _no_op: input.parse()?,
        })
    }
}

impl Parse for StmtIMark {
    fn parse(input: ParseStream) -> Result<Self> {
        while input.parse::<Token![-]>().is_ok() {}
        let info;
        let res = Self {
            _imark: input.parse()?,
            _paren: parenthesized!(info in input),
            info: info.parse_terminated(LitInt::parse)?,
        };
        while input.parse::<Token![-]>().is_ok() {}
        Ok(res)
    }
}

enum AbiArg {
    Expr(Expr),
    Int(LitInt),
}

impl AbiArg {
    fn expect_expr(self) -> syn::Result<Expr> {
        match self {
            Self::Expr(expr) => Ok(expr),
            _ => panic!(),
        }
    }

    fn expect_lit(self) -> syn::Result<LitInt> {
        match self {
            Self::Int(lit) => Ok(lit),
            _ => panic!(),
        }
    }
}

impl Parse for AbiArg {
    fn parse(input: ParseStream) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(LitInt) {
            input.parse().map(Self::Int)
        } else {
            input.parse().map(Self::Expr)
        }
    }
}

impl Parse for StmtAbiHint {
    fn parse(input: ParseStream) -> Result<Self> {
        while input.parse::<Token![=]>().is_ok() {}
        let info;
        let _abi_hint: kw::AbiHint = input.parse()?;
        let _paren = parenthesized!(info in input);
        let info = info.parse_terminated::<_, Token![,]>(AbiArg::parse)?;
        let mut info_iter = info.into_iter();

        let res = Self {
            base: info_iter.next().unwrap().expect_expr()?,
            len: info_iter.next().unwrap().expect_lit()?,
            nia: info_iter.next().unwrap().expect_expr()?,
        };
        while input.parse::<Token![=]>().is_ok() {}
        Ok(res)
    }
}

impl Parse for StmtWrTmp {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(Self {
            tmp: input.parse()?,
            _eq: input.parse()?,
            data: input.parse()?,
        })
    }
}

impl Parse for StmtPut {
    fn parse(input: ParseStream) -> Result<Self> {
        let offset;
        Ok(Self {
            _put: input.parse()?,
            _paren: parenthesized!(offset in input),
            offset: offset.parse()?,
            _eq: input.parse()?,
            data: input.parse()?,
        })
    }
}

impl Parse for StmtStore {
    fn parse(input: ParseStream) -> Result<Self> {
        let addr;
        Ok(Self {
            store: input.parse()?,
            _paren: parenthesized!(addr in input),
            addr: addr.parse()?,
            _eq: input.parse()?,
            data: input.parse()?,
        })
    }
}

impl quote::ToTokens for Stmt {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        match self {
            Self::NoOp => tokens.extend(quote!(Stmt::no_op())),
            Self::IMark(imark) => imark.to_tokens(tokens),
            Self::AbiHint(hint) => hint.to_tokens(tokens),
            Self::WrTmp(wr_tmp) => wr_tmp.to_tokens(tokens),
            Self::Put(put) => put.to_tokens(tokens),
            Self::Store(store) => store.to_tokens(tokens),
        }
    }
}

impl quote::ToTokens for StmtIMark {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let info = &self.info;
        tokens.extend(quote!(Stmt::imark(#info)))
    }
}

impl quote::ToTokens for StmtAbiHint {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let StmtAbiHint { base, len, nia } = self;
        tokens.extend(quote!(Stmt::abi_hint(#base, #len, #nia)))
    }
}

impl quote::ToTokens for StmtWrTmp {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let (tmp, data) = (&self.tmp, &self.data);
        tokens.extend(quote!(Stmt::wr_tmp(#tmp, #data)))
    }
}

impl quote::ToTokens for StmtPut {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let (offset, data) = (&self.offset, &self.data);
        tokens.extend(quote!(Stmt::put(#offset, #data)))
    }
}

impl quote::ToTokens for StmtStore {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let (end, addr, data) = (&self.store, &self.addr, &self.data);
        tokens.extend(quote!(Stmt::store(#end, #addr, #data)))
    }
}

struct ExitKind {
    _semi: Token![;],
    _exit: kw::exit,
    _dash: Token![-],
    kind: Ident,
}

impl Parse for ExitKind {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(Self {
            _semi: input.parse()?,
            _exit: input.parse()?,
            _dash: input.parse()?,
            kind: input.parse()?,
        })
    }
}

struct IRSB {
    ty_env: TypeEnv,
    stmts: Vec<Stmt>,
    exit: ExitKind,
}

impl Parse for IRSB {
    fn parse(input: ParseStream) -> Result<Self> {
        let ty_env = input.parse()?;
        let mut stmts = Vec::new();
        while !(input.is_empty() || input.peek(Token![;])) {
            stmts.push(input.parse()?);
        }
        Ok(IRSB {
            ty_env,
            stmts,
            exit: input.parse()?,
        })
    }
}

#[allow(non_snake_case)]
#[proc_macro]
pub fn IRSB(item: TokenStream) -> TokenStream {
    let irsb = parse_macro_input!(item as IRSB);

    let (ip_offset, next, stmts) = match irsb.stmts.split_last() {
        Some((Stmt::Put(StmtPut { offset, data, .. }), stmts)) => (offset, data, stmts),
        Some(_) => {
            return quote!(compile_error!(
                "The last statement is not a valid 'next' statement (PUT(ip_offset) = Expr)"
            ))
            .into();
        }
        None => {
            return quote!(compile_error!(
                "No statements found! (There must be at least the 'next' statement.)"
            ))
            .into();
        }
    };
    let jk = format_ident!("Ijk_{}", &irsb.exit.kind);
    let mut output = quote! {
        use libvex::ir::{Const, Expr, IREndness, IRSB, JumpKind, Op, Stmt, Type};
        let mut irsb = IRSB::new();
    };
    for (tmp, _colon, ty) in irsb.ty_env.tmps.iter() {
        let ty = format_ident!("Ity_{}", ty);
        output = quote! {
            #output
            let #tmp = irsb.type_env().new_tmp(Type::#ty);
        };
    }
    for stmt in stmts {
        output = quote! {
            #output
            irsb.add_stmt(#stmt);
        };
    }
    quote!(unsafe {
        #output
        irsb.set_next(#next);
        irsb.set_offs_ip(#ip_offset);
        irsb.set_jump_kind(JumpKind::#jk);
        irsb
    })
    .into()
}
