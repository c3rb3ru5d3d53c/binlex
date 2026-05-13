use super::LoweringContext;
use super::helpers::{coerce_int_value_width, const_int, render_address_space, sanitize_symbol};
use crate::semantics::{
    SemanticExpression, SemanticLocation, SemanticOperationBinary, SemanticOperationCast,
    SemanticOperationCompare, SemanticOperationUnary,
};
use inkwell::IntPredicate;
use inkwell::attributes::AttributeLoc;
use inkwell::values::{BasicMetadataValueEnum, FunctionValue, IntValue};
use std::io::Error;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    pub(super) fn lower_expression(
        &mut self,
        expression: &SemanticExpression,
    ) -> Result<IntValue<'ctx>, Error> {
        match expression {
            SemanticExpression::Const { value, bits } => {
                Ok(const_int(self.int_type(*bits), *value))
            }
            SemanticExpression::Function { name, bits } => {
                let function = self.module.get_function(name).ok_or_else(|| {
                    Error::other(format!("unknown semantic function target {name}"))
                })?;
                self.builder
                    .build_ptr_to_int(
                        function.as_global_value().as_pointer_value(),
                        self.int_type(*bits),
                        "functmp",
                    )
                    .map_err(|err| Error::other(err.to_string()))
            }
            SemanticExpression::DataAddress { name, bits } => {
                let global_name = sanitize_symbol(&format!("binlex_data_{name}"));
                let global = self
                    .module
                    .get_global(&global_name)
                    .ok_or_else(|| Error::other(format!("unknown semantic data target {name}")))?;
                self.builder
                    .build_ptr_to_int(global.as_pointer_value(), self.int_type(*bits), "datatmp")
                    .map_err(|err| Error::other(err.to_string()))
            }
            SemanticExpression::AddressOf { location, bits } => {
                let pointer = self.pointer_for_location(location)?;
                let pointer = self
                    .builder
                    .build_ptr_to_int(pointer, self.int_type(*bits), "addroftmp")
                    .map_err(|err| Error::other(err.to_string()))?;
                Ok(pointer)
            }
            SemanticExpression::Read(location) => self.read_location(location),
            SemanticExpression::Load { space, addr, bits } => {
                if let Some(value) = self.try_direct_load(space, addr, *bits)? {
                    return Ok(value);
                }
                let helper = self.declare_value_helper(
                    &format!(
                        "binlex_load_{}_{}",
                        sanitize_symbol(&render_address_space(space)),
                        bits
                    ),
                    self.int_type(*bits),
                    &[self.context.i64_type().into()],
                    false,
                );
                self.record_semantic_lowering(
                    "load_helper",
                    format!(
                        "space={} bits={} helper={}",
                        render_address_space(space),
                        bits,
                        helper.get_name().to_string_lossy()
                    ),
                );
                let addr = self.lower_expression(addr)?;
                let addr = self.to_i64(addr);
                self.call_value(helper, &[addr.into()], "loadtmp")
            }
            SemanticExpression::Unary { op, arg, bits } => {
                let arg = self.lower_expression(arg)?;
                self.lower_unary(*op, arg, *bits)
            }
            SemanticExpression::Binary {
                op,
                left,
                right,
                bits,
            } => {
                let left = self.lower_expression(left)?;
                let right = self.lower_expression(right)?;
                self.lower_binary(*op, left, right, *bits)
            }
            SemanticExpression::Cast { op, arg, bits } => {
                let arg = self.lower_expression(arg)?;
                self.lower_cast(*op, arg, *bits)
            }
            SemanticExpression::Compare {
                op, left, right, ..
            } => {
                let left = self.lower_expression(left)?;
                let right = self.lower_expression(right)?;
                self.lower_compare(*op, left, right)
            }
            SemanticExpression::Select {
                condition,
                when_true,
                when_false,
                ..
            } => {
                let condition = self.lower_expression(condition)?;
                let condition = self.to_bool(condition);
                let when_true = self.lower_expression(when_true)?;
                let when_false = self.lower_expression(when_false)?;
                Ok(self
                    .builder
                    .build_select(condition, when_true, when_false, "selecttmp")
                    .map_err(|err| Error::other(err.to_string()))?
                    .into_int_value())
            }
            SemanticExpression::Extract { arg, lsb, bits } => {
                if let Some(value) = self.try_lower_i386_div_extract(arg, *lsb, *bits)? {
                    return Ok(value);
                }
                let arg = self.lower_expression(arg)?;
                let shifted = self
                    .builder
                    .build_right_shift(
                        arg,
                        arg.get_type().const_int(*lsb as u64, false),
                        false,
                        "extract_shift",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
                if shifted.get_type().get_bit_width() == *bits as u32 {
                    Ok(shifted)
                } else {
                    self.builder
                        .build_int_truncate(shifted, self.int_type(*bits), "extract_trunc")
                        .map_err(|err| Error::other(err.to_string()))
                }
            }
            SemanticExpression::Concat { parts, bits } => {
                let target = self.int_type(*bits);
                let mut acc = target.const_zero();
                for part in parts {
                    let value = self.lower_expression(part)?;
                    let zext = if value.get_type().get_bit_width() == *bits as u32 {
                        value
                    } else {
                        self.builder
                            .build_int_z_extend(value, target, "concat_zext")
                            .map_err(|err| Error::other(err.to_string()))?
                    };
                    let shift = target.const_int(value.get_type().get_bit_width() as u64, false);
                    acc = self
                        .builder
                        .build_left_shift(acc, shift, "concat_shift")
                        .map_err(|err| Error::other(err.to_string()))?;
                    acc = self
                        .builder
                        .build_or(acc, zext, "concat_or")
                        .map_err(|err| Error::other(err.to_string()))?;
                }
                Ok(acc)
            }
            SemanticExpression::Undefined { bits } | SemanticExpression::Poison { bits } => {
                Ok(self.int_type(*bits).const_zero())
            }
            SemanticExpression::Null { bits } => Ok(self.int_type(*bits).const_zero()),
            SemanticExpression::Allocate { kind, bits } => {
                let helper_name = format!("binlex_ref_alloc_{}_{}", sanitize_symbol(kind), bits);
                let helper =
                    self.declare_value_helper(&helper_name, self.int_type(*bits), &[], true);
                self.record_semantic_lowering(
                    "reference_helper",
                    format!(
                        "Allocate kind={} bits={} helper={}",
                        kind, bits, helper_name
                    ),
                );
                self.call_value(helper, &[], "refalloc")
            }
            SemanticExpression::ReadProperty {
                reference,
                name,
                bits,
            } => {
                let helper_name = format!("binlex_ref_property_{}_{}", sanitize_symbol(name), bits);
                let helper = self.declare_value_helper(
                    &helper_name,
                    self.int_type(*bits),
                    &[self.context.i64_type().into()],
                    true,
                );
                let reference = self.lower_expression(reference)?;
                let reference = self.to_i64(reference);
                self.call_value(helper, &[reference.into()], "refprop")
            }
            SemanticExpression::ReadElement {
                reference,
                index,
                bits,
            } => {
                let helper_name = format!("binlex_ref_element_{}", bits);
                let helper = self.declare_value_helper(
                    &helper_name,
                    self.int_type(*bits),
                    &[
                        self.context.i64_type().into(),
                        self.context.i64_type().into(),
                    ],
                    true,
                );
                let reference = self.lower_expression(reference)?;
                let reference = self.to_i64(reference);
                let index = self.lower_expression(index)?;
                let index = self.to_i64(index);
                self.call_value(helper, &[reference.into(), index.into()], "refelem")
            }
            SemanticExpression::Intrinsic { name, args, bits } => {
                let helper_name = format!("binlex_expr_{}", sanitize_symbol(name));
                let helper =
                    self.declare_value_helper(&helper_name, self.int_type(*bits), &[], true);
                self.record_semantic_lowering(
                    "expression_intrinsic",
                    format!(
                        "name={} bits={} args={} helper={}",
                        name,
                        bits,
                        args.len(),
                        helper.get_name().to_string_lossy()
                    ),
                );
                let args = self.lower_arg_values(args)?;
                self.call_value(helper, &args, "intrinsicexpr")
            }
        }
    }

    fn try_lower_i386_div_extract(
        &mut self,
        arg: &SemanticExpression,
        lsb: u16,
        bits: u16,
    ) -> Result<Option<IntValue<'ctx>>, Error> {
        let is_i386 = matches!(
            self.module.get_triple().as_str().to_str(),
            Ok(triple) if triple.starts_with("i386")
        );
        if !is_i386 || lsb != 0 || bits != 32 {
            return Ok(None);
        }
        let (signed, remainder, dividend, divisor) = match arg {
            SemanticExpression::Binary {
                op,
                left,
                right,
                bits: 64,
            } => match op {
                SemanticOperationBinary::UDiv => (false, false, &**left, &**right),
                SemanticOperationBinary::SDiv => (true, false, &**left, &**right),
                SemanticOperationBinary::URem => (false, true, &**left, &**right),
                SemanticOperationBinary::SRem => (true, true, &**left, &**right),
                _ => return Ok(None),
            },
            _ => return Ok(None),
        };
        let (high, low) = match dividend {
            SemanticExpression::Concat { parts, bits: 64 } if parts.len() == 2 => {
                (&parts[0], &parts[1])
            }
            _ => return Ok(None),
        };
        let divisor = match divisor {
            SemanticExpression::Cast { arg, bits: 64, .. } => &**arg,
            _ => return Ok(None),
        };
        let ty = self.context.i32_type();
        let low_value = self.lower_expression(low)?;
        let low_value = self.lower_cast(SemanticOperationCast::ZeroExtend, low_value, 32)?;
        let high_value = self.lower_expression(high)?;
        let high_value = self.lower_cast(SemanticOperationCast::ZeroExtend, high_value, 32)?;
        let divisor_value = self.lower_expression(divisor)?;
        let divisor_value =
            self.lower_cast(SemanticOperationCast::ZeroExtend, divisor_value, 32)?;
        let low_slot = self.build_entry_alloca(ty, "div_low_slot")?;
        let high_slot = self.build_entry_alloca(ty, "div_high_slot")?;
        let divisor_slot = self.build_entry_alloca(ty, "div_divisor_slot")?;
        let out_slot = self.build_entry_alloca(ty, "div_out_slot")?;
        self.builder
            .build_store(low_slot, low_value)
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_store(high_slot, high_value)
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_store(divisor_slot, divisor_value)
            .map_err(|err| Error::other(err.to_string()))?;
        let fn_ty = self.context.void_type().fn_type(
            &[
                self.context
                    .ptr_type(inkwell::AddressSpace::default())
                    .into(),
                self.context
                    .ptr_type(inkwell::AddressSpace::default())
                    .into(),
                self.context
                    .ptr_type(inkwell::AddressSpace::default())
                    .into(),
                self.context
                    .ptr_type(inkwell::AddressSpace::default())
                    .into(),
            ],
            false,
        );
        let div_mnemonic = if signed { "idivl" } else { "divl" };
        let store_reg = if remainder { "%edx" } else { "%eax" };
        let asm = self.context.create_inline_asm(
            fn_ty,
            format!("movl $0, %eax; movl $1, %edx; {div_mnemonic} $2; movl {store_reg}, $3"),
            "*m,*m,*m,*m,~{eax},~{edx},~{dirflag},~{fpsr},~{flags}".to_string(),
            true,
            false,
            None,
            false,
        );
        let call = self
            .builder
            .build_indirect_call(
                fn_ty,
                asm,
                &[
                    low_slot.into(),
                    high_slot.into(),
                    divisor_slot.into(),
                    out_slot.into(),
                ],
                "",
            )
            .map_err(|err| Error::other(err.to_string()))?;
        for index in 0..4 {
            call.add_attribute(AttributeLoc::Param(index), self.elementtype_attribute(ty));
        }
        Ok(Some(
            self.builder
                .build_load(ty, out_slot, "div_extract")
                .map_err(|err| Error::other(err.to_string()))?
                .into_int_value(),
        ))
    }

    pub(super) fn read_location(
        &mut self,
        location: &SemanticLocation,
    ) -> Result<IntValue<'ctx>, Error> {
        match location {
            SemanticLocation::Memory { space, addr, bits } => {
                if let Some(value) = self.try_direct_load(space, addr, *bits)? {
                    return Ok(value);
                }
                let helper = self.declare_value_helper(
                    &format!(
                        "binlex_load_{}_{}",
                        sanitize_symbol(&render_address_space(space)),
                        bits
                    ),
                    self.int_type(*bits),
                    &[self.context.i64_type().into()],
                    false,
                );
                self.record_semantic_lowering(
                    "load_helper",
                    format!(
                        "space={} bits={} helper={}",
                        render_address_space(space),
                        bits,
                        helper.get_name().to_string_lossy()
                    ),
                );
                let addr = self.lower_expression(addr)?;
                let addr = self.to_i64(addr);
                self.call_value(helper, &[addr.into()], "memread")
            }
            _ => {
                let slot = self.slot_for_location(location)?;
                let ty = self.location_type(location);
                Ok(self
                    .builder
                    .build_load(ty, slot, "readtmp")
                    .map_err(|err| Error::other(err.to_string()))?
                    .into_int_value())
            }
        }
    }

    pub(super) fn lower_arg_values(
        &mut self,
        args: &[SemanticExpression],
    ) -> Result<Vec<BasicMetadataValueEnum<'ctx>>, Error> {
        args.iter()
            .map(|arg| self.lower_expression(arg).map(Into::into))
            .collect()
    }

    pub(super) fn call_value(
        &self,
        function: FunctionValue<'ctx>,
        args: &[BasicMetadataValueEnum<'ctx>],
        name: &str,
    ) -> Result<IntValue<'ctx>, Error> {
        self.builder
            .build_call(function, args, name)
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected value result from helper call"))
            .map(|value| value.into_int_value())
    }

    fn lower_unary(
        &mut self,
        op: SemanticOperationUnary,
        arg: IntValue<'ctx>,
        bits: u16,
    ) -> Result<IntValue<'ctx>, Error> {
        match op {
            SemanticOperationUnary::Not => self
                .builder
                .build_not(arg, "nottmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationUnary::Neg => self
                .builder
                .build_int_neg(arg, "negtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationUnary::ByteSwap => {
                let name = format!("llvm.bswap.i{}", bits);
                let function = self.module.get_function(&name).unwrap_or_else(|| {
                    self.module.add_function(
                        &name,
                        self.int_type(bits)
                            .fn_type(&[self.int_type(bits).into()], false),
                        None,
                    )
                });
                self.call_value(function, &[arg.into()], "bswaptmp")
            }
            SemanticOperationUnary::CountLeadingZeros => {
                let name = format!("llvm.ctlz.i{}", bits);
                let function = self.module.get_function(&name).unwrap_or_else(|| {
                    self.module.add_function(
                        &name,
                        self.int_type(bits).fn_type(
                            &[self.int_type(bits).into(), self.context.bool_type().into()],
                            false,
                        ),
                        None,
                    )
                });
                self.call_value(
                    function,
                    &[arg.into(), self.context.bool_type().const_zero().into()],
                    "ctlztmp",
                )
            }
            SemanticOperationUnary::CountTrailingZeros => {
                let name = format!("llvm.cttz.i{}", bits);
                let function = self.module.get_function(&name).unwrap_or_else(|| {
                    self.module.add_function(
                        &name,
                        self.int_type(bits).fn_type(
                            &[self.int_type(bits).into(), self.context.bool_type().into()],
                            false,
                        ),
                        None,
                    )
                });
                self.call_value(
                    function,
                    &[arg.into(), self.context.bool_type().const_zero().into()],
                    "cttztmp",
                )
            }
            SemanticOperationUnary::PopCount => {
                let name = format!("llvm.ctpop.i{}", bits);
                let function = self.module.get_function(&name).unwrap_or_else(|| {
                    self.module.add_function(
                        &name,
                        self.int_type(bits)
                            .fn_type(&[self.int_type(bits).into()], false),
                        None,
                    )
                });
                self.call_value(function, &[arg.into()], "ctpoptmp")
            }
            _ => {
                let helper_name = format!("binlex_unary_{:?}", op).to_lowercase();
                let helper = self.declare_value_helper(
                    &helper_name,
                    self.int_type(bits),
                    &[arg.get_type().into()],
                    false,
                );
                self.record_semantic_lowering(
                    "unary_helper",
                    format!(
                        "{:?} bits={} helper={}",
                        op,
                        bits,
                        helper.get_name().to_string_lossy()
                    ),
                );
                self.call_value(helper, &[arg.into()], "unarytmp")
            }
        }
    }

    fn lower_binary(
        &mut self,
        op: SemanticOperationBinary,
        left: IntValue<'ctx>,
        right: IntValue<'ctx>,
        bits: u16,
    ) -> Result<IntValue<'ctx>, Error> {
        let binary_helper = |this: &mut Self| {
            let helper_name = format!("binlex_binary_{:?}", op).to_lowercase();
            let helper = this.declare_value_helper(
                &helper_name,
                this.int_type(bits),
                &[left.get_type().into(), right.get_type().into()],
                false,
            );
            this.record_semantic_lowering(
                "binary_helper",
                format!(
                    "{:?} bits={} helper={}",
                    op,
                    bits,
                    helper.get_name().to_string_lossy()
                ),
            );
            this.call_value(helper, &[left.into(), right.into()], "binarytmp")
        };
        match op {
            SemanticOperationBinary::FAdd => {
                if !matches!(bits, 32 | 64) {
                    return binary_helper(self);
                }
                let float_type = self.float_type(bits)?;
                let left = self.int_bits_to_float(left, float_type, "fadd_lhs")?;
                let right = self.int_bits_to_float(right, float_type, "fadd_rhs")?;
                let sum = self
                    .builder
                    .build_float_add(left, right, "faddtmp")
                    .map_err(|err| Error::other(err.to_string()))?;
                self.float_to_int_bits(sum, self.int_type(bits), "fadd_bits")
            }
            SemanticOperationBinary::FSub => {
                if !matches!(bits, 32 | 64) {
                    return binary_helper(self);
                }
                let float_type = self.float_type(bits)?;
                let left = self.int_bits_to_float(left, float_type, "fsub_lhs")?;
                let right = self.int_bits_to_float(right, float_type, "fsub_rhs")?;
                let difference = self
                    .builder
                    .build_float_sub(left, right, "fsubtmp")
                    .map_err(|err| Error::other(err.to_string()))?;
                self.float_to_int_bits(difference, self.int_type(bits), "fsub_bits")
            }
            SemanticOperationBinary::FMul => {
                if !matches!(bits, 32 | 64) {
                    return binary_helper(self);
                }
                let float_type = self.float_type(bits)?;
                let left = self.int_bits_to_float(left, float_type, "fmul_lhs")?;
                let right = self.int_bits_to_float(right, float_type, "fmul_rhs")?;
                let product = self
                    .builder
                    .build_float_mul(left, right, "fmultmp")
                    .map_err(|err| Error::other(err.to_string()))?;
                self.float_to_int_bits(product, self.int_type(bits), "fmul_bits")
            }
            SemanticOperationBinary::FDiv => {
                if !matches!(bits, 32 | 64) {
                    return binary_helper(self);
                }
                let float_type = self.float_type(bits)?;
                let left = self.int_bits_to_float(left, float_type, "fdiv_lhs")?;
                let right = self.int_bits_to_float(right, float_type, "fdiv_rhs")?;
                let quotient = self
                    .builder
                    .build_float_div(left, right, "fdivtmp")
                    .map_err(|err| Error::other(err.to_string()))?;
                self.float_to_int_bits(quotient, self.int_type(bits), "fdiv_bits")
            }
            SemanticOperationBinary::Add | SemanticOperationBinary::AddWithCarry => self
                .builder
                .build_int_add(left, right, "addtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::Sub | SemanticOperationBinary::SubWithBorrow => self
                .builder
                .build_int_sub(left, right, "subtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::Mul => self
                .builder
                .build_int_mul(left, right, "multmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::UDiv => self
                .builder
                .build_int_unsigned_div(left, right, "udivtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::SDiv => self
                .builder
                .build_int_signed_div(left, right, "sdivtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::URem => self
                .builder
                .build_int_unsigned_rem(left, right, "uremtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::SRem => self
                .builder
                .build_int_signed_rem(left, right, "sremtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::And => self
                .builder
                .build_and(left, right, "andtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::Or => self
                .builder
                .build_or(left, right, "ortmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::Xor => self
                .builder
                .build_xor(left, right, "xortmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::Shl => self
                .builder
                .build_left_shift(
                    left,
                    coerce_int_value_width(
                        &self.builder,
                        right,
                        left.get_type(),
                        "shift_zext",
                        "shift_trunc",
                    )?,
                    "shltmp",
                )
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::LShr => self
                .builder
                .build_right_shift(
                    left,
                    coerce_int_value_width(
                        &self.builder,
                        right,
                        left.get_type(),
                        "shift_zext",
                        "shift_trunc",
                    )?,
                    false,
                    "lshrtmp",
                )
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::AShr => self
                .builder
                .build_right_shift(
                    left,
                    coerce_int_value_width(
                        &self.builder,
                        right,
                        left.get_type(),
                        "shift_zext",
                        "shift_trunc",
                    )?,
                    true,
                    "ashrtmp",
                )
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::RotateLeft => {
                self.record_semantic_lowering(
                    "binary_intrinsic",
                    format!("RotateLeft bits={} via llvm.fshl.i{}", bits, bits),
                );
                let name = format!("llvm.fshl.i{}", bits);
                let function = self.module.get_function(&name).unwrap_or_else(|| {
                    self.module.add_function(
                        &name,
                        self.int_type(bits).fn_type(
                            &[
                                self.int_type(bits).into(),
                                self.int_type(bits).into(),
                                self.int_type(bits).into(),
                            ],
                            false,
                        ),
                        None,
                    )
                });
                let right = coerce_int_value_width(
                    &self.builder,
                    right,
                    left.get_type(),
                    "rotate_zext",
                    "rotate_trunc",
                )?;
                self.call_value(
                    function,
                    &[left.into(), left.into(), right.into()],
                    "roltmp",
                )
            }
            SemanticOperationBinary::RotateRight => {
                self.record_semantic_lowering(
                    "binary_intrinsic",
                    format!("RotateRight bits={} via llvm.fshr.i{}", bits, bits),
                );
                let name = format!("llvm.fshr.i{}", bits);
                let function = self.module.get_function(&name).unwrap_or_else(|| {
                    self.module.add_function(
                        &name,
                        self.int_type(bits).fn_type(
                            &[
                                self.int_type(bits).into(),
                                self.int_type(bits).into(),
                                self.int_type(bits).into(),
                            ],
                            false,
                        ),
                        None,
                    )
                });
                let right = coerce_int_value_width(
                    &self.builder,
                    right,
                    left.get_type(),
                    "rotate_zext",
                    "rotate_trunc",
                )?;
                self.call_value(
                    function,
                    &[left.into(), left.into(), right.into()],
                    "rortmp",
                )
            }
            _ => binary_helper(self),
        }
    }

    fn lower_cast(
        &mut self,
        op: SemanticOperationCast,
        arg: IntValue<'ctx>,
        bits: u16,
    ) -> Result<IntValue<'ctx>, Error> {
        let target = self.int_type(bits);
        let source_bits = arg.get_type().get_bit_width();
        let cast_helper = |this: &mut Self| {
            let helper_name = format!("binlex_cast_{:?}", op).to_lowercase();
            let helper =
                this.declare_value_helper(&helper_name, target, &[arg.get_type().into()], false);
            this.record_semantic_lowering(
                "cast_helper",
                format!(
                    "{:?} {}->{} helper={}",
                    op,
                    source_bits,
                    bits,
                    helper.get_name().to_string_lossy()
                ),
            );
            this.call_value(helper, &[arg.into()], "casttmp")
        };
        match op {
            SemanticOperationCast::ZeroExtend => {
                if source_bits == bits as u32 {
                    Ok(arg)
                } else if source_bits > bits as u32 {
                    self.builder
                        .build_int_truncate(arg, target, "trunctmp")
                        .map_err(|err| Error::other(err.to_string()))
                } else {
                    self.builder
                        .build_int_z_extend(arg, target, "zexttmp")
                        .map_err(|err| Error::other(err.to_string()))
                }
            }
            SemanticOperationCast::SignExtend => {
                if source_bits == bits as u32 {
                    Ok(arg)
                } else if source_bits > bits as u32 {
                    self.builder
                        .build_int_truncate(arg, target, "trunctmp")
                        .map_err(|err| Error::other(err.to_string()))
                } else {
                    self.builder
                        .build_int_s_extend(arg, target, "sexttmp")
                        .map_err(|err| Error::other(err.to_string()))
                }
            }
            SemanticOperationCast::Truncate => {
                if source_bits == bits as u32 {
                    Ok(arg)
                } else {
                    self.builder
                        .build_int_truncate(arg, target, "trunctmp")
                        .map_err(|err| Error::other(err.to_string()))
                }
            }
            SemanticOperationCast::IntToFloat => {
                if !matches!(bits, 32 | 64) {
                    return cast_helper(self);
                }
                let float_type = self.float_type(bits)?;
                let float = self
                    .builder
                    .build_signed_int_to_float(arg, float_type, "sitofptmp")
                    .map_err(|err| Error::other(err.to_string()))?;
                self.float_to_int_bits(float, target, "sitofp_bits")
            }
            SemanticOperationCast::UIntToFloat => {
                if !matches!(bits, 32 | 64) {
                    return cast_helper(self);
                }
                let float_type = self.float_type(bits)?;
                let float = self
                    .builder
                    .build_unsigned_int_to_float(arg, float_type, "uitofptmp")
                    .map_err(|err| Error::other(err.to_string()))?;
                self.float_to_int_bits(float, target, "uitofp_bits")
            }
            SemanticOperationCast::FloatToInt => {
                if !matches!(source_bits as u16, 32 | 64) {
                    return cast_helper(self);
                }
                let float_type = self.float_type(source_bits as u16)?;
                let float = self.int_bits_to_float(arg, float_type, "fptosi_arg")?;
                let ordered = self
                    .builder
                    .build_float_compare(inkwell::FloatPredicate::ORD, float, float, "fptosi_ord")
                    .map_err(|err| Error::other(err.to_string()))?;
                let min_float = match bits {
                    32 => float_type.const_float(i32::MIN as f64),
                    64 => float_type.const_float(i64::MIN as f64),
                    _ => {
                        return Err(Error::other(format!(
                            "unsupported float-to-int destination width: {}",
                            bits
                        )));
                    }
                };
                let max_float = match bits {
                    32 => float_type.const_float(i32::MAX as f64),
                    64 => float_type.const_float(i64::MAX as f64),
                    _ => unreachable!(),
                };
                let ge_min = self
                    .builder
                    .build_float_compare(
                        inkwell::FloatPredicate::OGE,
                        float,
                        min_float,
                        "fptosi_ge_min",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
                let le_max = self
                    .builder
                    .build_float_compare(
                        inkwell::FloatPredicate::OLE,
                        float,
                        max_float,
                        "fptosi_le_max",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
                let in_range = self
                    .builder
                    .build_and(ordered, ge_min, "fptosi_ord_min")
                    .map_err(|err| Error::other(err.to_string()))?;
                let in_range = self
                    .builder
                    .build_and(in_range, le_max, "fptosi_in_range")
                    .map_err(|err| Error::other(err.to_string()))?;
                let converted = self
                    .builder
                    .build_float_to_signed_int(float, target, "fptositmp")
                    .map_err(|err| Error::other(err.to_string()))?;
                let fallback = match bits {
                    32 => target.const_int(i32::MIN as u32 as u64, false),
                    64 => target.const_int(i64::MIN as u64, false),
                    _ => unreachable!(),
                };
                self.builder
                    .build_select(in_range, converted, fallback, "fptosi_select")
                    .map_err(|err| Error::other(err.to_string()))
                    .map(|value| value.into_int_value())
            }
            SemanticOperationCast::FloatToUInt => {
                if !matches!(source_bits as u16, 32 | 64) {
                    return cast_helper(self);
                }
                let float_type = self.float_type(source_bits as u16)?;
                let float = self.int_bits_to_float(arg, float_type, "fptoui_arg")?;
                let ordered = self
                    .builder
                    .build_float_compare(inkwell::FloatPredicate::ORD, float, float, "fptoui_ord")
                    .map_err(|err| Error::other(err.to_string()))?;
                let min_float = float_type.const_float(-1.0);
                let max_float = match bits {
                    32 => float_type.const_float(u32::MAX as f64),
                    64 => float_type.const_float(u64::MAX as f64),
                    _ => {
                        return Err(Error::other(format!(
                            "unsupported float-to-uint destination width: {}",
                            bits
                        )));
                    }
                };
                let gt_min = self
                    .builder
                    .build_float_compare(
                        inkwell::FloatPredicate::OGT,
                        float,
                        min_float,
                        "fptoui_gt_min",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
                let le_max = self
                    .builder
                    .build_float_compare(
                        inkwell::FloatPredicate::OLE,
                        float,
                        max_float,
                        "fptoui_le_max",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
                let in_range = self
                    .builder
                    .build_and(ordered, gt_min, "fptoui_ord_min")
                    .map_err(|err| Error::other(err.to_string()))?;
                let in_range = self
                    .builder
                    .build_and(in_range, le_max, "fptoui_in_range")
                    .map_err(|err| Error::other(err.to_string()))?;
                let converted = self
                    .builder
                    .build_float_to_unsigned_int(float, target, "fptouitmp")
                    .map_err(|err| Error::other(err.to_string()))?;
                self.builder
                    .build_select(in_range, converted, target.const_zero(), "fptoui_select")
                    .map_err(|err| Error::other(err.to_string()))
                    .map(|value| value.into_int_value())
            }
            _ => cast_helper(self),
        }
    }

    fn lower_compare(
        &mut self,
        op: SemanticOperationCompare,
        left: IntValue<'ctx>,
        right: IntValue<'ctx>,
    ) -> Result<IntValue<'ctx>, Error> {
        let compare_helper = |this: &mut Self| {
            let helper_name = format!("binlex_compare_{:?}", op).to_lowercase();
            let helper = this.declare_value_helper(
                &helper_name,
                this.context.bool_type(),
                &[left.get_type().into(), right.get_type().into()],
                false,
            );
            this.record_semantic_lowering(
                "compare_helper",
                format!(
                    "{:?} lhs_bits={} rhs_bits={} helper={}",
                    op,
                    left.get_type().get_bit_width(),
                    right.get_type().get_bit_width(),
                    helper.get_name().to_string_lossy()
                ),
            );
            this.call_value(helper, &[left.into(), right.into()], "cmptmp")
        };
        let predicate = match op {
            SemanticOperationCompare::Eq => Some(IntPredicate::EQ),
            SemanticOperationCompare::Ne => Some(IntPredicate::NE),
            SemanticOperationCompare::Ult => Some(IntPredicate::ULT),
            SemanticOperationCompare::Ule => Some(IntPredicate::ULE),
            SemanticOperationCompare::Ugt => Some(IntPredicate::UGT),
            SemanticOperationCompare::Uge => Some(IntPredicate::UGE),
            SemanticOperationCompare::Slt => Some(IntPredicate::SLT),
            SemanticOperationCompare::Sle => Some(IntPredicate::SLE),
            SemanticOperationCompare::Sgt => Some(IntPredicate::SGT),
            SemanticOperationCompare::Sge => Some(IntPredicate::SGE),
            _ => None,
        };
        if let Some(predicate) = predicate {
            self.builder
                .build_int_compare(predicate, left, right, "cmptmp")
                .map_err(|err| Error::other(err.to_string()))
        } else {
            match op {
                SemanticOperationCompare::Oeq
                | SemanticOperationCompare::Oge
                | SemanticOperationCompare::Olt
                | SemanticOperationCompare::Unordered => {
                    if !matches!(left.get_type().get_bit_width(), 32 | 64) {
                        return compare_helper(self);
                    }
                    let float_type = self.float_type(left.get_type().get_bit_width() as u16)?;
                    let left = self.int_bits_to_float(left, float_type, "fcmp_lhs")?;
                    let right = self.int_bits_to_float(right, float_type, "fcmp_rhs")?;
                    let predicate = match op {
                        SemanticOperationCompare::Oeq => inkwell::FloatPredicate::OEQ,
                        SemanticOperationCompare::Oge => inkwell::FloatPredicate::OGE,
                        SemanticOperationCompare::Olt => inkwell::FloatPredicate::OLT,
                        SemanticOperationCompare::Unordered => inkwell::FloatPredicate::UNO,
                        _ => unreachable!("matched above"),
                    };
                    self.builder
                        .build_float_compare(predicate, left, right, "cmptmp")
                        .map_err(|err| Error::other(err.to_string()))
                }
                _ => compare_helper(self),
            }
        }
    }
}
