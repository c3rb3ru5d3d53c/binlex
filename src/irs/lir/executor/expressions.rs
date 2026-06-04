use crate::irs::lir::executor::{LirExecutor, LirExecutorError, LirExecutorState};
use crate::irs::lir::{
    LirExpression, LirLocation, LirOperationBinary, LirOperationCast, LirOperationCompare,
    LirOperationUnary,
};
use std::collections::BTreeSet;
use z3::ast::{BV, Bool, RoundingMode};

#[derive(Clone)]
pub(crate) struct EvaluatedValue {
    pub(crate) value: BV,
    pub(crate) deps: BTreeSet<u64>,
}

#[derive(Clone)]
pub(crate) struct EvaluatedCondition {
    pub(crate) value: Bool,
    pub(crate) deps: BTreeSet<u64>,
}

impl LirExecutor {
    pub(crate) fn eval_expression(
        &self,
        state: &mut LirExecutorState,
        expression: &LirExpression,
        expected_float: bool,
    ) -> Result<EvaluatedValue, LirExecutorError> {
        match expression {
            LirExpression::Const { value, bits } => Ok(EvaluatedValue {
                value: state.backend().const_bv(*value, *bits)?,
                deps: BTreeSet::new(),
            }),
            LirExpression::Function { bits, .. } => Ok(EvaluatedValue {
                value: state.backend().const_bv(0, *bits)?,
                deps: BTreeSet::new(),
            }),
            LirExpression::DataAddress { name, bits } => {
                let address = state.semantic_data_address(name).ok_or(
                    LirExecutorError::UnsupportedExpression("unknown semantic data_address symbol"),
                )?;
                Ok(EvaluatedValue {
                    value: state.backend().const_bv(address as u128, *bits)?,
                    deps: BTreeSet::new(),
                })
            }
            LirExpression::AddressOf { bits, .. } => Ok(EvaluatedValue {
                value: state.backend().const_bv(0, *bits)?,
                deps: BTreeSet::new(),
            }),
            LirExpression::Read(location) => self.read_location(state, location),
            LirExpression::Load { addr, bits, .. } => {
                let address = self.eval_expression(state, addr, false)?;
                let address_value = self.coerce_address(state, &address.value)?;
                let (value, mut deps) =
                    state
                        .memory()
                        .load_with_provenance(state.backend(), &address_value, *bits)?;
                if address_value.as_u64().is_none() {
                    deps.extend(address.deps);
                }
                if deps.is_empty() && address_value.as_u64().is_some() && *bits <= 64 {
                    if let Some(concrete) = state
                        .backend()
                        .eval_bv_u64(state.solver_constraints(), &value)?
                    {
                        return Ok(EvaluatedValue {
                            value: state.backend().const_bv(concrete as u128, *bits)?,
                            deps,
                        });
                    }
                }
                Ok(EvaluatedValue { value, deps })
            }
            LirExpression::Null { bits } => Ok(EvaluatedValue {
                value: state.backend().const_bv(0, *bits)?,
                deps: BTreeSet::new(),
            }),
            LirExpression::Allocate { kind, bits } => {
                let cell = state.allocate_reference(kind, *bits)?;
                Ok(EvaluatedValue {
                    value: cell.value,
                    deps: cell.def_id.into_iter().collect(),
                })
            }
            LirExpression::ReadProperty {
                reference,
                name,
                bits,
            } => {
                let reference = self.eval_expression(state, reference, false)?;
                let reference_key = self.symbolic_key(&reference.value);
                let cell = state.get_or_create_reference_property(&reference_key, name, *bits)?;
                let mut deps = cell.def_id.into_iter().collect::<BTreeSet<_>>();
                if reference.value.as_u64().is_none() {
                    deps.extend(reference.deps);
                }
                Ok(EvaluatedValue {
                    value: cell.value,
                    deps,
                })
            }
            LirExpression::ReadElement {
                reference,
                index,
                bits,
            } => {
                let reference = self.eval_expression(state, reference, false)?;
                let reference_key = self.symbolic_key(&reference.value);
                let index = self.eval_expression(state, index, false)?;
                let index_key = self.symbolic_key(&index.value);
                let cell =
                    state.get_or_create_reference_element(&reference_key, &index_key, *bits)?;
                let mut deps = cell.def_id.into_iter().collect::<BTreeSet<_>>();
                if reference.value.as_u64().is_none() {
                    deps.extend(reference.deps);
                }
                if index.value.as_u64().is_none() {
                    deps.extend(index.deps);
                }
                Ok(EvaluatedValue {
                    value: cell.value,
                    deps,
                })
            }
            LirExpression::Unary { op, arg, bits } => {
                let arg_expression = arg.as_ref();
                let arg = self.eval_expression(state, arg_expression, expected_float)?;
                let value = state.backend().coerce_bv_width(&arg.value, *bits)?;
                Ok(EvaluatedValue {
                    value: self.eval_unary(
                        state,
                        *op,
                        value,
                        arg_expression,
                        *bits,
                        expected_float,
                    )?,
                    deps: arg.deps,
                })
            }
            LirExpression::Binary {
                op,
                left,
                right,
                bits,
            } => {
                let binary_is_float = matches!(
                    op,
                    LirOperationBinary::FAdd
                        | LirOperationBinary::FSub
                        | LirOperationBinary::FMul
                        | LirOperationBinary::FDiv
                );
                let left = self.eval_expression(state, left, binary_is_float)?;
                let right = self.eval_expression(state, right, binary_is_float)?;
                let lhs = state.backend().coerce_bv_width(&left.value, *bits)?;
                let rhs = state.backend().coerce_bv_width(&right.value, *bits)?;
                let mut deps = left.deps;
                deps.extend(right.deps);
                Ok(EvaluatedValue {
                    value: self.eval_binary(state, *op, lhs, rhs)?,
                    deps,
                })
            }
            LirExpression::Cast { op, arg, bits } => {
                let cast_arg_is_float = matches!(
                    op,
                    LirOperationCast::FloatToInt
                        | LirOperationCast::FloatToUInt
                        | LirOperationCast::FloatExtend
                        | LirOperationCast::FloatTruncate
                );
                let arg = self.eval_expression(state, arg, cast_arg_is_float)?;
                Ok(EvaluatedValue {
                    value: self.eval_cast(state, *op, arg.value, *bits)?,
                    deps: arg.deps,
                })
            }
            LirExpression::Compare {
                op,
                left,
                right,
                bits,
            } => {
                let compare_is_float = matches!(
                    op,
                    LirOperationCompare::Ordered
                        | LirOperationCompare::Unordered
                        | LirOperationCompare::Oeq
                        | LirOperationCompare::One
                        | LirOperationCompare::Olt
                        | LirOperationCompare::Ole
                        | LirOperationCompare::Ogt
                        | LirOperationCompare::Oge
                        | LirOperationCompare::Ueq
                        | LirOperationCompare::Une
                        | LirOperationCompare::UltFp
                        | LirOperationCompare::UleFp
                        | LirOperationCompare::UgtFp
                        | LirOperationCompare::UgeFp
                );
                let left = self.eval_expression(state, left, compare_is_float)?;
                let right = self.eval_expression(state, right, compare_is_float)?;
                let width = left.value.get_size().max(right.value.get_size()) as u16;
                let lhs = state.backend().coerce_bv_width(&left.value, width)?;
                let rhs = state.backend().coerce_bv_width(&right.value, width)?;
                let value = self.eval_compare(state, *op, lhs, rhs)?;
                let mut deps = left.deps;
                deps.extend(right.deps);
                Ok(EvaluatedValue {
                    value: state.backend().bool_to_bv(&value, *bits)?,
                    deps,
                })
            }
            LirExpression::Select {
                condition,
                when_true,
                when_false,
                bits,
            } => {
                let condition = self.eval_condition(state, condition)?;
                let when_true = self.eval_expression(state, when_true, expected_float)?;
                let when_false = self.eval_expression(state, when_false, expected_float)?;
                let when_true_value = state.backend().coerce_bv_width(&when_true.value, *bits)?;
                let when_false_value = state.backend().coerce_bv_width(&when_false.value, *bits)?;
                let mut deps = condition.deps;
                deps.extend(when_true.deps);
                deps.extend(when_false.deps);
                Ok(EvaluatedValue {
                    value: condition.value.ite(&when_true_value, &when_false_value),
                    deps,
                })
            }
            LirExpression::Extract { arg, lsb, bits } => {
                let arg = self.eval_expression(state, arg, expected_float)?;
                Ok(EvaluatedValue {
                    value: arg.value.extract((*lsb + *bits - 1) as u32, *lsb as u32),
                    deps: arg.deps,
                })
            }
            LirExpression::Concat { parts, bits } => {
                let mut parts = parts.iter();
                let first = parts.next().ok_or(LirExecutorError::UnsupportedExpression(
                    "concat with zero parts",
                ))?;
                let mut value = self.eval_expression(state, first, expected_float)?;
                for part in parts {
                    let next = self.eval_expression(state, part, expected_float)?;
                    value.value = value.value.concat(&next.value);
                    value.deps.extend(next.deps);
                }
                Ok(EvaluatedValue {
                    value: state.backend().coerce_bv_width(&value.value, *bits)?,
                    deps: value.deps,
                })
            }
            LirExpression::Undefined { bits } => {
                let cell = state.fresh_value("undefined", *bits)?;
                Ok(EvaluatedValue {
                    value: cell.value,
                    deps: cell.def_id.into_iter().collect(),
                })
            }
            LirExpression::Poison { bits } => {
                let cell = state.fresh_value("poison", *bits)?;
                Ok(EvaluatedValue {
                    value: cell.value,
                    deps: cell.def_id.into_iter().collect(),
                })
            }
            LirExpression::Intrinsic { name, args, bits } => {
                let mut deps = BTreeSet::new();
                for arg in args {
                    deps.extend(self.eval_expression(state, arg, false)?.deps);
                }
                Ok(EvaluatedValue {
                    value: self.eval_intrinsic_expression(state, name, args, *bits)?,
                    deps,
                })
            }
        }
    }

    pub(crate) fn eval_condition(
        &self,
        state: &mut LirExecutorState,
        expression: &LirExpression,
    ) -> Result<EvaluatedCondition, LirExecutorError> {
        let value = self.eval_expression(state, expression, false)?;
        Ok(EvaluatedCondition {
            value: state.backend().bv_to_bool(&value.value),
            deps: value.deps,
        })
    }

    fn eval_unary(
        &self,
        state: &mut LirExecutorState,
        op: LirOperationUnary,
        arg: BV,
        arg_expression: &LirExpression,
        bits: u16,
        expected_float: bool,
    ) -> Result<BV, LirExecutorError> {
        match op {
            LirOperationUnary::Not => Ok(arg.bvnot()),
            LirOperationUnary::Neg => {
                if expected_float || self.expression_is_probably_float(arg_expression) {
                    self.eval_fp_neg(state, arg)
                } else {
                    Ok(arg.bvneg())
                }
            }
            LirOperationUnary::BitReverse => self.bit_reverse(state, &arg, bits),
            LirOperationUnary::ByteSwap => self.byte_swap(state, &arg, bits),
            LirOperationUnary::CountLeadingZeros => self.count_leading_zeros(state, &arg, bits),
            LirOperationUnary::CountTrailingZeros => self.count_trailing_zeros(state, &arg, bits),
            LirOperationUnary::PopCount => self.popcount(state, &arg, bits),
            LirOperationUnary::Abs => {
                if expected_float || self.expression_is_probably_float(arg_expression) {
                    self.eval_fp_abs(state, arg)
                } else {
                    let zero = state.backend().zero_bv(bits)?;
                    let negative = arg.bvslt(&zero);
                    Ok(negative.ite(&arg.bvneg(), &arg))
                }
            }
            LirOperationUnary::Sqrt => self.eval_fp_sqrt(state, arg),
        }
    }

    fn eval_binary(
        &self,
        state: &LirExecutorState,
        op: LirOperationBinary,
        left: BV,
        right: BV,
    ) -> Result<BV, LirExecutorError> {
        match op {
            LirOperationBinary::Add => Ok(left.bvadd(&right)),
            LirOperationBinary::AddWithCarry => Ok(left.bvadd(&right)),
            LirOperationBinary::Sub => Ok(left.bvsub(&right)),
            LirOperationBinary::SubWithBorrow => Ok(left.bvsub(&right)),
            LirOperationBinary::Mul => Ok(left.bvmul(&right)),
            LirOperationBinary::FAdd
            | LirOperationBinary::FSub
            | LirOperationBinary::FMul
            | LirOperationBinary::FDiv => self.eval_fp_binary(state, op, left, right),
            LirOperationBinary::UMulHigh => self.unsigned_mul_high(&left, &right),
            LirOperationBinary::SMulHigh => self.signed_mul_high(&left, &right),
            LirOperationBinary::UDiv => Ok(left.bvudiv(&right)),
            LirOperationBinary::SDiv => Ok(left.bvsdiv(&right)),
            LirOperationBinary::URem => Ok(left.bvurem(&right)),
            LirOperationBinary::SRem => Ok(left.bvsrem(&right)),
            LirOperationBinary::And => Ok(left.bvand(&right)),
            LirOperationBinary::Or => Ok(left.bvor(&right)),
            LirOperationBinary::Xor => Ok(left.bvxor(&right)),
            LirOperationBinary::Shl => Ok(left.bvshl(&right)),
            LirOperationBinary::LShr => Ok(left.bvlshr(&right)),
            LirOperationBinary::AShr => Ok(left.bvashr(&right)),
            LirOperationBinary::RotateLeft => Ok(left.bvrotl(&right)),
            LirOperationBinary::RotateRight => Ok(left.bvrotr(&right)),
            LirOperationBinary::MinUnsigned => Ok(left.bvule(&right).ite(&left, &right)),
            LirOperationBinary::MinSigned => Ok(left.bvsle(&right).ite(&left, &right)),
            LirOperationBinary::MaxUnsigned => Ok(left.bvuge(&right).ite(&left, &right)),
            LirOperationBinary::MaxSigned => Ok(left.bvsge(&right).ite(&left, &right)),
        }
    }

    fn eval_cast(
        &self,
        state: &mut LirExecutorState,
        op: LirOperationCast,
        arg: BV,
        bits: u16,
    ) -> Result<BV, LirExecutorError> {
        let current = arg.get_size() as u16;
        match op {
            LirOperationCast::ZeroExtend => {
                if current >= bits {
                    state.backend().coerce_bv_width(&arg, bits)
                } else {
                    Ok(arg.zero_ext((bits - current) as u32))
                }
            }
            LirOperationCast::SignExtend => {
                if current >= bits {
                    state.backend().coerce_bv_width(&arg, bits)
                } else {
                    Ok(arg.sign_ext((bits - current) as u32))
                }
            }
            LirOperationCast::Truncate | LirOperationCast::Bitcast => {
                state.backend().coerce_bv_width(&arg, bits)
            }
            LirOperationCast::IntToFloat => {
                let value = state.backend().signed_bv_to_float(&arg, bits)?;
                Ok(state.backend().float_to_ieee_bv(&value))
            }
            LirOperationCast::UIntToFloat => {
                let value = state.backend().unsigned_bv_to_float(&arg, bits)?;
                Ok(state.backend().float_to_ieee_bv(&value))
            }
            LirOperationCast::FloatToInt => {
                let value = state.backend().float_from_ieee_bv(&arg)?;
                Ok(state.backend().float_to_signed_bv(&value, bits))
            }
            LirOperationCast::FloatToUInt => {
                let value = state.backend().float_from_ieee_bv(&arg)?;
                Ok(state.backend().float_to_unsigned_bv(&value, bits))
            }
            LirOperationCast::FloatExtend | LirOperationCast::FloatTruncate => {
                let value = state.backend().float_from_ieee_bv(&arg)?;
                let value = state.backend().float_cast(&value, bits)?;
                Ok(state.backend().float_to_ieee_bv(&value))
            }
        }
    }

    fn eval_compare(
        &self,
        state: &LirExecutorState,
        op: LirOperationCompare,
        left: BV,
        right: BV,
    ) -> Result<Bool, LirExecutorError> {
        match op {
            LirOperationCompare::Eq => Ok(left.eq(&right)),
            LirOperationCompare::Ne => Ok(left.eq(&right).not()),
            LirOperationCompare::Ult => Ok(left.bvult(&right)),
            LirOperationCompare::Ule => Ok(left.bvule(&right)),
            LirOperationCompare::Ugt => Ok(left.bvugt(&right)),
            LirOperationCompare::Uge => Ok(left.bvuge(&right)),
            LirOperationCompare::Slt => Ok(left.bvslt(&right)),
            LirOperationCompare::Sle => Ok(left.bvsle(&right)),
            LirOperationCompare::Sgt => Ok(left.bvsgt(&right)),
            LirOperationCompare::Sge => Ok(left.bvsge(&right)),
            LirOperationCompare::Ueq
            | LirOperationCompare::Une
            | LirOperationCompare::Ordered
            | LirOperationCompare::Unordered
            | LirOperationCompare::Oeq
            | LirOperationCompare::One
            | LirOperationCompare::Olt
            | LirOperationCompare::Ole
            | LirOperationCompare::Ogt
            | LirOperationCompare::Oge
            | LirOperationCompare::UltFp
            | LirOperationCompare::UleFp
            | LirOperationCompare::UgtFp
            | LirOperationCompare::UgeFp => self.eval_fp_compare(state, op, left, right),
        }
    }

    pub(crate) fn coerce_address(
        &self,
        state: &mut LirExecutorState,
        value: &BV,
    ) -> Result<BV, LirExecutorError> {
        state.backend().coerce_bv_width(value, state.address_bits())
    }

    fn unsigned_mul_high(&self, left: &BV, right: &BV) -> Result<BV, LirExecutorError> {
        let bits = left.get_size() as u16;
        let extended_bits = bits * 2;
        let lhs = left.zero_ext(bits as u32);
        let rhs = right.zero_ext(bits as u32);
        let product = lhs.bvmul(&rhs);
        Ok(product.extract((extended_bits - 1) as u32, bits as u32))
    }

    fn signed_mul_high(&self, left: &BV, right: &BV) -> Result<BV, LirExecutorError> {
        let bits = left.get_size() as u16;
        let extended_bits = bits * 2;
        let lhs = left.sign_ext(bits as u32);
        let rhs = right.sign_ext(bits as u32);
        let product = lhs.bvmul(&rhs);
        Ok(product.extract((extended_bits - 1) as u32, bits as u32))
    }

    fn byte_swap(
        &self,
        state: &mut LirExecutorState,
        arg: &BV,
        bits: u16,
    ) -> Result<BV, LirExecutorError> {
        if !bits.is_multiple_of(8) {
            return Err(LirExecutorError::UnsupportedExpression(
                "byte swap requires a byte-aligned width",
            ));
        }
        let mut bytes = (0..(bits / 8))
            .map(|index| {
                let low = (index * 8) as u32;
                arg.extract(low + 7, low)
            })
            .collect::<Vec<_>>();
        bytes.reverse();
        self.concat_parts(state, &bytes)
    }

    fn bit_reverse(
        &self,
        state: &mut LirExecutorState,
        arg: &BV,
        bits: u16,
    ) -> Result<BV, LirExecutorError> {
        let parts = (0..bits)
            .map(|index| arg.extract(index as u32, index as u32))
            .collect::<Vec<_>>();
        self.concat_parts(state, &parts)
    }

    fn popcount(
        &self,
        state: &mut LirExecutorState,
        arg: &BV,
        bits: u16,
    ) -> Result<BV, LirExecutorError> {
        let mut total = state.backend().zero_bv(bits)?;
        for index in 0..bits {
            let bit = arg.extract(index as u32, index as u32);
            let extended = bit.zero_ext((bits - 1) as u32);
            total = total.bvadd(&extended);
        }
        Ok(total)
    }

    fn count_leading_zeros(
        &self,
        state: &mut LirExecutorState,
        arg: &BV,
        bits: u16,
    ) -> Result<BV, LirExecutorError> {
        let mut total = state.backend().zero_bv(bits)?;
        let one = state.backend().one_bv(bits)?;
        let mut still_zero = Bool::from_bool(true);
        for index in (0..bits).rev() {
            let bit_is_zero = arg.extract(index as u32, index as u32).eq(0);
            let increment = Bool::and(&[still_zero.clone(), bit_is_zero.clone()]);
            total = increment.ite(&total.bvadd(&one), &total);
            still_zero = Bool::and(&[still_zero, bit_is_zero]);
        }
        Ok(total)
    }

    fn count_trailing_zeros(
        &self,
        state: &mut LirExecutorState,
        arg: &BV,
        bits: u16,
    ) -> Result<BV, LirExecutorError> {
        let mut total = state.backend().zero_bv(bits)?;
        let one = state.backend().one_bv(bits)?;
        let mut still_zero = Bool::from_bool(true);
        for index in 0..bits {
            let bit_is_zero = arg.extract(index as u32, index as u32).eq(0);
            let increment = Bool::and(&[still_zero.clone(), bit_is_zero.clone()]);
            total = increment.ite(&total.bvadd(&one), &total);
            still_zero = Bool::and(&[still_zero, bit_is_zero]);
        }
        Ok(total)
    }

    fn concat_parts(
        &self,
        state: &mut LirExecutorState,
        parts: &[BV],
    ) -> Result<BV, LirExecutorError> {
        let mut parts = parts.iter();
        let first = parts
            .next()
            .cloned()
            .ok_or(LirExecutorError::UnsupportedExpression(
                "concat with zero parts",
            ))?;
        let mut value = first;
        for part in parts {
            value = value.concat(part);
        }
        state
            .backend()
            .coerce_bv_width(&value, value.get_size() as u16)
    }

    pub(crate) fn eval_fp_abs(
        &self,
        state: &LirExecutorState,
        value: BV,
    ) -> Result<BV, LirExecutorError> {
        let value = state.backend().float_from_ieee_bv(&value)?;
        Ok(state.backend().float_to_ieee_bv(&value.unary_abs()))
    }

    pub(crate) fn eval_fp_neg(
        &self,
        state: &LirExecutorState,
        value: BV,
    ) -> Result<BV, LirExecutorError> {
        let value = state.backend().float_from_ieee_bv(&value)?;
        Ok(state.backend().float_to_ieee_bv(&value.unary_neg()))
    }

    pub(crate) fn eval_fp_sqrt(
        &self,
        state: &LirExecutorState,
        value: BV,
    ) -> Result<BV, LirExecutorError> {
        let value = state.backend().float_from_ieee_bv(&value)?;
        Ok(state.backend().float_to_ieee_bv(&value.sqrt()))
    }

    fn expression_is_probably_float(&self, expression: &LirExpression) -> bool {
        match expression {
            LirExpression::Const { bits, .. } => matches!(*bits, 32 | 64),
            LirExpression::Function { .. } => false,
            LirExpression::DataAddress { .. } => false,
            LirExpression::AddressOf { .. } => false,
            LirExpression::Read(location) => self.location_is_probably_float(location),
            LirExpression::Load { bits, .. } => matches!(*bits, 32 | 64),
            LirExpression::Unary { op, arg, .. } => match op {
                LirOperationUnary::Sqrt | LirOperationUnary::Abs => true,
                LirOperationUnary::Neg => self.expression_is_probably_float(arg),
                _ => false,
            },
            LirExpression::Binary { op, .. } => matches!(
                op,
                LirOperationBinary::FAdd
                    | LirOperationBinary::FSub
                    | LirOperationBinary::FMul
                    | LirOperationBinary::FDiv
            ),
            LirExpression::Cast { op, .. } => matches!(
                op,
                LirOperationCast::IntToFloat
                    | LirOperationCast::UIntToFloat
                    | LirOperationCast::FloatExtend
                    | LirOperationCast::FloatTruncate
            ),
            LirExpression::Compare { op, .. } => matches!(
                op,
                LirOperationCompare::Ordered
                    | LirOperationCompare::Unordered
                    | LirOperationCompare::Oeq
                    | LirOperationCompare::One
                    | LirOperationCompare::Olt
                    | LirOperationCompare::Ole
                    | LirOperationCompare::Ogt
                    | LirOperationCompare::Oge
                    | LirOperationCompare::Ueq
                    | LirOperationCompare::Une
                    | LirOperationCompare::UltFp
                    | LirOperationCompare::UleFp
                    | LirOperationCompare::UgtFp
                    | LirOperationCompare::UgeFp
            ),
            LirExpression::Select {
                when_true,
                when_false,
                ..
            } => {
                self.expression_is_probably_float(when_true)
                    || self.expression_is_probably_float(when_false)
            }
            LirExpression::Extract { arg, .. } => self.expression_is_probably_float(arg),
            LirExpression::Concat { parts, .. } => parts
                .iter()
                .any(|part| self.expression_is_probably_float(part)),
            LirExpression::Undefined { .. }
            | LirExpression::Poison { .. }
            | LirExpression::Intrinsic { .. }
            | LirExpression::Null { .. }
            | LirExpression::Allocate { .. }
            | LirExpression::ReadProperty { .. }
            | LirExpression::ReadElement { .. } => false,
        }
    }

    pub(crate) fn location_is_probably_float(&self, location: &LirLocation) -> bool {
        match location {
            LirLocation::Register { name, bits } => {
                if !matches!(*bits, 32 | 64 | 80 | 128 | 256 | 512) {
                    return false;
                }
                let lowered = name.to_ascii_lowercase();
                self.matches_arm64_fp_register(&lowered)
                    || lowered.starts_with("xmm")
                    || lowered.starts_with("ymm")
                    || lowered.starts_with("zmm")
                    || lowered.starts_with("x87_st")
                    || lowered.starts_with("st(")
            }
            LirLocation::Memory { .. }
            | LirLocation::IndexedMemory { .. }
            | LirLocation::StackMemory { .. } => false,
            _ => false,
        }
    }

    fn matches_arm64_fp_register(&self, name: &str) -> bool {
        self.matches_arm64_fp_prefix(name, 's')
            || self.matches_arm64_fp_prefix(name, 'd')
            || self.matches_arm64_fp_prefix(name, 'h')
            || self.matches_arm64_fp_prefix(name, 'q')
            || self.matches_arm64_fp_prefix(name, 'v')
    }

    fn matches_arm64_fp_prefix(&self, name: &str, prefix: char) -> bool {
        let mut chars = name.chars();
        if chars.next() != Some(prefix) {
            return false;
        }
        chars.all(|ch| ch.is_ascii_digit())
    }

    fn eval_fp_binary(
        &self,
        state: &LirExecutorState,
        op: LirOperationBinary,
        left: BV,
        right: BV,
    ) -> Result<BV, LirExecutorError> {
        let left = state.backend().float_from_ieee_bv(&left)?;
        let right = state.backend().float_from_ieee_bv(&right)?;
        let rounding = RoundingMode::round_nearest_ties_to_even();
        let value = match op {
            LirOperationBinary::FAdd => left.add_with_rounding_mode(&right, &rounding),
            LirOperationBinary::FSub => left.sub_with_rounding_mode(&right, &rounding),
            LirOperationBinary::FMul => left.mul_with_rounding_mode(&right, &rounding),
            LirOperationBinary::FDiv => left.div_with_rounding_mode(&right, &rounding),
            _ => return Err(LirExecutorError::UnsupportedExpression("binary op")),
        };
        Ok(state.backend().float_to_ieee_bv(&value))
    }

    fn eval_fp_compare(
        &self,
        state: &LirExecutorState,
        op: LirOperationCompare,
        left: BV,
        right: BV,
    ) -> Result<Bool, LirExecutorError> {
        let left = state.backend().float_from_ieee_bv(&left)?;
        let right = state.backend().float_from_ieee_bv(&right)?;
        let unordered = Bool::or(&[left.is_nan(), right.is_nan()]);
        let ordered = unordered.not();
        let eq = left.eq_fpa(&right);
        let lt = left.lt(&right);
        let le = left.le(&right);
        let gt = left.gt(&right);
        let ge = left.ge(&right);
        match op {
            LirOperationCompare::Ordered => Ok(ordered),
            LirOperationCompare::Unordered => Ok(unordered),
            LirOperationCompare::Oeq => Ok(Bool::and(&[ordered, eq])),
            LirOperationCompare::One => Ok(Bool::and(&[ordered, eq.not()])),
            LirOperationCompare::Olt => Ok(Bool::and(&[ordered, lt])),
            LirOperationCompare::Ole => Ok(Bool::and(&[ordered, le])),
            LirOperationCompare::Ogt => Ok(Bool::and(&[ordered, gt])),
            LirOperationCompare::Oge => Ok(Bool::and(&[ordered, ge])),
            LirOperationCompare::Ueq => Ok(Bool::or(&[unordered, eq])),
            LirOperationCompare::Une => Ok(Bool::or(&[unordered, eq.not()])),
            LirOperationCompare::UltFp => Ok(Bool::or(&[unordered, lt])),
            LirOperationCompare::UleFp => Ok(Bool::or(&[unordered, le])),
            LirOperationCompare::UgtFp => Ok(Bool::or(&[unordered, gt])),
            LirOperationCompare::UgeFp => Ok(Bool::or(&[unordered, ge])),
            _ => Err(LirExecutorError::UnsupportedExpression("compare op")),
        }
    }

    pub(crate) fn eval_intrinsic_expression(
        &self,
        state: &mut LirExecutorState,
        name: &str,
        args: &[LirExpression],
        bits: u16,
    ) -> Result<BV, LirExecutorError> {
        if let Some(value) = self.eval_x87_intrinsic_expression(state, name, args, bits)? {
            return Ok(value);
        }
        Err(LirExecutorError::UnsupportedExpression("intrinsic"))
    }
}
