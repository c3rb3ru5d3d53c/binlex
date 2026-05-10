use crate::semantics::{
    SemanticExpression, SemanticLocation, SemanticOperationBinary, SemanticOperationCast,
    SemanticOperationCompare, SemanticOperationUnary,
};
use crate::symbolic::{Error, SymbolicCpuState, SymbolicExecutor};
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

impl SymbolicExecutor {
    pub(crate) fn eval_expression(
        &self,
        state: &mut SymbolicCpuState,
        expression: &SemanticExpression,
        expected_float: bool,
    ) -> Result<EvaluatedValue, Error> {
        match expression {
            SemanticExpression::Const { value, bits } => Ok(EvaluatedValue {
                value: state.backend().const_bv(*value, *bits)?,
                deps: BTreeSet::new(),
            }),
            SemanticExpression::Function { bits, .. } => Ok(EvaluatedValue {
                value: state.backend().const_bv(0, *bits)?,
                deps: BTreeSet::new(),
            }),
            SemanticExpression::AddressOf { bits, .. } => Ok(EvaluatedValue {
                value: state.backend().const_bv(0, *bits)?,
                deps: BTreeSet::new(),
            }),
            SemanticExpression::Read(location) => self.read_location(state, location),
            SemanticExpression::Load { addr, bits, .. } => {
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
            SemanticExpression::Null { bits } => Ok(EvaluatedValue {
                value: state.backend().const_bv(0, *bits)?,
                deps: BTreeSet::new(),
            }),
            SemanticExpression::Allocate { kind, bits } => {
                let cell = state.allocate_reference(kind, *bits)?;
                Ok(EvaluatedValue {
                    value: cell.value,
                    deps: cell.def_id.into_iter().collect(),
                })
            }
            SemanticExpression::ReadProperty {
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
            SemanticExpression::ReadElement {
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
            SemanticExpression::Unary { op, arg, bits } => {
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
            SemanticExpression::Binary {
                op,
                left,
                right,
                bits,
            } => {
                let binary_is_float = matches!(
                    op,
                    SemanticOperationBinary::FAdd
                        | SemanticOperationBinary::FSub
                        | SemanticOperationBinary::FMul
                        | SemanticOperationBinary::FDiv
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
            SemanticExpression::Cast { op, arg, bits } => {
                let cast_arg_is_float = matches!(
                    op,
                    SemanticOperationCast::FloatToInt
                        | SemanticOperationCast::FloatToUInt
                        | SemanticOperationCast::FloatExtend
                        | SemanticOperationCast::FloatTruncate
                );
                let arg = self.eval_expression(state, arg, cast_arg_is_float)?;
                Ok(EvaluatedValue {
                    value: self.eval_cast(state, *op, arg.value, *bits)?,
                    deps: arg.deps,
                })
            }
            SemanticExpression::Compare {
                op,
                left,
                right,
                bits,
            } => {
                let compare_is_float = matches!(
                    op,
                    SemanticOperationCompare::Ordered
                        | SemanticOperationCompare::Unordered
                        | SemanticOperationCompare::Oeq
                        | SemanticOperationCompare::One
                        | SemanticOperationCompare::Olt
                        | SemanticOperationCompare::Ole
                        | SemanticOperationCompare::Ogt
                        | SemanticOperationCompare::Oge
                        | SemanticOperationCompare::Ueq
                        | SemanticOperationCompare::Une
                        | SemanticOperationCompare::UltFp
                        | SemanticOperationCompare::UleFp
                        | SemanticOperationCompare::UgtFp
                        | SemanticOperationCompare::UgeFp
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
            SemanticExpression::Select {
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
            SemanticExpression::Extract { arg, lsb, bits } => {
                let arg = self.eval_expression(state, arg, expected_float)?;
                Ok(EvaluatedValue {
                    value: arg.value.extract((*lsb + *bits - 1) as u32, *lsb as u32),
                    deps: arg.deps,
                })
            }
            SemanticExpression::Concat { parts, bits } => {
                let mut parts = parts.iter();
                let first = parts
                    .next()
                    .ok_or(Error::UnsupportedExpression("concat with zero parts"))?;
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
            SemanticExpression::Undefined { bits } => {
                let cell = state.fresh_value("undefined", *bits)?;
                Ok(EvaluatedValue {
                    value: cell.value,
                    deps: cell.def_id.into_iter().collect(),
                })
            }
            SemanticExpression::Poison { bits } => {
                let cell = state.fresh_value("poison", *bits)?;
                Ok(EvaluatedValue {
                    value: cell.value,
                    deps: cell.def_id.into_iter().collect(),
                })
            }
            SemanticExpression::Intrinsic { name, args, bits } => {
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
        state: &mut SymbolicCpuState,
        expression: &SemanticExpression,
    ) -> Result<EvaluatedCondition, Error> {
        let value = self.eval_expression(state, expression, false)?;
        Ok(EvaluatedCondition {
            value: state.backend().bv_to_bool(&value.value),
            deps: value.deps,
        })
    }

    fn eval_unary(
        &self,
        state: &mut SymbolicCpuState,
        op: SemanticOperationUnary,
        arg: BV,
        arg_expression: &SemanticExpression,
        bits: u16,
        expected_float: bool,
    ) -> Result<BV, Error> {
        match op {
            SemanticOperationUnary::Not => Ok(arg.bvnot()),
            SemanticOperationUnary::Neg => {
                if expected_float || self.expression_is_probably_float(arg_expression) {
                    self.eval_fp_neg(state, arg)
                } else {
                    Ok(arg.bvneg())
                }
            }
            SemanticOperationUnary::BitReverse => self.bit_reverse(state, &arg, bits),
            SemanticOperationUnary::ByteSwap => self.byte_swap(state, &arg, bits),
            SemanticOperationUnary::CountLeadingZeros => {
                self.count_leading_zeros(state, &arg, bits)
            }
            SemanticOperationUnary::CountTrailingZeros => {
                self.count_trailing_zeros(state, &arg, bits)
            }
            SemanticOperationUnary::PopCount => self.popcount(state, &arg, bits),
            SemanticOperationUnary::Abs => {
                if expected_float || self.expression_is_probably_float(arg_expression) {
                    self.eval_fp_abs(state, arg)
                } else {
                    let zero = state.backend().zero_bv(bits)?;
                    let negative = arg.bvslt(&zero);
                    Ok(negative.ite(&arg.bvneg(), &arg))
                }
            }
            SemanticOperationUnary::Sqrt => self.eval_fp_sqrt(state, arg),
        }
    }

    fn eval_binary(
        &self,
        state: &SymbolicCpuState,
        op: SemanticOperationBinary,
        left: BV,
        right: BV,
    ) -> Result<BV, Error> {
        match op {
            SemanticOperationBinary::Add => Ok(left.bvadd(&right)),
            SemanticOperationBinary::AddWithCarry => Ok(left.bvadd(&right)),
            SemanticOperationBinary::Sub => Ok(left.bvsub(&right)),
            SemanticOperationBinary::SubWithBorrow => Ok(left.bvsub(&right)),
            SemanticOperationBinary::Mul => Ok(left.bvmul(&right)),
            SemanticOperationBinary::FAdd
            | SemanticOperationBinary::FSub
            | SemanticOperationBinary::FMul
            | SemanticOperationBinary::FDiv => self.eval_fp_binary(state, op, left, right),
            SemanticOperationBinary::UMulHigh => self.unsigned_mul_high(&left, &right),
            SemanticOperationBinary::SMulHigh => self.signed_mul_high(&left, &right),
            SemanticOperationBinary::UDiv => Ok(left.bvudiv(&right)),
            SemanticOperationBinary::SDiv => Ok(left.bvsdiv(&right)),
            SemanticOperationBinary::URem => Ok(left.bvurem(&right)),
            SemanticOperationBinary::SRem => Ok(left.bvsrem(&right)),
            SemanticOperationBinary::And => Ok(left.bvand(&right)),
            SemanticOperationBinary::Or => Ok(left.bvor(&right)),
            SemanticOperationBinary::Xor => Ok(left.bvxor(&right)),
            SemanticOperationBinary::Shl => Ok(left.bvshl(&right)),
            SemanticOperationBinary::LShr => Ok(left.bvlshr(&right)),
            SemanticOperationBinary::AShr => Ok(left.bvashr(&right)),
            SemanticOperationBinary::RotateLeft => Ok(left.bvrotl(&right)),
            SemanticOperationBinary::RotateRight => Ok(left.bvrotr(&right)),
            SemanticOperationBinary::MinUnsigned => Ok(left.bvule(&right).ite(&left, &right)),
            SemanticOperationBinary::MinSigned => Ok(left.bvsle(&right).ite(&left, &right)),
            SemanticOperationBinary::MaxUnsigned => Ok(left.bvuge(&right).ite(&left, &right)),
            SemanticOperationBinary::MaxSigned => Ok(left.bvsge(&right).ite(&left, &right)),
        }
    }

    fn eval_cast(
        &self,
        state: &mut SymbolicCpuState,
        op: SemanticOperationCast,
        arg: BV,
        bits: u16,
    ) -> Result<BV, Error> {
        let current = arg.get_size() as u16;
        match op {
            SemanticOperationCast::ZeroExtend => {
                if current >= bits {
                    state.backend().coerce_bv_width(&arg, bits)
                } else {
                    Ok(arg.zero_ext((bits - current) as u32))
                }
            }
            SemanticOperationCast::SignExtend => {
                if current >= bits {
                    state.backend().coerce_bv_width(&arg, bits)
                } else {
                    Ok(arg.sign_ext((bits - current) as u32))
                }
            }
            SemanticOperationCast::Truncate | SemanticOperationCast::Bitcast => {
                state.backend().coerce_bv_width(&arg, bits)
            }
            SemanticOperationCast::IntToFloat => {
                let value = state.backend().signed_bv_to_float(&arg, bits)?;
                Ok(state.backend().float_to_ieee_bv(&value))
            }
            SemanticOperationCast::UIntToFloat => {
                let value = state.backend().unsigned_bv_to_float(&arg, bits)?;
                Ok(state.backend().float_to_ieee_bv(&value))
            }
            SemanticOperationCast::FloatToInt => {
                let value = state.backend().float_from_ieee_bv(&arg)?;
                Ok(state.backend().float_to_signed_bv(&value, bits))
            }
            SemanticOperationCast::FloatToUInt => {
                let value = state.backend().float_from_ieee_bv(&arg)?;
                Ok(state.backend().float_to_unsigned_bv(&value, bits))
            }
            SemanticOperationCast::FloatExtend | SemanticOperationCast::FloatTruncate => {
                let value = state.backend().float_from_ieee_bv(&arg)?;
                let value = state.backend().float_cast(&value, bits)?;
                Ok(state.backend().float_to_ieee_bv(&value))
            }
        }
    }

    fn eval_compare(
        &self,
        state: &SymbolicCpuState,
        op: SemanticOperationCompare,
        left: BV,
        right: BV,
    ) -> Result<Bool, Error> {
        match op {
            SemanticOperationCompare::Eq => Ok(left.eq(&right)),
            SemanticOperationCompare::Ne => Ok(left.eq(&right).not()),
            SemanticOperationCompare::Ult => Ok(left.bvult(&right)),
            SemanticOperationCompare::Ule => Ok(left.bvule(&right)),
            SemanticOperationCompare::Ugt => Ok(left.bvugt(&right)),
            SemanticOperationCompare::Uge => Ok(left.bvuge(&right)),
            SemanticOperationCompare::Slt => Ok(left.bvslt(&right)),
            SemanticOperationCompare::Sle => Ok(left.bvsle(&right)),
            SemanticOperationCompare::Sgt => Ok(left.bvsgt(&right)),
            SemanticOperationCompare::Sge => Ok(left.bvsge(&right)),
            SemanticOperationCompare::Ueq
            | SemanticOperationCompare::Une
            | SemanticOperationCompare::Ordered
            | SemanticOperationCompare::Unordered
            | SemanticOperationCompare::Oeq
            | SemanticOperationCompare::One
            | SemanticOperationCompare::Olt
            | SemanticOperationCompare::Ole
            | SemanticOperationCompare::Ogt
            | SemanticOperationCompare::Oge
            | SemanticOperationCompare::UltFp
            | SemanticOperationCompare::UleFp
            | SemanticOperationCompare::UgtFp
            | SemanticOperationCompare::UgeFp => self.eval_fp_compare(state, op, left, right),
        }
    }

    pub(crate) fn coerce_address(
        &self,
        state: &mut SymbolicCpuState,
        value: &BV,
    ) -> Result<BV, Error> {
        state.backend().coerce_bv_width(value, state.address_bits())
    }

    fn unsigned_mul_high(&self, left: &BV, right: &BV) -> Result<BV, Error> {
        let bits = left.get_size() as u16;
        let extended_bits = bits * 2;
        let lhs = left.zero_ext(bits as u32);
        let rhs = right.zero_ext(bits as u32);
        let product = lhs.bvmul(&rhs);
        Ok(product.extract((extended_bits - 1) as u32, bits as u32))
    }

    fn signed_mul_high(&self, left: &BV, right: &BV) -> Result<BV, Error> {
        let bits = left.get_size() as u16;
        let extended_bits = bits * 2;
        let lhs = left.sign_ext(bits as u32);
        let rhs = right.sign_ext(bits as u32);
        let product = lhs.bvmul(&rhs);
        Ok(product.extract((extended_bits - 1) as u32, bits as u32))
    }

    fn byte_swap(&self, state: &mut SymbolicCpuState, arg: &BV, bits: u16) -> Result<BV, Error> {
        if !bits.is_multiple_of(8) {
            return Err(Error::UnsupportedExpression(
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

    fn bit_reverse(&self, state: &mut SymbolicCpuState, arg: &BV, bits: u16) -> Result<BV, Error> {
        let parts = (0..bits)
            .map(|index| arg.extract(index as u32, index as u32))
            .collect::<Vec<_>>();
        self.concat_parts(state, &parts)
    }

    fn popcount(&self, state: &mut SymbolicCpuState, arg: &BV, bits: u16) -> Result<BV, Error> {
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
        state: &mut SymbolicCpuState,
        arg: &BV,
        bits: u16,
    ) -> Result<BV, Error> {
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
        state: &mut SymbolicCpuState,
        arg: &BV,
        bits: u16,
    ) -> Result<BV, Error> {
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

    fn concat_parts(&self, state: &mut SymbolicCpuState, parts: &[BV]) -> Result<BV, Error> {
        let mut parts = parts.iter();
        let first = parts
            .next()
            .cloned()
            .ok_or(Error::UnsupportedExpression("concat with zero parts"))?;
        let mut value = first;
        for part in parts {
            value = value.concat(part);
        }
        state
            .backend()
            .coerce_bv_width(&value, value.get_size() as u16)
    }

    pub(crate) fn eval_fp_abs(&self, state: &SymbolicCpuState, value: BV) -> Result<BV, Error> {
        let value = state.backend().float_from_ieee_bv(&value)?;
        Ok(state.backend().float_to_ieee_bv(&value.unary_abs()))
    }

    pub(crate) fn eval_fp_neg(&self, state: &SymbolicCpuState, value: BV) -> Result<BV, Error> {
        let value = state.backend().float_from_ieee_bv(&value)?;
        Ok(state.backend().float_to_ieee_bv(&value.unary_neg()))
    }

    pub(crate) fn eval_fp_sqrt(&self, state: &SymbolicCpuState, value: BV) -> Result<BV, Error> {
        let value = state.backend().float_from_ieee_bv(&value)?;
        Ok(state.backend().float_to_ieee_bv(&value.sqrt()))
    }

    fn expression_is_probably_float(&self, expression: &SemanticExpression) -> bool {
        match expression {
            SemanticExpression::Const { bits, .. } => matches!(*bits, 32 | 64),
            SemanticExpression::Function { .. } => false,
            SemanticExpression::AddressOf { .. } => false,
            SemanticExpression::Read(location) => self.location_is_probably_float(location),
            SemanticExpression::Load { bits, .. } => matches!(*bits, 32 | 64),
            SemanticExpression::Unary { op, arg, .. } => match op {
                SemanticOperationUnary::Sqrt | SemanticOperationUnary::Abs => true,
                SemanticOperationUnary::Neg => self.expression_is_probably_float(arg),
                _ => false,
            },
            SemanticExpression::Binary { op, .. } => matches!(
                op,
                SemanticOperationBinary::FAdd
                    | SemanticOperationBinary::FSub
                    | SemanticOperationBinary::FMul
                    | SemanticOperationBinary::FDiv
            ),
            SemanticExpression::Cast { op, .. } => matches!(
                op,
                SemanticOperationCast::IntToFloat
                    | SemanticOperationCast::UIntToFloat
                    | SemanticOperationCast::FloatExtend
                    | SemanticOperationCast::FloatTruncate
            ),
            SemanticExpression::Compare { op, .. } => matches!(
                op,
                SemanticOperationCompare::Ordered
                    | SemanticOperationCompare::Unordered
                    | SemanticOperationCompare::Oeq
                    | SemanticOperationCompare::One
                    | SemanticOperationCompare::Olt
                    | SemanticOperationCompare::Ole
                    | SemanticOperationCompare::Ogt
                    | SemanticOperationCompare::Oge
                    | SemanticOperationCompare::Ueq
                    | SemanticOperationCompare::Une
                    | SemanticOperationCompare::UltFp
                    | SemanticOperationCompare::UleFp
                    | SemanticOperationCompare::UgtFp
                    | SemanticOperationCompare::UgeFp
            ),
            SemanticExpression::Select {
                when_true,
                when_false,
                ..
            } => {
                self.expression_is_probably_float(when_true)
                    || self.expression_is_probably_float(when_false)
            }
            SemanticExpression::Extract { arg, .. } => self.expression_is_probably_float(arg),
            SemanticExpression::Concat { parts, .. } => parts
                .iter()
                .any(|part| self.expression_is_probably_float(part)),
            SemanticExpression::Undefined { .. }
            | SemanticExpression::Poison { .. }
            | SemanticExpression::Intrinsic { .. }
            | SemanticExpression::Null { .. }
            | SemanticExpression::Allocate { .. }
            | SemanticExpression::ReadProperty { .. }
            | SemanticExpression::ReadElement { .. } => false,
        }
    }

    pub(crate) fn location_is_probably_float(&self, location: &SemanticLocation) -> bool {
        match location {
            SemanticLocation::Register { name, bits } => {
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
            SemanticLocation::Memory { .. }
            | SemanticLocation::IndexedMemory { .. }
            | SemanticLocation::StackMemory { .. } => false,
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
        state: &SymbolicCpuState,
        op: SemanticOperationBinary,
        left: BV,
        right: BV,
    ) -> Result<BV, Error> {
        let left = state.backend().float_from_ieee_bv(&left)?;
        let right = state.backend().float_from_ieee_bv(&right)?;
        let rounding = RoundingMode::round_nearest_ties_to_even();
        let value = match op {
            SemanticOperationBinary::FAdd => left.add_with_rounding_mode(&right, &rounding),
            SemanticOperationBinary::FSub => left.sub_with_rounding_mode(&right, &rounding),
            SemanticOperationBinary::FMul => left.mul_with_rounding_mode(&right, &rounding),
            SemanticOperationBinary::FDiv => left.div_with_rounding_mode(&right, &rounding),
            _ => return Err(Error::UnsupportedExpression("binary op")),
        };
        Ok(state.backend().float_to_ieee_bv(&value))
    }

    fn eval_fp_compare(
        &self,
        state: &SymbolicCpuState,
        op: SemanticOperationCompare,
        left: BV,
        right: BV,
    ) -> Result<Bool, Error> {
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
            SemanticOperationCompare::Ordered => Ok(ordered),
            SemanticOperationCompare::Unordered => Ok(unordered),
            SemanticOperationCompare::Oeq => Ok(Bool::and(&[ordered, eq])),
            SemanticOperationCompare::One => Ok(Bool::and(&[ordered, eq.not()])),
            SemanticOperationCompare::Olt => Ok(Bool::and(&[ordered, lt])),
            SemanticOperationCompare::Ole => Ok(Bool::and(&[ordered, le])),
            SemanticOperationCompare::Ogt => Ok(Bool::and(&[ordered, gt])),
            SemanticOperationCompare::Oge => Ok(Bool::and(&[ordered, ge])),
            SemanticOperationCompare::Ueq => Ok(Bool::or(&[unordered, eq])),
            SemanticOperationCompare::Une => Ok(Bool::or(&[unordered, eq.not()])),
            SemanticOperationCompare::UltFp => Ok(Bool::or(&[unordered, lt])),
            SemanticOperationCompare::UleFp => Ok(Bool::or(&[unordered, le])),
            SemanticOperationCompare::UgtFp => Ok(Bool::or(&[unordered, gt])),
            SemanticOperationCompare::UgeFp => Ok(Bool::or(&[unordered, ge])),
            _ => Err(Error::UnsupportedExpression("compare op")),
        }
    }

    pub(crate) fn eval_intrinsic_expression(
        &self,
        state: &mut SymbolicCpuState,
        name: &str,
        args: &[SemanticExpression],
        bits: u16,
    ) -> Result<BV, Error> {
        if let Some(value) = self.eval_x87_intrinsic_expression(state, name, args, bits)? {
            return Ok(value);
        }
        Err(Error::UnsupportedExpression("intrinsic"))
    }
}
