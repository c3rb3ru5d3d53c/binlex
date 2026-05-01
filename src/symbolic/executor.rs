use crate::semantics::{
    InstructionSemantics, SemanticExpression, SemanticLocation, SemanticOperationBinary,
    SemanticOperationCast, SemanticOperationCompare, SemanticOperationUnary, SemanticStatus,
    SemanticTerminator,
};
use crate::symbolic::Error;
use crate::symbolic::State;
use crate::{Architecture, semantics::SemanticEffect};
use z3::ast::{Ast, BV, Bool};
use z3::ast::RoundingMode;

#[derive(Clone)]
pub struct Executor {
    architecture: Architecture,
    address_bits: u16,
}

impl Executor {
    pub fn new(architecture: Architecture) -> Result<Self, Error> {
        let address_bits = match architecture {
            Architecture::AMD64 | Architecture::ARM64 | Architecture::CIL => 64,
            Architecture::I386 => 32,
            Architecture::UNKNOWN => {
                return Err(Error::UnsupportedArchitecture("unknown".to_string()));
            }
        };
        Ok(Self {
            architecture,
            address_bits,
        })
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn state(&self) -> State {
        State::new(self.architecture, self.address_bits)
    }

    pub fn step(
        &self,
        semantics: &InstructionSemantics,
        state: &State,
    ) -> Result<Vec<State>, Error> {
        if !matches!(semantics.status, SemanticStatus::Complete) {
            return Err(Error::UnsupportedExpression(
                "partial instruction semantics are not executable",
            ));
        }
        let mut working = state.clone();
        for effect in &semantics.effects {
            self.apply_effect(&mut working, effect)?;
        }
        self.apply_terminator(working, &semantics.terminator)
    }

    pub fn run<'a, I>(&self, semantics: I, state: &State) -> Result<Vec<State>, Error>
    where
        I: IntoIterator<Item = &'a InstructionSemantics>,
    {
        let mut live_states = vec![state.clone()];
        for instruction in semantics {
            let mut next_states = Vec::new();
            for live in &live_states {
                next_states.extend(self.step(instruction, live)?);
            }
            live_states = next_states;
            if live_states.is_empty() {
                break;
            }
        }
        Ok(live_states)
    }

    fn apply_effect(&self, state: &mut State, effect: &SemanticEffect) -> Result<(), Error> {
        match effect {
            SemanticEffect::Set { dst, expression } => {
                let value = self.eval_expression(state, expression, self.location_is_probably_float(dst))?;
                self.write_location(state, dst, value)
            }
            SemanticEffect::Store {
                addr,
                expression,
                bits,
                ..
            } => {
                let raw_address = self.eval_expression(state, addr, false)?;
                let address = self.coerce_address(state, &raw_address)?;
                let value = self.eval_expression(state, expression, false)?;
                let backend = state.backend().clone();
                state.memory_mut().store(&backend, &address, &value, *bits)
            }
            SemanticEffect::MemorySet {
                addr,
                value,
                count,
                element_bits,
                decrement,
                ..
            } => self.apply_memory_set(state, addr, value, count, *element_bits, decrement),
            SemanticEffect::MemoryCopy {
                src_addr,
                dst_addr,
                count,
                element_bits,
                decrement,
                ..
            } => self.apply_memory_copy(state, src_addr, dst_addr, count, *element_bits, decrement),
            SemanticEffect::AtomicCmpXchg {
                addr,
                expected,
                desired,
                bits,
                observed,
                ..
            } => self.apply_atomic_cmpxchg(state, addr, expected, desired, *bits, observed),
            SemanticEffect::Nop => Ok(()),
            SemanticEffect::Fence { .. } => Err(Error::UnsupportedEffect("fence")),
            SemanticEffect::Trap { .. } => Err(Error::UnsupportedEffect("trap")),
            SemanticEffect::Intrinsic { name, args, outputs } => {
                self.apply_intrinsic_effect(state, name, args, outputs)
            }
        }
    }

    fn apply_terminator(
        &self,
        mut state: State,
        terminator: &SemanticTerminator,
    ) -> Result<Vec<State>, Error> {
        match terminator {
            SemanticTerminator::FallThrough => Ok(vec![state]),
            SemanticTerminator::Jump { target } => {
                let target = self.eval_expression(&mut state, target, false)?;
                let target = self.coerce_address(&mut state, &target)?;
                state.set_program_counter(target);
                Ok(vec![state])
            }
            SemanticTerminator::Branch {
                condition,
                true_target,
                false_target,
            } => {
                let condition = self.eval_condition(&mut state, condition)?;
                let true_target = self.eval_expression(&mut state, true_target, false)?;
                let false_target = self.eval_expression(&mut state, false_target, false)?;
                let true_target = self.coerce_address(&mut state, &true_target)?;
                let false_target = self.coerce_address(&mut state, &false_target)?;

                let mut taken = state.clone();
                taken.add_constraint(condition.clone());
                taken.set_program_counter(true_target);

                let mut not_taken = state;
                not_taken.add_constraint(condition.not());
                not_taken.set_program_counter(false_target);

                Ok(vec![taken, not_taken])
            }
            SemanticTerminator::Return { expression } => {
                if let Some(expression) = expression {
                    let target = self.eval_expression(&mut state, expression, false)?;
                    let target = self.coerce_address(&mut state, &target)?;
                    state.set_program_counter(target);
                }
                Ok(vec![state])
            }
            SemanticTerminator::Trap | SemanticTerminator::Unreachable => Ok(Vec::new()),
            SemanticTerminator::Call { target, .. } => {
                let target = self.eval_expression(&mut state, target, false)?;
                let target = self.coerce_address(&mut state, &target)?;
                state.set_program_counter(target);
                Ok(vec![state])
            }
        }
    }

    fn apply_memory_set(
        &self,
        state: &mut State,
        addr: &SemanticExpression,
        value: &SemanticExpression,
        count: &SemanticExpression,
        element_bits: u16,
        decrement: &SemanticExpression,
    ) -> Result<(), Error> {
        let base_address = self.eval_expression(state, addr, false)?;
        let base_address = self.coerce_address(state, &base_address)?;
        let value = self.eval_expression(state, value, false)?;
        let value = state.backend().coerce_bv_width(&value, element_bits)?;
        let count = self.eval_expression(state, count, false)?;
        let count = self
            .concrete_bv_u64(&count)
            .ok_or(Error::UnsupportedEffect("memory_set with symbolic count"))?;
        let decrement = self.eval_condition(state, decrement)?;
        let decrement = self
            .concrete_bool(&decrement)
            .ok_or(Error::UnsupportedEffect(
                "memory_set with symbolic decrement",
            ))?;
        let backend = state.backend().clone();
        let stride = (element_bits / 8) as u64;
        for index in 0..count {
            let offset = if decrement {
                index * stride
            } else {
                index * stride
            };
            let offset = backend.const_bv(offset as u128, self.address_bits)?;
            let address = if decrement {
                base_address.bvsub(&offset)
            } else {
                base_address.bvadd(&offset)
            };
            state
                .memory_mut()
                .store(&backend, &address, &value, element_bits)?;
        }
        Ok(())
    }

    fn apply_memory_copy(
        &self,
        state: &mut State,
        src_addr: &SemanticExpression,
        dst_addr: &SemanticExpression,
        count: &SemanticExpression,
        element_bits: u16,
        decrement: &SemanticExpression,
    ) -> Result<(), Error> {
        let src_base = self.eval_expression(state, src_addr, false)?;
        let src_base = self.coerce_address(state, &src_base)?;
        let dst_base = self.eval_expression(state, dst_addr, false)?;
        let dst_base = self.coerce_address(state, &dst_base)?;
        let count = self.eval_expression(state, count, false)?;
        let count = self
            .concrete_bv_u64(&count)
            .ok_or(Error::UnsupportedEffect("memory_copy with symbolic count"))?;
        let decrement = self.eval_condition(state, decrement)?;
        let decrement = self
            .concrete_bool(&decrement)
            .ok_or(Error::UnsupportedEffect(
                "memory_copy with symbolic decrement",
            ))?;
        let backend = state.backend().clone();
        let stride = (element_bits / 8) as u64;
        for index in 0..count {
            let offset = backend.const_bv((index * stride) as u128, self.address_bits)?;
            let src = if decrement {
                src_base.bvsub(&offset)
            } else {
                src_base.bvadd(&offset)
            };
            let dst = if decrement {
                dst_base.bvsub(&offset)
            } else {
                dst_base.bvadd(&offset)
            };
            let value = state.memory().load(&backend, &src, element_bits)?;
            state
                .memory_mut()
                .store(&backend, &dst, &value, element_bits)?;
        }
        Ok(())
    }

    fn apply_atomic_cmpxchg(
        &self,
        state: &mut State,
        addr: &SemanticExpression,
        expected: &SemanticExpression,
        desired: &SemanticExpression,
        bits: u16,
        observed: &SemanticLocation,
    ) -> Result<(), Error> {
        let address = self.eval_expression(state, addr, false)?;
        let address = self.coerce_address(state, &address)?;
        let backend = state.backend().clone();
        let observed_value = state.memory().load(&backend, &address, bits)?;
        self.write_location(state, observed, observed_value.clone())?;
        let expected = self.eval_expression(state, expected, false)?;
        let expected = state.backend().coerce_bv_width(&expected, bits)?;
        let desired = self.eval_expression(state, desired, false)?;
        let desired = state.backend().coerce_bv_width(&desired, bits)?;
        let equal = observed_value.eq(&expected);
        let stored = equal.ite(&desired, &observed_value);
        state
            .memory_mut()
            .store(&backend, &address, &stored, bits)?;
        Ok(())
    }

    fn read_location(&self, state: &mut State, location: &SemanticLocation) -> Result<BV, Error> {
        match location {
            SemanticLocation::Register { name, bits } => state.get_or_create_register(name, *bits),
            SemanticLocation::Flag { name, bits } => state.get_or_create_flag(name, *bits),
            SemanticLocation::ProgramCounter { bits } => state.get_or_create_program_counter(*bits),
            SemanticLocation::Temporary { id, bits } => state.get_or_create_temporary(*id, *bits),
            SemanticLocation::Memory { addr, bits, .. } => {
                let address = self.eval_expression(state, addr, false)?;
                let address = self.coerce_address(state, &address)?;
                state.memory().load(state.backend(), &address, *bits)
            }
        }
    }

    fn write_location(
        &self,
        state: &mut State,
        location: &SemanticLocation,
        value: BV,
    ) -> Result<(), Error> {
        match location {
            SemanticLocation::Register { name, bits } => {
                let value = state.backend().coerce_bv_width(&value, *bits)?;
                state.set_register_value(name, value);
                Ok(())
            }
            SemanticLocation::Flag { name, bits } => {
                let value = state.backend().coerce_bv_width(&value, *bits)?;
                state.set_flag_value(name, value);
                Ok(())
            }
            SemanticLocation::ProgramCounter { bits } => {
                let value = state.backend().coerce_bv_width(&value, *bits)?;
                state.set_program_counter(value);
                Ok(())
            }
            SemanticLocation::Temporary { id, bits } => {
                let value = state.backend().coerce_bv_width(&value, *bits)?;
                state.set_temporary_value(*id, value);
                Ok(())
            }
            SemanticLocation::Memory { addr, bits, .. } => {
                let address = self.eval_expression(state, addr, false)?;
                let address = self.coerce_address(state, &address)?;
                let value = state.backend().coerce_bv_width(&value, *bits)?;
                let backend = state.backend().clone();
                state.memory_mut().store(&backend, &address, &value, *bits)
            }
        }
    }

    fn eval_expression(
        &self,
        state: &mut State,
        expression: &SemanticExpression,
        expected_float: bool,
    ) -> Result<BV, Error> {
        match expression {
            SemanticExpression::Const { value, bits } => state.backend().const_bv(*value, *bits),
            SemanticExpression::Read(location) => self.read_location(state, location),
            SemanticExpression::Load { addr, bits, .. } => {
                let address = self.eval_expression(state, addr, false)?;
                let address = self.coerce_address(state, &address)?;
                state.memory().load(state.backend(), &address, *bits)
            }
            SemanticExpression::Unary { op, arg, bits } => {
                let arg_expression = arg.as_ref();
                let arg = self.eval_expression(state, arg_expression, expected_float)?;
                let arg = state.backend().coerce_bv_width(&arg, *bits)?;
                self.eval_unary(state, *op, arg, arg_expression, *bits, expected_float)
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
                let left = state.backend().coerce_bv_width(&left, *bits)?;
                let right = state.backend().coerce_bv_width(&right, *bits)?;
                self.eval_binary(state, *op, left, right)
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
                self.eval_cast(state, *op, arg, *bits)
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
                let width = left.get_size().max(right.get_size()) as u16;
                let left = state.backend().coerce_bv_width(&left, width)?;
                let right = state.backend().coerce_bv_width(&right, width)?;
                let value = self.eval_compare(state, *op, left, right)?;
                state.backend().bool_to_bv(&value, *bits)
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
                let when_true = state.backend().coerce_bv_width(&when_true, *bits)?;
                let when_false = state.backend().coerce_bv_width(&when_false, *bits)?;
                Ok(condition.ite(&when_true, &when_false))
            }
            SemanticExpression::Extract { arg, lsb, bits } => {
                let arg = self.eval_expression(state, arg, expected_float)?;
                Ok(arg.extract((*lsb + *bits - 1) as u32, *lsb as u32))
            }
            SemanticExpression::Concat { parts, bits } => {
                let mut parts = parts.iter();
                let first = parts
                    .next()
                    .ok_or(Error::UnsupportedExpression("concat with zero parts"))?;
                let mut value = self.eval_expression(state, first, expected_float)?;
                for part in parts {
                    let next = self.eval_expression(state, part, expected_float)?;
                    value = value.concat(&next);
                }
                state.backend().coerce_bv_width(&value, *bits)
            }
            SemanticExpression::Undefined { bits } => state.fresh_value("undefined", *bits),
            SemanticExpression::Poison { bits } => state.fresh_value("poison", *bits),
            SemanticExpression::Intrinsic { name, args, bits } => {
                self.eval_intrinsic_expression(state, name, args, *bits)
            }
        }
    }

    fn eval_condition(
        &self,
        state: &mut State,
        expression: &SemanticExpression,
    ) -> Result<z3::ast::Bool, Error> {
        let value = self.eval_expression(state, expression, false)?;
        Ok(state.backend().bv_to_bool(&value))
    }

    fn eval_unary(
        &self,
        state: &mut State,
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
        state: &State,
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
        state: &mut State,
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
        state: &State,
        op: SemanticOperationCompare,
        left: BV,
        right: BV,
    ) -> Result<z3::ast::Bool, Error> {
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

    fn coerce_address(&self, state: &mut State, value: &BV) -> Result<BV, Error> {
        state.backend().coerce_bv_width(value, self.address_bits)
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

    fn byte_swap(&self, state: &mut State, arg: &BV, bits: u16) -> Result<BV, Error> {
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

    fn bit_reverse(&self, state: &mut State, arg: &BV, bits: u16) -> Result<BV, Error> {
        let parts = (0..bits)
            .map(|index| arg.extract(index as u32, index as u32))
            .collect::<Vec<_>>();
        self.concat_parts(state, &parts)
    }

    fn popcount(&self, state: &mut State, arg: &BV, bits: u16) -> Result<BV, Error> {
        let mut total = state.backend().zero_bv(bits)?;
        for index in 0..bits {
            let bit = arg.extract(index as u32, index as u32);
            let extended = bit.zero_ext((bits - 1) as u32);
            total = total.bvadd(&extended);
        }
        Ok(total)
    }

    fn count_leading_zeros(&self, state: &mut State, arg: &BV, bits: u16) -> Result<BV, Error> {
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

    fn count_trailing_zeros(&self, state: &mut State, arg: &BV, bits: u16) -> Result<BV, Error> {
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

    fn concat_parts(&self, state: &mut State, parts: &[BV]) -> Result<BV, Error> {
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

    fn eval_fp_abs(&self, state: &State, value: BV) -> Result<BV, Error> {
        let value = state.backend().float_from_ieee_bv(&value)?;
        Ok(state.backend().float_to_ieee_bv(&value.unary_abs()))
    }

    fn eval_fp_neg(&self, state: &State, value: BV) -> Result<BV, Error> {
        let value = state.backend().float_from_ieee_bv(&value)?;
        Ok(state.backend().float_to_ieee_bv(&value.unary_neg()))
    }

    fn eval_fp_sqrt(&self, state: &State, value: BV) -> Result<BV, Error> {
        let value = state.backend().float_from_ieee_bv(&value)?;
        Ok(state.backend().float_to_ieee_bv(&value.sqrt()))
    }

    fn expression_is_probably_float(&self, expression: &SemanticExpression) -> bool {
        match expression {
            SemanticExpression::Const { bits, .. } => matches!(*bits, 32 | 64),
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
            | SemanticExpression::Intrinsic { .. } => false,
        }
    }

    fn location_is_probably_float(&self, location: &SemanticLocation) -> bool {
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
            SemanticLocation::Memory { .. } => false,
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
        state: &State,
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
        state: &State,
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

    fn eval_intrinsic_expression(
        &self,
        state: &mut State,
        name: &str,
        args: &[SemanticExpression],
        bits: u16,
    ) -> Result<BV, Error> {
        if let Some(value) = self.eval_x87_intrinsic_expression(state, name, args, bits)? {
            return Ok(value);
        }
        Err(Error::UnsupportedExpression("intrinsic"))
    }

    fn eval_x87_intrinsic_expression(
        &self,
        state: &mut State,
        name: &str,
        args: &[SemanticExpression],
        bits: u16,
    ) -> Result<Option<BV>, Error> {
        if let Some(constant) = name.strip_prefix("x86.x87.const_") {
            return Ok(Some(self.eval_x87_constant(state, constant, bits)?));
        }
        if !name.starts_with("x86.x87.") {
            return Ok(None);
        }

        let op = &name["x86.x87.".len()..];
        let evaluated = args
            .iter()
            .map(|arg| self.eval_expression(state, arg, true))
            .collect::<Result<Vec<_>, _>>()?;

        let value = match op {
            "add" | "sub" | "mul" | "div" => {
                let [left, right] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let left = state.backend().float_from_ieee_bv(left)?;
                let right = state.backend().float_from_ieee_bv(right)?;
                let rounding = RoundingMode::round_nearest_ties_to_even();
                let result = match op {
                    "add" => left.add_with_rounding_mode(&right, &rounding),
                    "sub" => left.sub_with_rounding_mode(&right, &rounding),
                    "mul" => left.mul_with_rounding_mode(&right, &rounding),
                    "div" => left.div_with_rounding_mode(&right, &rounding),
                    _ => unreachable!(),
                };
                state.backend().float_to_ieee_bv(&result)
            }
            "abs" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                self.eval_fp_abs(state, value.clone())?
            }
            "neg" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                self.eval_fp_neg(state, value.clone())?
            }
            "sqrt" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                self.eval_fp_sqrt(state, value.clone())?
            }
            "rint" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let value = state.backend().float_from_ieee_bv(value)?;
                let rounded = value
                    .round_to_integral_with_rounding_mode(&RoundingMode::round_nearest_ties_to_even());
                state.backend().float_to_ieee_bv(&rounded)
            }
            "load_f32" => {
                let [raw] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let value = state.backend().float_from_ieee_bv(raw)?;
                let value = state.backend().float_cast(&value, bits)?;
                state.backend().float_to_ieee_bv(&value)
            }
            "load_f64" => {
                let [raw] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let value = state.backend().float_from_ieee_bv(raw)?;
                let value = state.backend().float_cast(&value, bits)?;
                state.backend().float_to_ieee_bv(&value)
            }
            "load_i16" | "load_i32" | "load_i64" => {
                let [raw] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let value = state.backend().signed_bv_to_float(raw, bits)?;
                state.backend().float_to_ieee_bv(&value)
            }
            "load_bcd" => {
                let [raw] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let raw = self
                    .concrete_bv_u128(raw)
                    .ok_or(Error::UnsupportedExpression("x87 intrinsic requires concrete value"))?;
                let integer = self.decode_x87_bcd(raw)?;
                let integer = state.backend().const_bv(integer as u128, 64)?;
                let value = state.backend().signed_bv_to_float(&integer, bits)?;
                state.backend().float_to_ieee_bv(&value)
            }
            "store_f32" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let value = state.backend().float_from_ieee_bv(value)?;
                let value = state.backend().float_cast(&value, 32)?;
                state.backend().float_to_ieee_bv(&value)
            }
            "store_f64" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let value = state.backend().float_from_ieee_bv(value)?;
                let value = state.backend().float_cast(&value, 64)?;
                state.backend().float_to_ieee_bv(&value)
            }
            "store_bcd" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let value = self
                    .try_concrete_f64_from_fp_bv(state, value)
                    .ok_or(Error::UnsupportedExpression("x87 intrinsic requires concrete value"))?;
                if !value.is_finite() || value < i64::MIN as f64 || value > i64::MAX as f64 {
                    return Err(Error::UnsupportedExpression("x87 bcd value out of range"));
                }
                let rounded = value.round_ties_even() as i64;
                state.backend().const_bv(self.encode_x87_bcd(rounded), bits)?
            }
            "sin" | "cos" | "tan" | "f2xm1" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let concrete = self
                    .try_concrete_f64_from_fp_bv(state, value)
                    .ok_or(Error::UnsupportedExpression("x87 intrinsic requires concrete value"))?;
                let result = match op {
                    "sin" => concrete.sin(),
                    "cos" => concrete.cos(),
                    "tan" => concrete.tan(),
                    "f2xm1" => 2.0f64.powf(concrete) - 1.0,
                    _ => unreachable!(),
                };
                let value = state.backend().float_from_f64(bits, result)?;
                state.backend().float_to_ieee_bv(&value)
            }
            "atan2" | "yl2x" | "yl2xp1" | "scale" => {
                let [left, right] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let left = self
                    .try_concrete_f64_from_fp_bv(state, left)
                    .ok_or(Error::UnsupportedExpression("x87 intrinsic requires concrete value"))?;
                let right = self
                    .try_concrete_f64_from_fp_bv(state, right)
                    .ok_or(Error::UnsupportedExpression("x87 intrinsic requires concrete value"))?;
                let result = match op {
                    "atan2" => left.atan2(right),
                    "yl2x" => left * right.log2(),
                    "yl2xp1" => left * (right + 1.0).log2(),
                    "scale" => left * 2.0f64.powf(right.trunc()),
                    _ => unreachable!(),
                };
                let value = state.backend().float_from_f64(bits, result)?;
                state.backend().float_to_ieee_bv(&value)
            }
            op if op.starts_with("store_i") => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let (target_bits, trunc) = self.parse_x87_store_int_op(op)?;
                let value = state.backend().float_from_ieee_bv(value)?;
                let rounded = if trunc {
                    value.to_sbv_with_rounding_mode(&RoundingMode::round_towards_zero(), target_bits as u32)
                } else {
                    value.to_sbv_with_rounding_mode(
                        &RoundingMode::round_nearest_ties_to_even(),
                        target_bits as u32,
                    )
                };
                rounded.zero_ext((bits - target_bits) as u32)
            }
            _ => return Ok(None),
        };

        Ok(Some(state.backend().coerce_bv_width(&value, bits)?))
    }

    fn eval_x87_constant(&self, state: &State, name: &str, bits: u16) -> Result<BV, Error> {
        let value = match name {
            "one" => 1.0,
            "zero" => 0.0,
            "pi" => std::f64::consts::PI,
            "l2t" => std::f64::consts::LOG2_10,
            "l2e" => std::f64::consts::LOG2_E,
            "lg2" => std::f64::consts::LOG10_2,
            "ln2" => std::f64::consts::LN_2,
            _ => return Err(Error::UnsupportedExpression("x87 constant")),
        };
        let value = state.backend().float_from_f64(bits, value)?;
        Ok(state.backend().float_to_ieee_bv(&value))
    }

    fn try_concrete_f64_from_fp_bv(&self, state: &State, value: &BV) -> Option<f64> {
        let value = state.backend().float_from_ieee_bv(value).ok()?;
        let value = state.backend().float_cast(&value, 64).ok()?;
        let bits = state.backend().float_to_ieee_bv(&value).simplify();
        bits.as_u64().map(f64::from_bits)
    }

    fn encode_x87_bcd(&self, value: i64) -> u128 {
        let negative = value.is_negative();
        let mut magnitude = value.unsigned_abs();
        let mut bytes = [0u8; 10];
        for byte in bytes.iter_mut().take(9) {
            let low = (magnitude % 10) as u8;
            magnitude /= 10;
            let high = (magnitude % 10) as u8;
            magnitude /= 10;
            *byte = low | (high << 4);
        }
        let top_digit = (magnitude % 10) as u8;
        bytes[9] = top_digit | if negative { 0x80 } else { 0x00 };
        u128::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
            bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
            0, 0, 0, 0, 0, 0,
        ])
    }

    fn decode_x87_bcd(&self, raw: u128) -> Result<i64, Error> {
        let bytes = raw.to_le_bytes();
        let mut digits = 0u64;
        let mut factor = 1u64;
        for byte in bytes.iter().take(9) {
            let low = byte & 0x0f;
            let high = (byte >> 4) & 0x0f;
            if low > 9 || high > 9 {
                return Err(Error::UnsupportedExpression("invalid x87 bcd digit"));
            }
            digits = digits
                .checked_add((low as u64).saturating_mul(factor))
                .ok_or(Error::UnsupportedExpression("x87 bcd overflow"))?;
            factor = factor
                .checked_mul(10)
                .ok_or(Error::UnsupportedExpression("x87 bcd overflow"))?;
            digits = digits
                .checked_add((high as u64).saturating_mul(factor))
                .ok_or(Error::UnsupportedExpression("x87 bcd overflow"))?;
            factor = factor
                .checked_mul(10)
                .ok_or(Error::UnsupportedExpression("x87 bcd overflow"))?;
        }
        let top = bytes[9] & 0x0f;
        if top > 9 {
            return Err(Error::UnsupportedExpression("invalid x87 bcd digit"));
        }
        digits = digits
            .checked_add((top as u64).saturating_mul(factor))
            .ok_or(Error::UnsupportedExpression("x87 bcd overflow"))?;
        let negative = (bytes[9] & 0x80) != 0;
        if negative {
            Ok(-(digits as i64))
        } else {
            Ok(digits as i64)
        }
    }

    fn apply_intrinsic_effect(
        &self,
        state: &mut State,
        name: &str,
        args: &[SemanticExpression],
        outputs: &[SemanticLocation],
    ) -> Result<(), Error> {
        if name == "x86.x87.xam" {
            return self.apply_x87_xam_effect(state, args, outputs);
        }
        Err(Error::UnsupportedEffect("intrinsic"))
    }

    fn apply_x87_xam_effect(
        &self,
        state: &mut State,
        args: &[SemanticExpression],
        outputs: &[SemanticLocation],
    ) -> Result<(), Error> {
        let [arg] = args else {
            return Err(Error::UnsupportedEffect("x87 xam arity"));
        };
        if outputs.len() != 4 {
            return Err(Error::UnsupportedEffect("x87 xam outputs"));
        }

        let value = self.eval_expression(state, arg, true)?;
        let value = state.backend().float_from_ieee_bv(&value)?;

        let c0 = Bool::or(&[value.is_nan(), value.is_infinite()]);
        let c1 = value.is_negative();
        let c2 = Bool::or(&[value.is_normal(), value.is_infinite(), value.is_subnormal()]);
        let c3 = Bool::or(&[value.is_zero(), value.is_subnormal()]);

        let flags = [c0, c1, c2, c3];
        for (output, flag) in outputs.iter().zip(flags.into_iter()) {
            let bits = output.bits();
            let value = state.backend().bool_to_bv(&flag, bits)?;
            self.write_location(state, output, value)?;
        }
        Ok(())
    }

    fn parse_x87_store_int_op(&self, op: &str) -> Result<(u16, bool), Error> {
        let Some(suffix) = op.strip_prefix("store_i") else {
            return Err(Error::UnsupportedExpression("x87 store intrinsic"));
        };
        let trunc = suffix.ends_with("_trunc");
        let width = if trunc {
            &suffix[..suffix.len() - "_trunc".len()]
        } else {
            suffix
        };
        let bits = width
            .parse::<u16>()
            .map_err(|_| Error::UnsupportedExpression("x87 store intrinsic"))?;
        match bits {
            16 | 32 | 64 => Ok((bits, trunc)),
            _ => Err(Error::UnsupportedExpression("x87 store intrinsic")),
        }
    }

    fn concrete_bv_u64(&self, value: &BV) -> Option<u64> {
        value.as_u64()
    }

    fn concrete_bv_u128(&self, value: &BV) -> Option<u128> {
        if let Some(value) = value.as_u64() {
            return Some(value as u128);
        }
        let text = value.simplify().to_string();
        if let Some(hex) = text.strip_prefix("#x") {
            return u128::from_str_radix(hex, 16).ok();
        }
        if let Some(binary) = text.strip_prefix("#b") {
            return u128::from_str_radix(binary, 2).ok();
        }
        text.parse::<u128>().ok()
    }

    fn concrete_bool(&self, value: &Bool) -> Option<bool> {
        value.as_bool()
    }
}

#[cfg(test)]
mod tests {
    use super::Executor;
    use crate::Architecture;
    use crate::semantics::{
        InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation,
        SemanticOperationBinary, SemanticOperationCast, SemanticOperationCompare,
        SemanticOperationUnary, SemanticStatus, SemanticTerminator,
    };

    #[test]
    fn symbolic_branch_forks() {
        let executor = Executor::new(Architecture::ARM64).expect("executor");
        let mut state = executor.state();
        state
            .symbolize_register("x0", 64, Some("input_x0"))
            .expect("symbolize register");

        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::Branch {
                condition: SemanticExpression::Compare {
                    op: SemanticOperationCompare::Eq,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x0".to_string(),
                            bits: 64,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Const { value: 0, bits: 64 }),
                    bits: 1,
                },
                true_target: SemanticExpression::Const {
                    value: 0x1000,
                    bits: 64,
                },
                false_target: SemanticExpression::Const {
                    value: 0x2000,
                    bits: 64,
                },
            },
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics, &state).expect("step");
        assert_eq!(states.len(), 2);
        assert!(
            states
                .iter()
                .all(|state| state.satisfiable().expect("sat check"))
        );
        let targets = states
            .iter()
            .map(|state| {
                state
                    .evaluate_register("pc", 64)
                    .expect("evaluate ip register")
                    .expect("concrete ip register")
            })
            .collect::<Vec<_>>();
        assert!(targets.contains(&0x1000));
        assert!(targets.contains(&0x2000));
    }

    #[test]
    fn symbolic_memory_store_then_load() {
        let executor = Executor::new(Architecture::AMD64).expect("executor");
        let state = executor.state();

        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Store {
                    space: crate::semantics::SemanticAddressSpace::Default,
                    addr: SemanticExpression::Const {
                        value: 0x3000,
                        bits: 64,
                    },
                    expression: SemanticExpression::Const {
                        value: 0x41,
                        bits: 8,
                    },
                    bits: 8,
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "rax".to_string(),
                        bits: 8,
                    },
                    expression: SemanticExpression::Load {
                        space: crate::semantics::SemanticAddressSpace::Default,
                        addr: Box::new(SemanticExpression::Const {
                            value: 0x3000,
                            bits: 64,
                        }),
                        bits: 8,
                    },
                },
            ],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics, &state).expect("step");
        let value = states[0]
                .evaluate_register("rax", 8)
            .expect("evaluate register")
            .expect("concrete register");
        assert_eq!(value, 0x41);
    }

    #[test]
    fn symbolic_unary_popcount_executes() {
        let executor = Executor::new(Architecture::ARM64).expect("executor");
        let state = executor.state();
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x0".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Unary {
                    op: SemanticOperationUnary::PopCount,
                    arg: Box::new(SemanticExpression::Const {
                        value: 0b1011,
                        bits: 64,
                    }),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let states = executor.step(&semantics, &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("x0", 64)
                .expect("eval register")
                .expect("concrete value"),
            3
        );
    }

    #[test]
    fn symbolic_mul_high_executes() {
        let executor = Executor::new(Architecture::ARM64).expect("executor");
        let state = executor.state();
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x0".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::UMulHigh,
                    left: Box::new(SemanticExpression::Const {
                        value: u64::MAX as u128,
                        bits: 64,
                    }),
                    right: Box::new(SemanticExpression::Const { value: 2, bits: 64 }),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let states = executor.step(&semantics, &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("x0", 64)
                .expect("eval register")
                .expect("concrete value"),
            1
        );
    }

    #[test]
    fn partial_semantics_are_rejected() {
        let executor = Executor::new(Architecture::AMD64).expect("executor");
        let state = executor.state();
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Partial,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        assert!(executor.step(&semantics, &state).is_err());
    }

    #[test]
    fn symbolic_trace_run_executes() {
        let executor = Executor::new(Architecture::AMD64).expect("executor");
        let state = executor.state();
        let first = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Const { value: 7, bits: 64 },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let second = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "rbx".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::Add,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "rax".to_string(),
                            bits: 64,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Const { value: 5, bits: 64 }),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::Jump {
                target: SemanticExpression::Const {
                    value: 0x401000,
                    bits: 64,
                },
            },
            diagnostics: Vec::new(),
        };
        let states = executor.run([&first, &second], &state).expect("run");
        assert_eq!(states.len(), 1);
        assert_eq!(
            states[0]
                .evaluate_register("rbx", 64)
                .expect("eval register")
                .expect("concrete value"),
            12
        );
        assert_eq!(
            states[0]
                .eval_program_counter_u64()
                .expect("eval program counter")
                .expect("concrete pc"),
            0x401000
        );
    }

    #[test]
    fn symbolic_memory_u64_eval_executes() {
        let executor = Executor::new(Architecture::AMD64).expect("executor");
        let mut state = executor.state();
        state
            .write_memory(0x5000, &[0x44, 0x33, 0x22, 0x11])
            .expect("write memory");
        assert_eq!(
            state
                .evaluate_memory(0x5000, 4)
                .expect("eval memory")
                .expect("concrete memory"),
            0x11223344
        );
    }

    #[test]
    fn symbolic_call_sets_program_counter() {
        let executor = Executor::new(Architecture::ARM64).expect("executor");
        let state = executor.state();
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::Call {
                target: SemanticExpression::Const {
                    value: 0x1000,
                    bits: 64,
                },
                return_target: None,
                does_return: Some(true),
            },
            diagnostics: Vec::new(),
        };
        let states = executor.step(&semantics, &state).expect("step");
        assert_eq!(
            states[0]
                .eval_program_counter_u64()
                .expect("eval program counter")
                .expect("concrete pc"),
            0x1000
        );
    }

    #[test]
    fn symbolic_fp_add32_executes() {
        let executor = Executor::new(Architecture::ARM64).expect("executor");
        let mut state = executor.state();
        state
            .set_register("s0", 32, 1.5f32.to_bits() as u64)
            .expect("set register");
        state
            .set_register("s1", 32, 2.25f32.to_bits() as u64)
            .expect("set register");

        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "s2".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::FAdd,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "s0".to_string(),
                            bits: 32,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "s1".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 32,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics, &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("s2", 32)
                .expect("eval register")
                .expect("concrete value"),
            (1.5f32 + 2.25f32).to_bits() as u64
        );
    }

    #[test]
    fn symbolic_fp_casts_execute() {
        let executor = Executor::new(Architecture::ARM64).expect("executor");
        let mut state = executor.state();
        state.set_register("x0", 64, 42).expect("set register");

        let to_float = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "d0".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let from_float = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::FloatToInt,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "d0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run([&to_float, &from_float], &state)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("d0", 64)
                .expect("eval register")
                .expect("concrete value"),
            (42f64).to_bits()
        );
        assert_eq!(
            states[0]
                .evaluate_register("x1", 64)
                .expect("eval register")
                .expect("concrete value"),
            42
        );
    }

    #[test]
    fn symbolic_fp_unordered_compare_executes() {
        let executor = Executor::new(Architecture::ARM64).expect("executor");
        let mut state = executor.state();
        state
            .set_register("d0", 64, f64::NAN.to_bits())
            .expect("set register");
        state
            .set_register("d1", 64, 1.0f64.to_bits())
            .expect("set register");

        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x2".to_string(),
                    bits: 1,
                },
                expression: SemanticExpression::Compare {
                    op: SemanticOperationCompare::Unordered,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "d0".to_string(),
                            bits: 64,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "d1".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 1,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics, &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("x2", 1)
                .expect("eval register")
                .expect("concrete value"),
            1
        );
    }

    #[test]
    fn symbolic_fp_neg_executes() {
        let executor = Executor::new(Architecture::ARM64).expect("executor");
        let mut state = executor.state();
        state
            .set_register("d0", 64, 3.5f64.to_bits())
            .expect("set register");

        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "d1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Unary {
                    op: SemanticOperationUnary::Neg,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "d0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics, &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("d1", 64)
                .expect("eval register")
                .expect("concrete value"),
            (-3.5f64).to_bits()
        );
    }

    #[test]
    fn symbolic_fp_neg_of_const_executes() {
        let executor = Executor::new(Architecture::ARM64).expect("executor");
        let state = executor.state();

        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "d1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Unary {
                    op: SemanticOperationUnary::Neg,
                    arg: Box::new(SemanticExpression::Const {
                        value: 3.5f64.to_bits() as u128,
                        bits: 64,
                    }),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics, &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("d1", 64)
                .expect("eval register")
                .expect("concrete value"),
            (-3.5f64).to_bits()
        );
    }

    #[test]
    fn symbolic_fp_neg_of_memory_load_executes() {
        let executor = Executor::new(Architecture::ARM64).expect("executor");
        let mut state = executor.state();
        state
            .write_memory(0x8000, &3.5f64.to_bits().to_le_bytes())
            .expect("write memory");

        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "d1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Unary {
                    op: SemanticOperationUnary::Neg,
                    arg: Box::new(SemanticExpression::Load {
                        space: crate::semantics::SemanticAddressSpace::Default,
                        addr: Box::new(SemanticExpression::Const {
                            value: 0x8000,
                            bits: 64,
                        }),
                        bits: 64,
                    }),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics, &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("d1", 64)
                .expect("eval register")
                .expect("concrete value"),
            (-3.5f64).to_bits()
        );
    }

    #[test]
    fn symbolic_integer_neg_still_executes() {
        let executor = Executor::new(Architecture::ARM64).expect("executor");
        let mut state = executor.state();
        state.set_register("x0", 64, 7).expect("set register");

        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Unary {
                    op: SemanticOperationUnary::Neg,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics, &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("x1", 64)
                .expect("eval register")
                .expect("concrete value"),
            (!7u64).wrapping_add(1)
        );
    }

    #[test]
    fn symbolic_float80_compare_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let mut state = executor.state();
        state.set_register("eax", 32, 1).expect("set register");
        state.set_register("ebx", 32, 2).expect("set register");

        let to_fp80_left = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let to_fp80_right = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st1".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "ebx".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let compare = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "ecx".to_string(),
                    bits: 1,
                },
                expression: SemanticExpression::Compare {
                    op: SemanticOperationCompare::Olt,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st1".to_string(),
                            bits: 80,
                        },
                    ))),
                    bits: 1,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run([&to_fp80_left, &to_fp80_right, &compare], &state)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("ecx", 32)
                .expect("eval register")
                .expect("concrete value"),
            1
        );
    }

    #[test]
    fn symbolic_float80_truncate_to_f64_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let mut state = executor.state();
        state.set_register("eax", 32, 42).expect("set register");

        let to_fp80 = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let truncate = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm0".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::FloatTruncate,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.run([&to_fp80, &truncate], &state).expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("xmm0", 64)
                .expect("eval register")
                .expect("concrete value"),
            (42f64).to_bits()
        );
    }

    #[test]
    fn symbolic_x87_const_add_store_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let mut state = executor.state();
        state.set_register("eax", 32, 7).expect("set register");
        state.set_register("ebx", 32, 2).expect("set register");

        let lhs = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let rhs = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st1".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "ebx".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let add = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.add".to_string(),
                    args: vec![
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        })),
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st1".to_string(),
                            bits: 80,
                        })),
                    ],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm0".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run([&lhs, &rhs, &add, &store], &state)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("xmm0", 64)
                .expect("eval register")
                .expect("concrete value"),
            (9.0f64).to_bits()
        );
    }

    #[test]
    fn symbolic_x87_load_f32_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let mut state = executor.state();
        state
            .write_memory(0x9000, &3.25f32.to_bits().to_le_bytes())
            .expect("write memory");

        let load = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.load_f32".to_string(),
                    args: vec![SemanticExpression::Load {
                        space: crate::semantics::SemanticAddressSpace::Default,
                        addr: Box::new(SemanticExpression::Const {
                            value: 0x9000,
                            bits: 32,
                        }),
                        bits: 32,
                    }],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm0".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.run([&load, &store], &state).expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("xmm0", 64)
                .expect("eval register")
                .expect("concrete value"),
            (3.25f32 as f64).to_bits()
        );
    }

    #[test]
    fn symbolic_x87_store_i32_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let state = executor.state();

        let load = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.const_pi".to_string(),
                    args: Vec::new(),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Store {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: SemanticExpression::Const {
                    value: 0xA000,
                    bits: 32,
                },
                expression: SemanticExpression::Extract {
                    arg: Box::new(SemanticExpression::Intrinsic {
                        name: "x86.x87.store_i32".to_string(),
                        args: vec![SemanticExpression::Read(Box::new(
                            SemanticLocation::Register {
                                name: "x87_st0".to_string(),
                                bits: 80,
                            },
                        ))],
                        bits: 80,
                    }),
                    lsb: 0,
                    bits: 32,
                },
                bits: 32,
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.run([&load, &store], &state).expect("run");
        assert_eq!(
            states[0]
                .evaluate_memory(0xA000, 4)
                .expect("eval memory")
                .expect("concrete value"),
            3
        );
    }

    #[test]
    fn symbolic_x87_store_i32_trunc_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let mut state = executor.state();
        state.set_register("eax", 32, 7).expect("set register");
        state.set_register("ebx", 32, 2).expect("set register");

        let to_fp80 = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let divide = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st1".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "ebx".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }, SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.div".to_string(),
                    args: vec![
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        })),
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st1".to_string(),
                            bits: 80,
                        })),
                    ],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Store {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: SemanticExpression::Const {
                    value: 0xA100,
                    bits: 32,
                },
                expression: SemanticExpression::Extract {
                    arg: Box::new(SemanticExpression::Intrinsic {
                        name: "x86.x87.store_i32_trunc".to_string(),
                        args: vec![SemanticExpression::Read(Box::new(
                            SemanticLocation::Register {
                                name: "x87_st0".to_string(),
                                bits: 80,
                            },
                        ))],
                        bits: 80,
                    }),
                    lsb: 0,
                    bits: 32,
                },
                bits: 32,
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run([&to_fp80, &divide, &store], &state)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_memory(0xA100, 4)
                .expect("eval memory")
                .expect("concrete value"),
            3
        );
    }

    #[test]
    fn symbolic_x87_xam_negative_zero_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let mut state = executor.state();
        state
            .set_register("xmm0", 64, (-0.0f64).to_bits())
            .expect("set register");

        let load = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::FloatExtend,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "xmm0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Intrinsic {
                name: "x86.x87.xam".to_string(),
                args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                }))],
                outputs: vec![
                    SemanticLocation::Register {
                        name: "c0".to_string(),
                        bits: 1,
                    },
                    SemanticLocation::Register {
                        name: "c1".to_string(),
                        bits: 1,
                    },
                    SemanticLocation::Register {
                        name: "c2".to_string(),
                        bits: 1,
                    },
                    SemanticLocation::Register {
                        name: "c3".to_string(),
                        bits: 1,
                    },
                ],
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.run([&load, &semantics], &state).expect("run");
        assert_eq!(states[0].evaluate_register("c0", 1).expect("eval").expect("value"), 0);
        assert_eq!(states[0].evaluate_register("c1", 1).expect("eval").expect("value"), 1);
        assert_eq!(states[0].evaluate_register("c2", 1).expect("eval").expect("value"), 0);
        assert_eq!(states[0].evaluate_register("c3", 1).expect("eval").expect("value"), 1);
    }

    #[test]
    fn symbolic_x87_xam_infinity_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let mut state = executor.state();
        state
            .set_register("xmm0", 64, f64::INFINITY.to_bits())
            .expect("set register");

        let load = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::FloatExtend,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "xmm0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Intrinsic {
                name: "x86.x87.xam".to_string(),
                args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                }))],
                outputs: vec![
                    SemanticLocation::Register {
                        name: "c0".to_string(),
                        bits: 1,
                    },
                    SemanticLocation::Register {
                        name: "c1".to_string(),
                        bits: 1,
                    },
                    SemanticLocation::Register {
                        name: "c2".to_string(),
                        bits: 1,
                    },
                    SemanticLocation::Register {
                        name: "c3".to_string(),
                        bits: 1,
                    },
                ],
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.run([&load, &semantics], &state).expect("run");
        assert_eq!(states[0].evaluate_register("c0", 1).expect("eval").expect("value"), 1);
        assert_eq!(states[0].evaluate_register("c1", 1).expect("eval").expect("value"), 0);
        assert_eq!(states[0].evaluate_register("c2", 1).expect("eval").expect("value"), 1);
        assert_eq!(states[0].evaluate_register("c3", 1).expect("eval").expect("value"), 0);
    }

    #[test]
    fn symbolic_x87_sin_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let mut state = executor.state();
        state.set_register("xmm0", 64, 0.0f64.to_bits()).expect("set register");

        let load = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::FloatExtend,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "xmm0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let sin = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.sin".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.run([&load, &sin, &store], &state).expect("run");
        let value = states[0].evaluate_register("xmm1", 64).expect("eval").expect("value");
        assert!(f64::from_bits(value).abs() < 1e-300);
    }

    #[test]
    fn symbolic_x87_cos_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let mut state = executor.state();
        state.set_register("xmm0", 64, 0.0f64.to_bits()).expect("set register");

        let load = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::FloatExtend,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "xmm0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let cos = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.cos".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.run([&load, &cos, &store], &state).expect("run");
        assert_eq!(
            states[0].evaluate_register("xmm1", 64).expect("eval").expect("value"),
            1.0f64.to_bits()
        );
    }

    #[test]
    fn symbolic_x87_atan2_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let mut state = executor.state();
        state.set_register("eax", 32, 1).expect("set register");

        let lhs = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }, SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st1".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let atan2 = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st1".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.atan2".to_string(),
                    args: vec![
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st1".to_string(),
                            bits: 80,
                        })),
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        })),
                    ],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                        name: "x87_st1".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.run([&lhs, &atan2, &store], &state).expect("run");
        assert_eq!(
            states[0].evaluate_register("xmm1", 64).expect("eval").expect("value"),
            std::f64::consts::FRAC_PI_4.to_bits()
        );
    }

    #[test]
    fn symbolic_x87_scale_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let mut state = executor.state();
        state.set_register("eax", 32, 3).expect("set register");
        state.set_register("ebx", 32, 2).expect("set register");

        let load = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }, SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st1".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "ebx".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let scale = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.scale".to_string(),
                    args: vec![
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        })),
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st1".to_string(),
                            bits: 80,
                        })),
                    ],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.run([&load, &scale, &store], &state).expect("run");
        assert_eq!(
            states[0].evaluate_register("xmm1", 64).expect("eval").expect("value"),
            (12.0f64).to_bits()
        );
    }

    #[test]
    fn symbolic_x87_f2xm1_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let mut state = executor.state();
        state.set_register("eax", 32, 1).expect("set register");

        let load = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let op = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.f2xm1".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.run([&load, &op, &store], &state).expect("run");
        assert_eq!(
            states[0].evaluate_register("xmm1", 64).expect("eval").expect("value"),
            1.0f64.to_bits()
        );
    }

    #[test]
    fn symbolic_x87_load_bcd_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let state = executor.state();

        let load = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.load_bcd".to_string(),
                    args: vec![SemanticExpression::Const {
                        value: 0x80000001234567890123,
                        bits: 80,
                    }],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.run([&load, &store], &state).expect("run");
        assert_eq!(
            states[0].evaluate_register("xmm1", 64).expect("eval").expect("value"),
            (-1234567890123.0f64).to_bits()
        );
    }

    #[test]
    fn symbolic_x87_store_bcd_executes() {
        let executor = Executor::new(Architecture::I386).expect("executor");
        let mut state = executor.state();
        state.set_register("eax", 32, 42).expect("set register");

        let load = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Store {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: SemanticExpression::Const {
                    value: 0xA200,
                    bits: 32,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_bcd".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
                bits: 80,
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.run([&load, &store], &state).expect("run");
        assert_eq!(
            states[0]
                .evaluate_memory(0xA200, 8)
                .expect("eval memory")
                .expect("concrete value"),
            0x42
        );
        assert_eq!(
            states[0]
                .evaluate_memory(0xA208, 2)
                .expect("eval memory")
                .expect("concrete value"),
            0
        );
    }
}
