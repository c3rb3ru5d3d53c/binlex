use crate::semantics::{SemanticEffect, SemanticExpression, SemanticLocation};
use crate::symbolic::{Error, Executor, State};
use z3::ast::{Ast, BV, Bool};

impl Executor {
    pub(crate) fn apply_effect(
        &self,
        state: &mut State,
        effect: &SemanticEffect,
    ) -> Result<(), Error> {
        match effect {
            SemanticEffect::Set { dst, expression } => {
                let value =
                    self.eval_expression(state, expression, self.location_is_probably_float(dst))?;
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
            SemanticEffect::Intrinsic {
                name,
                args,
                outputs,
            } => self.apply_intrinsic_effect(state, name, args, outputs),
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
            let offset = index * stride;
            let offset = backend.const_bv(offset as u128, self.address_bits())?;
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
            let offset = backend.const_bv((index * stride) as u128, self.address_bits())?;
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

    pub(crate) fn read_location(
        &self,
        state: &mut State,
        location: &SemanticLocation,
    ) -> Result<BV, Error> {
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

    pub(crate) fn write_location(
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

    pub(crate) fn concrete_bv_u64(&self, value: &BV) -> Option<u64> {
        value.as_u64()
    }

    pub(crate) fn concrete_bv_u128(&self, value: &BV) -> Option<u128> {
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

    pub(crate) fn concrete_bool(&self, value: &Bool) -> Option<bool> {
        value.as_bool()
    }
}
