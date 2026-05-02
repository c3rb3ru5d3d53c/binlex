use crate::semantics::{SemanticEffect, SemanticExpression, SemanticLocation};
use crate::symbolic::{Error, Executor, State};
use z3::ast::{Ast, BV, Bool};

impl Executor {
    pub(crate) fn concretize_if_dependency_free(
        &self,
        state: &State,
        value: crate::symbolic::expressions::EvaluatedValue,
    ) -> Result<crate::symbolic::expressions::EvaluatedValue, Error> {
        if value.deps.is_empty() && value.value.get_size() <= 64 {
            if let Some(concrete) = state
                .backend()
                .eval_bv_u64(state.solver_constraints(), &value.value)?
            {
                return Ok(crate::symbolic::expressions::EvaluatedValue {
                    value: state
                        .backend()
                        .const_bv(concrete as u128, value.value.get_size() as u16)?,
                    deps: value.deps,
                });
            }
        }
        Ok(value)
    }

    fn format_memory_location(&self, address: &BV) -> String {
        if let Some(address) = address.as_u64() {
            format!("memory[0x{address:x}]")
        } else {
            format!("memory[{address}]")
        }
    }

    pub(crate) fn apply_effect(
        &self,
        state: &mut State,
        instruction: Option<&crate::semantics::InstructionEncoding>,
        effect: &SemanticEffect,
    ) -> Result<(), Error> {
        match effect {
            SemanticEffect::Set { dst, expression } => {
                let value =
                    self.eval_expression(state, expression, self.location_is_probably_float(dst))?;
                let value = self.concretize_if_dependency_free(state, value)?;
                self.write_location(state, instruction, dst, value)
            }
            SemanticEffect::Store {
                addr,
                expression,
                bits,
                ..
            } => {
                let raw_address = self.eval_expression(state, addr, false)?;
                let address = self.coerce_address(state, &raw_address.value)?;
                let value = self.eval_expression(state, expression, false)?;
                let value = self.concretize_if_dependency_free(state, value)?;
                let mut parents = if address.as_u64().is_none() {
                    raw_address.deps
                } else {
                    std::collections::BTreeSet::new()
                };
                parents.extend(value.deps.clone());
                let def_id = state.define_location(
                    instruction,
                    self.format_memory_location(&address),
                    &value.value,
                    &parents,
                );
                let backend = state.backend().clone();
                state.memory_mut().store_with_provenance(
                    &backend,
                    &address,
                    &value.value,
                    *bits,
                    def_id,
                )
            }
            SemanticEffect::MemorySet {
                addr,
                value,
                count,
                element_bits,
                decrement,
                ..
            } => self.apply_memory_set(
                state,
                instruction,
                addr,
                value,
                count,
                *element_bits,
                decrement,
            ),
            SemanticEffect::MemoryCopy {
                src_addr,
                dst_addr,
                count,
                element_bits,
                decrement,
                ..
            } => self.apply_memory_copy(
                state,
                instruction,
                src_addr,
                dst_addr,
                count,
                *element_bits,
                decrement,
            ),
            SemanticEffect::AtomicCmpXchg {
                addr,
                expected,
                desired,
                bits,
                observed,
                ..
            } => self.apply_atomic_cmpxchg(
                state,
                instruction,
                addr,
                expected,
                desired,
                *bits,
                observed,
            ),
            SemanticEffect::Nop => Ok(()),
            SemanticEffect::Fence { .. } => Err(Error::UnsupportedEffect("fence")),
            SemanticEffect::Trap { .. } => Err(Error::UnsupportedEffect("trap")),
            SemanticEffect::Intrinsic {
                name,
                args,
                outputs,
            } => self.apply_intrinsic_effect(state, instruction, name, args, outputs),
        }
    }

    fn apply_memory_set(
        &self,
        state: &mut State,
        instruction: Option<&crate::semantics::InstructionEncoding>,
        addr: &SemanticExpression,
        value: &SemanticExpression,
        count: &SemanticExpression,
        element_bits: u16,
        decrement: &SemanticExpression,
    ) -> Result<(), Error> {
        let base_address = self.eval_expression(state, addr, false)?;
        let base_address_value = self.coerce_address(state, &base_address.value)?;
        let value_eval = self.eval_expression(state, value, false)?;
        let value_eval = self.concretize_if_dependency_free(state, value_eval)?;
        let value = state
            .backend()
            .coerce_bv_width(&value_eval.value, element_bits)?;
        let count_eval = self.eval_expression(state, count, false)?;
        let count = self
            .concrete_bv_u64(&count_eval.value)
            .ok_or(Error::UnsupportedEffect("memory_set with symbolic count"))?;
        let decrement_eval = self.eval_condition(state, decrement)?;
        let decrement =
            self.concrete_bool(&decrement_eval.value)
                .ok_or(Error::UnsupportedEffect(
                    "memory_set with symbolic decrement",
                ))?;
        let backend = state.backend().clone();
        let stride = (element_bits / 8) as u64;
        for index in 0..count {
            let offset = index * stride;
            let offset = backend.const_bv(offset as u128, self.address_bits())?;
            let address = if decrement {
                base_address_value.bvsub(&offset)
            } else {
                base_address_value.bvadd(&offset)
            };
            let mut parents = if address.as_u64().is_none() {
                base_address.deps.clone()
            } else {
                std::collections::BTreeSet::new()
            };
            parents.extend(value_eval.deps.clone());
            parents.extend(count_eval.deps.clone());
            parents.extend(decrement_eval.deps.clone());
            let def_id = state.define_location(
                instruction,
                self.format_memory_location(&address),
                &value,
                &parents,
            );
            state.memory_mut().store_with_provenance(
                &backend,
                &address,
                &value,
                element_bits,
                def_id,
            )?;
        }
        Ok(())
    }

    fn apply_memory_copy(
        &self,
        state: &mut State,
        instruction: Option<&crate::semantics::InstructionEncoding>,
        src_addr: &SemanticExpression,
        dst_addr: &SemanticExpression,
        count: &SemanticExpression,
        element_bits: u16,
        decrement: &SemanticExpression,
    ) -> Result<(), Error> {
        let src_base = self.eval_expression(state, src_addr, false)?;
        let src_base_value = self.coerce_address(state, &src_base.value)?;
        let dst_base = self.eval_expression(state, dst_addr, false)?;
        let dst_base_value = self.coerce_address(state, &dst_base.value)?;
        let count_eval = self.eval_expression(state, count, false)?;
        let count = self
            .concrete_bv_u64(&count_eval.value)
            .ok_or(Error::UnsupportedEffect("memory_copy with symbolic count"))?;
        let decrement_eval = self.eval_condition(state, decrement)?;
        let decrement =
            self.concrete_bool(&decrement_eval.value)
                .ok_or(Error::UnsupportedEffect(
                    "memory_copy with symbolic decrement",
                ))?;
        let backend = state.backend().clone();
        let stride = (element_bits / 8) as u64;
        for index in 0..count {
            let offset = backend.const_bv((index * stride) as u128, self.address_bits())?;
            let src = if decrement {
                src_base_value.bvsub(&offset)
            } else {
                src_base_value.bvadd(&offset)
            };
            let dst = if decrement {
                dst_base_value.bvsub(&offset)
            } else {
                dst_base_value.bvadd(&offset)
            };
            let (value, mut parents) =
                state
                    .memory()
                    .load_with_provenance(&backend, &src, element_bits)?;
            if src.as_u64().is_none() {
                parents.extend(src_base.deps.clone());
            }
            if dst.as_u64().is_none() {
                parents.extend(dst_base.deps.clone());
            }
            parents.extend(count_eval.deps.clone());
            parents.extend(decrement_eval.deps.clone());
            let def_id = state.define_location(
                instruction,
                self.format_memory_location(&dst),
                &value,
                &parents,
            );
            state.memory_mut().store_with_provenance(
                &backend,
                &dst,
                &value,
                element_bits,
                def_id,
            )?;
        }
        Ok(())
    }

    fn apply_atomic_cmpxchg(
        &self,
        state: &mut State,
        instruction: Option<&crate::semantics::InstructionEncoding>,
        addr: &SemanticExpression,
        expected: &SemanticExpression,
        desired: &SemanticExpression,
        bits: u16,
        observed: &SemanticLocation,
    ) -> Result<(), Error> {
        let address = self.eval_expression(state, addr, false)?;
        let address_value = self.coerce_address(state, &address.value)?;
        let backend = state.backend().clone();
        let (observed_value, observed_parents) =
            state
                .memory()
                .load_with_provenance(&backend, &address_value, bits)?;
        self.write_location(
            state,
            instruction,
            observed,
            crate::symbolic::expressions::EvaluatedValue {
                value: observed_value.clone(),
                deps: observed_parents.clone(),
            },
        )?;
        let expected = self.eval_expression(state, expected, false)?;
        let expected = self.concretize_if_dependency_free(state, expected)?;
        let expected_value = state.backend().coerce_bv_width(&expected.value, bits)?;
        let desired = self.eval_expression(state, desired, false)?;
        let desired = self.concretize_if_dependency_free(state, desired)?;
        let desired_value = state.backend().coerce_bv_width(&desired.value, bits)?;
        let equal = observed_value.eq(&expected_value);
        let stored = equal.ite(&desired_value, &observed_value);
        let mut parents = if address_value.as_u64().is_none() {
            address.deps
        } else {
            std::collections::BTreeSet::new()
        };
        parents.extend(observed_parents);
        parents.extend(expected.deps);
        parents.extend(desired.deps);
        let def_id = state.define_location(
            instruction,
            self.format_memory_location(&address_value),
            &stored,
            &parents,
        );
        state.memory_mut().store_with_provenance(
            &backend,
            &address_value,
            &stored,
            bits,
            def_id,
        )?;
        Ok(())
    }

    pub(crate) fn read_location(
        &self,
        state: &mut State,
        location: &SemanticLocation,
    ) -> Result<crate::symbolic::expressions::EvaluatedValue, Error> {
        match location {
            SemanticLocation::Register { name, bits } => {
                let cell = state.get_or_create_register(name, *bits)?;
                Ok(crate::symbolic::expressions::EvaluatedValue {
                    value: cell.value,
                    deps: cell.def_id.into_iter().collect(),
                })
            }
            SemanticLocation::Flag { name, bits } => {
                let cell = state.get_or_create_flag(name, *bits)?;
                Ok(crate::symbolic::expressions::EvaluatedValue {
                    value: cell.value,
                    deps: cell.def_id.into_iter().collect(),
                })
            }
            SemanticLocation::ProgramCounter { bits } => {
                let cell = state.get_or_create_program_counter(*bits)?;
                Ok(crate::symbolic::expressions::EvaluatedValue {
                    value: cell.value,
                    deps: cell.def_id.into_iter().collect(),
                })
            }
            SemanticLocation::Temporary { id, bits } => {
                let cell = state.get_or_create_temporary(*id, *bits)?;
                Ok(crate::symbolic::expressions::EvaluatedValue {
                    value: cell.value,
                    deps: cell.def_id.into_iter().collect(),
                })
            }
            SemanticLocation::Memory { addr, bits, .. } => {
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
                        return Ok(crate::symbolic::expressions::EvaluatedValue {
                            value: state.backend().const_bv(concrete as u128, *bits)?,
                            deps,
                        });
                    }
                }
                Ok(crate::symbolic::expressions::EvaluatedValue { value, deps })
            }
        }
    }

    pub(crate) fn write_location(
        &self,
        state: &mut State,
        instruction: Option<&crate::semantics::InstructionEncoding>,
        location: &SemanticLocation,
        value: crate::symbolic::expressions::EvaluatedValue,
    ) -> Result<(), Error> {
        match location {
            SemanticLocation::Register { name, bits } => {
                let coerced = state.backend().coerce_bv_width(&value.value, *bits)?;
                let def_id = state.define_location(
                    instruction,
                    format!("register:{name}"),
                    &coerced,
                    &value.deps,
                );
                state.set_register_value(name, coerced, def_id);
                Ok(())
            }
            SemanticLocation::Flag { name, bits } => {
                let coerced = state.backend().coerce_bv_width(&value.value, *bits)?;
                let def_id = state.define_location(
                    instruction,
                    format!("flag:{name}"),
                    &coerced,
                    &value.deps,
                );
                state.set_flag_value(name, coerced, def_id);
                Ok(())
            }
            SemanticLocation::ProgramCounter { bits } => {
                let coerced = state.backend().coerce_bv_width(&value.value, *bits)?;
                let def_id = state.define_location(
                    instruction,
                    "program_counter".to_string(),
                    &coerced,
                    &value.deps,
                );
                state.set_program_counter(coerced, def_id);
                Ok(())
            }
            SemanticLocation::Temporary { id, bits } => {
                let coerced = state.backend().coerce_bv_width(&value.value, *bits)?;
                let def_id = state.define_location(
                    instruction,
                    format!("temporary:{id}"),
                    &coerced,
                    &value.deps,
                );
                state.set_temporary_value(*id, coerced, def_id);
                Ok(())
            }
            SemanticLocation::Memory { addr, bits, .. } => {
                let address = self.eval_expression(state, addr, false)?;
                let address_value = self.coerce_address(state, &address.value)?;
                let coerced = state.backend().coerce_bv_width(&value.value, *bits)?;
                let mut parents = if address_value.as_u64().is_none() {
                    address.deps
                } else {
                    std::collections::BTreeSet::new()
                };
                parents.extend(value.deps);
                let def_id = state.define_location(
                    instruction,
                    self.format_memory_location(&address_value),
                    &coerced,
                    &parents,
                );
                let backend = state.backend().clone();
                state.memory_mut().store_with_provenance(
                    &backend,
                    &address_value,
                    &coerced,
                    *bits,
                    def_id,
                )
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
