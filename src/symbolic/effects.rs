use crate::semantics::{SemanticEffect, SemanticExpression, SemanticLocation};
use crate::symbolic::{Error, SymbolicCpuState, SymbolicExecutor};
use z3::ast::{Ast, BV, Bool};

impl SymbolicExecutor {
    pub(crate) fn concretize_if_dependency_free(
        &self,
        state: &SymbolicCpuState,
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

    fn format_indexed_memory_location(&self, name: &str, index: &str) -> String {
        format!("indexed_memory:{name}[{index}]")
    }

    fn format_stack_memory_location(&self, name: &str, offset: u32) -> String {
        format!("stack_memory:{name}[{offset}]")
    }

    fn indexed_memory_key(&self, index: &BV) -> String {
        if let Some(index) = index.as_u64() {
            return index.to_string();
        }
        index.simplify().to_string()
    }

    pub(crate) fn symbolic_key(&self, value: &BV) -> String {
        if let Some(value) = value.as_u64() {
            return value.to_string();
        }
        value.simplify().to_string()
    }

    pub(crate) fn apply_effect(
        &self,
        state: &mut SymbolicCpuState,
        instruction: Option<&crate::semantics::SemanticEncoding>,
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
            SemanticEffect::WriteProperty {
                reference,
                name,
                expression,
                bits,
            } => {
                let reference = self.eval_expression(state, reference, false)?;
                let reference_key = self.symbolic_key(&reference.value);
                let value = self.eval_expression(state, expression, false)?;
                let value = self.concretize_if_dependency_free(state, value)?;
                let coerced = state.backend().coerce_bv_width(&value.value, *bits)?;
                let mut parents = if reference.value.as_u64().is_none() {
                    reference.deps
                } else {
                    std::collections::BTreeSet::new()
                };
                parents.extend(value.deps);
                let def_id = state.define_location(
                    instruction,
                    format!("reference:{reference_key}.{name}"),
                    &coerced,
                    &parents,
                );
                state.set_reference_property_value(reference_key, name.clone(), coerced, def_id);
                Ok(())
            }
            SemanticEffect::WriteElement {
                reference,
                index,
                expression,
                bits,
            } => {
                let reference = self.eval_expression(state, reference, false)?;
                let reference_key = self.symbolic_key(&reference.value);
                let index = self.eval_expression(state, index, false)?;
                let index_key = self.symbolic_key(&index.value);
                let value = self.eval_expression(state, expression, false)?;
                let value = self.concretize_if_dependency_free(state, value)?;
                let coerced = state.backend().coerce_bv_width(&value.value, *bits)?;
                let mut parents = if reference.value.as_u64().is_none() {
                    reference.deps
                } else {
                    std::collections::BTreeSet::new()
                };
                if index.value.as_u64().is_none() {
                    parents.extend(index.deps);
                }
                parents.extend(value.deps);
                let def_id = state.define_location(
                    instruction,
                    format!("reference:{reference_key}[{index_key}]"),
                    &coerced,
                    &parents,
                );
                state.set_reference_element_value(reference_key, index_key, coerced, def_id);
                Ok(())
            }
            SemanticEffect::Push { stack, expression } => {
                let value = self.eval_expression(state, expression, false)?;
                let value = self.concretize_if_dependency_free(state, value)?;
                let def_id = state.define_location(
                    instruction,
                    self.format_stack_memory_location(stack, 0),
                    &value.value,
                    &value.deps,
                );
                state.push_stack_memory_value(stack, value.value, def_id);
                Ok(())
            }
            SemanticEffect::Pop { stack, dst } => {
                let bits = dst.bits();
                let cell = state.pop_stack_memory_value(stack, bits)?;
                self.write_location(
                    state,
                    instruction,
                    dst,
                    crate::symbolic::expressions::EvaluatedValue {
                        value: cell.value,
                        deps: cell.def_id.into_iter().collect(),
                    },
                )
            }
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
        state: &mut SymbolicCpuState,
        instruction: Option<&crate::semantics::SemanticEncoding>,
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
            let offset = backend.const_bv(offset as u128, state.address_bits())?;
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
        state: &mut SymbolicCpuState,
        instruction: Option<&crate::semantics::SemanticEncoding>,
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
            let offset = backend.const_bv((index * stride) as u128, state.address_bits())?;
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
        state: &mut SymbolicCpuState,
        instruction: Option<&crate::semantics::SemanticEncoding>,
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
        state: &mut SymbolicCpuState,
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
            SemanticLocation::IndexedMemory { name, index, bits } => {
                let index = self.eval_expression(state, index, false)?;
                let key = self.indexed_memory_key(&index.value);
                let cell = state.get_or_create_indexed_memory(name, &key, *bits)?;
                let mut deps = cell
                    .def_id
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>();
                if index.value.as_u64().is_none() {
                    deps.extend(index.deps);
                }
                Ok(crate::symbolic::expressions::EvaluatedValue {
                    value: cell.value,
                    deps,
                })
            }
            SemanticLocation::StackMemory { name, offset, bits } => {
                let cell = state.get_or_create_stack_memory(name, *offset, *bits)?;
                Ok(crate::symbolic::expressions::EvaluatedValue {
                    value: cell.value,
                    deps: cell.def_id.into_iter().collect(),
                })
            }
        }
    }

    pub(crate) fn write_location(
        &self,
        state: &mut SymbolicCpuState,
        instruction: Option<&crate::semantics::SemanticEncoding>,
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
            SemanticLocation::IndexedMemory { name, index, bits } => {
                let index = self.eval_expression(state, index, false)?;
                let key = self.indexed_memory_key(&index.value);
                let coerced = state.backend().coerce_bv_width(&value.value, *bits)?;
                let mut parents = if index.value.as_u64().is_none() {
                    index.deps
                } else {
                    std::collections::BTreeSet::new()
                };
                parents.extend(value.deps);
                let def_id = state.define_location(
                    instruction,
                    self.format_indexed_memory_location(name, &key),
                    &coerced,
                    &parents,
                );
                state.set_indexed_memory_value(name, key, coerced, def_id);
                Ok(())
            }
            SemanticLocation::StackMemory { name, offset, bits } => {
                let coerced = state.backend().coerce_bv_width(&value.value, *bits)?;
                let def_id = state.define_location(
                    instruction,
                    self.format_stack_memory_location(name, *offset),
                    &coerced,
                    &value.deps,
                );
                state.set_stack_memory_value(name, *offset, coerced, def_id);
                Ok(())
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
