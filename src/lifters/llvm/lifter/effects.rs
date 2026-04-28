use super::helpers::{
    render_address_space, render_fence_kind, render_location, render_trap_kind, sanitize_symbol,
};
use super::LoweringContext;
use crate::lifters::llvm::abi::coerce_int_value_width;
use crate::semantics::{
    InstructionSemantics, SemanticAddressSpace, SemanticEffect, SemanticExpression,
    SemanticLocation, SemanticTerminator,
};
use crate::Abi;
use std::io::Error;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    pub(super) fn lower_semantics(
        &mut self,
        semantics: &InstructionSemantics,
    ) -> Result<(), Error> {
        for effect in &semantics.effects {
            self.lower_effect(effect)?;
        }
        self.lower_terminator(&semantics.terminator)
    }

    fn lower_effect(&mut self, effect: &SemanticEffect) -> Result<(), Error> {
        match effect {
            SemanticEffect::Set { dst, expression } => match dst {
                SemanticLocation::Memory { space, addr, bits } => {
                    self.emit_store(space, addr, expression, *bits)?;
                }
                _ => {
                    let value = self.lower_expression(expression)?;
                    let value = coerce_int_value_width(
                        &self.builder,
                        value,
                        self.location_type(dst),
                        "set_dst_zext",
                        "set_dst_trunc",
                    )?;
                    let slot = self.slot_for_location(dst)?;
                    self.builder
                        .build_store(slot, value)
                        .map_err(|err| Error::other(err.to_string()))?;
                    self.written_locations.insert(render_location(dst));
                    if let SemanticLocation::Register { name, bits } = dst {
                        self.merge_partial_register_write(name, *bits, value)?;
                    }
                }
            },
            SemanticEffect::Store {
                space,
                addr,
                expression,
                bits,
            } => self.emit_store(space, addr, expression, *bits)?,
            SemanticEffect::MemorySet {
                space,
                addr,
                value,
                count,
                element_bits,
                decrement,
            } => {
                if self.try_direct_memory_set(
                    space,
                    addr,
                    value,
                    count,
                    *element_bits,
                    decrement,
                )? {
                    return Ok(());
                }
                let helper_name = format!(
                    "binlex_effect_memset_{}_{}",
                    sanitize_symbol(&render_address_space(space)),
                    element_bits
                );
                self.record_semantic_lowering(
                    "effect_helper",
                    format!(
                        "MemorySet bits={} space={} helper={}",
                        element_bits,
                        render_address_space(space),
                        helper_name
                    ),
                );
                let helper = self.declare_void_helper(
                    &helper_name,
                    &[
                        self.context.i64_type().into(),
                        self.context.i64_type().into(),
                        self.int_type(*element_bits).into(),
                        self.context.bool_type().into(),
                    ],
                    false,
                );
                let addr = self.lower_expression(addr)?;
                let addr = self.to_i64(addr);
                let count = self.lower_expression(count)?;
                let count = self.to_i64(count);
                let value = self.lower_expression(value)?;
                let decrement = self.lower_expression(decrement)?;
                let decrement = self.to_bool(decrement);
                self.builder
                    .build_call(
                        helper,
                        &[addr.into(), count.into(), value.into(), decrement.into()],
                        "",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticEffect::MemoryCopy {
                src_space,
                src_addr,
                dst_space,
                dst_addr,
                count,
                element_bits,
                decrement,
            } => {
                if self.try_direct_memory_copy(
                    src_space,
                    src_addr,
                    dst_space,
                    dst_addr,
                    count,
                    *element_bits,
                    decrement,
                )? {
                    return Ok(());
                }
                let helper_name = format!(
                    "binlex_effect_memcpy_{}_{}_{}",
                    sanitize_symbol(&render_address_space(src_space)),
                    sanitize_symbol(&render_address_space(dst_space)),
                    element_bits
                );
                self.record_semantic_lowering(
                    "effect_helper",
                    format!(
                        "MemoryCopy bits={} src_space={} dst_space={} helper={}",
                        element_bits,
                        render_address_space(src_space),
                        render_address_space(dst_space),
                        helper_name
                    ),
                );
                let helper = self.declare_void_helper(
                    &helper_name,
                    &[
                        self.context.i64_type().into(),
                        self.context.i64_type().into(),
                        self.context.i64_type().into(),
                        self.context.bool_type().into(),
                    ],
                    false,
                );
                let src_addr = self.lower_expression(src_addr)?;
                let src_addr = self.to_i64(src_addr);
                let dst_addr = self.lower_expression(dst_addr)?;
                let dst_addr = self.to_i64(dst_addr);
                let count = self.lower_expression(count)?;
                let count = self.to_i64(count);
                let decrement = self.lower_expression(decrement)?;
                let decrement = self.to_bool(decrement);
                self.builder
                    .build_call(
                        helper,
                        &[
                            src_addr.into(),
                            dst_addr.into(),
                            count.into(),
                            decrement.into(),
                        ],
                        "",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticEffect::AtomicCmpXchg {
                space,
                addr,
                expected,
                desired,
                bits,
                observed,
            } => {
                let helper_name = format!(
                    "binlex_effect_atomic_cmpxchg_{}_{}",
                    sanitize_symbol(&render_address_space(space)),
                    bits
                );
                self.record_semantic_lowering(
                    "effect_helper",
                    format!(
                        "AtomicCmpXchg bits={} space={} helper={}",
                        bits,
                        render_address_space(space),
                        helper_name
                    ),
                );
                let helper = self.declare_value_helper(
                    &helper_name,
                    self.int_type(*bits),
                    &[
                        self.context.i64_type().into(),
                        self.int_type(*bits).into(),
                        self.int_type(*bits).into(),
                    ],
                    false,
                );
                let addr = self.lower_expression(addr)?;
                let addr = self.to_i64(addr);
                let expected = self.lower_expression(expected)?;
                let desired = self.lower_expression(desired)?;
                let observed_value = self.call_value(
                    helper,
                    &[addr.into(), expected.into(), desired.into()],
                    "cmpxchg_observed",
                )?;
                let slot = self.slot_for_location(observed)?;
                self.builder
                    .build_store(slot, observed_value)
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticEffect::Fence { kind } => {
                let helper_name = format!("binlex_fence_{}", render_fence_kind(kind));
                self.record_semantic_lowering(
                    "effect_helper",
                    format!("Fence {} helper={}", render_fence_kind(kind), helper_name),
                );
                let helper = self.declare_void_helper(&helper_name, &[], false);
                self.builder
                    .build_call(helper, &[], "")
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticEffect::Trap { kind } => {
                if matches!(
                    self.current_semantics_abi,
                    Some(Abi::LinuxSyscall | Abi::WindowsSyscall)
                ) {
                    return self.lower_native_trap(kind);
                }
                let helper_name = format!("binlex_trap_{}", render_trap_kind(kind));
                self.record_semantic_lowering(
                    "effect_helper",
                    format!("Trap {} helper={}", render_trap_kind(kind), helper_name),
                );
                let helper = self.declare_void_helper(&helper_name, &[], false);
                self.builder
                    .build_call(helper, &[], "")
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticEffect::Intrinsic { name, args, .. } => {
                let helper_name = format!("binlex_effect_{}", sanitize_symbol(name));
                self.record_semantic_lowering(
                    "effect_intrinsic",
                    format!("name={} args={} helper={}", name, args.len(), helper_name),
                );
                let helper = self.declare_void_helper(&helper_name, &[], true);
                let args = self.lower_arg_values(args)?;
                self.builder
                    .build_call(helper, &args, "")
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticEffect::Nop => {}
        }
        Ok(())
    }

    fn lower_terminator(&mut self, terminator: &SemanticTerminator) -> Result<(), Error> {
        if matches!(
            self.current_semantics_abi,
            Some(Abi::LinuxSyscall | Abi::WindowsSyscall)
        ) && matches!(terminator, SemanticTerminator::Trap)
        {
            return Ok(());
        }
        if !self.emit_terminator_helpers {
            match terminator {
                SemanticTerminator::Return { expression } => {
                    if let Some(adjust) = expression.as_ref().and_then(Self::const_return_adjust) {
                        self.native_return_adjust = Some(adjust);
                    }
                }
                SemanticTerminator::Unreachable => {
                    self.builder
                        .build_unreachable()
                        .map_err(|err| Error::other(err.to_string()))?;
                }
                _ => {}
            }
            return Ok(());
        }

        match terminator {
            SemanticTerminator::FallThrough => {}
            SemanticTerminator::Jump { target } => {
                self.record_semantic_lowering("terminator_helper", "Jump helper=binlex_term_jump");
                let helper = self.declare_void_helper(
                    "binlex_term_jump",
                    &[self.context.i64_type().into()],
                    false,
                );
                let target = self.lower_expression(target)?;
                let target = self.to_i64(target);
                self.builder
                    .build_call(helper, &[target.into()], "")
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Branch {
                condition,
                true_target,
                false_target,
            } => {
                self.record_semantic_lowering(
                    "terminator_helper",
                    "Branch helper=binlex_term_branch",
                );
                let helper = self.declare_void_helper(
                    "binlex_term_branch",
                    &[
                        self.context.bool_type().into(),
                        self.context.i64_type().into(),
                        self.context.i64_type().into(),
                    ],
                    false,
                );
                let condition = self.lower_expression(condition)?;
                let condition = self.to_bool(condition);
                let true_target = self.lower_expression(true_target)?;
                let true_target = self.to_i64(true_target);
                let false_target = self.lower_expression(false_target)?;
                let false_target = self.to_i64(false_target);
                self.builder
                    .build_call(
                        helper,
                        &[condition.into(), true_target.into(), false_target.into()],
                        "",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Call {
                target,
                return_target,
                does_return,
            } => {
                self.record_semantic_lowering(
                    "terminator_helper",
                    format!(
                        "Call helper=binlex_term_call does_return={}",
                        does_return.unwrap_or(true)
                    ),
                );
                let helper = self.declare_void_helper(
                    "binlex_term_call",
                    &[
                        self.context.i64_type().into(),
                        self.context.i64_type().into(),
                        self.context.bool_type().into(),
                    ],
                    false,
                );
                let target = self.lower_expression(target)?;
                let target = self.to_i64(target);
                let return_target = return_target
                    .as_ref()
                    .map(|expr| self.lower_expression(expr))
                    .transpose()?
                    .map(|value| self.to_i64(value))
                    .unwrap_or_else(|| self.context.i64_type().const_zero());
                let does_return = self
                    .context
                    .bool_type()
                    .const_int(does_return.unwrap_or(true) as u64, false);
                self.builder
                    .build_call(
                        helper,
                        &[target.into(), return_target.into(), does_return.into()],
                        "",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Return { expression } => {
                if let Some(adjust) = expression.as_ref().and_then(Self::const_return_adjust) {
                    self.native_return_adjust = Some(adjust);
                } else if let Some(expression) = expression {
                    self.record_semantic_lowering(
                        "terminator_helper",
                        "Return helper=binlex_term_return",
                    );
                    let value = self.lower_expression(expression)?;
                    let helper = self.declare_void_helper(
                        "binlex_term_return",
                        &[value.get_type().into()],
                        false,
                    );
                    self.builder
                        .build_call(helper, &[value.into()], "")
                        .map_err(|err| Error::other(err.to_string()))?;
                }
            }
            SemanticTerminator::Unreachable => {
                self.builder
                    .build_unreachable()
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Trap => {
                self.record_semantic_lowering("terminator_helper", "Trap helper=binlex_term_trap");
                let helper = self.declare_void_helper("binlex_term_trap", &[], false);
                self.builder
                    .build_call(helper, &[], "")
                    .map_err(|err| Error::other(err.to_string()))?;
            }
        }
        Ok(())
    }

    pub(super) fn emit_store(
        &mut self,
        space: &SemanticAddressSpace,
        addr: &SemanticExpression,
        expression: &SemanticExpression,
        bits: u16,
    ) -> Result<(), Error> {
        if let Some(()) = self.try_direct_store(space, addr, expression, bits)? {
            return Ok(());
        }
        let helper = self.declare_void_helper(
            &format!(
                "binlex_store_{}_{}",
                sanitize_symbol(&render_address_space(space)),
                bits
            ),
            &[self.context.i64_type().into(), self.int_type(bits).into()],
            false,
        );
        self.record_semantic_lowering(
            "store_helper",
            format!(
                "space={} bits={} helper={}",
                render_address_space(space),
                bits,
                helper.get_name().to_string_lossy()
            ),
        );
        let addr = self.lower_expression(addr)?;
        let addr = self.to_i64(addr);
        let value = self.lower_expression(expression)?;
        let value = coerce_int_value_width(
            &self.builder,
            value,
            self.int_type(bits),
            "store_zext",
            "store_trunc",
        )?;
        self.builder
            .build_call(helper, &[addr.into(), value.into()], "")
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(())
    }
}
