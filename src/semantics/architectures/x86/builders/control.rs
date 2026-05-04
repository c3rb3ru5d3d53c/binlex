// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::Architecture;
use crate::semantics::architectures::x86::X86InstructionView;
use crate::semantics::architectures::x86::helpers as common;
use crate::semantics::architectures::x86::{X86OperandKind, X86OperandView};
use crate::semantics::{
    InstructionSemantics, SemanticDiagnosticKind, SemanticEffect, SemanticExpression,
    SemanticLocation, SemanticTerminator,
};

pub(crate) fn build(
    machine: Architecture,
    view: &X86InstructionView,
) -> Option<InstructionSemantics> {
    if is_return(view) {
        let pointer_bits = common::pointer_bits(machine);
        let stack_pointer = stack_pointer_location(machine);
        let stack_adjust = return_stack_adjust(machine, view);
        let expression = Some(SemanticExpression::Load {
            space: crate::semantics::SemanticAddressSpace::Default,
            addr: Box::new(common::sub(
                SemanticExpression::Read(Box::new(stack_pointer.clone())),
                common::const_u64(stack_adjust, pointer_bits),
                pointer_bits,
            )),
            bits: pointer_bits,
        });
        return Some(common::complete(
            SemanticTerminator::Return { expression },
            vec![SemanticEffect::Set {
                dst: stack_pointer,
                expression: common::add(
                    SemanticExpression::Read(Box::new(stack_pointer_location(machine))),
                    common::const_u64(stack_adjust, pointer_bits),
                    pointer_bits,
                ),
            }],
        ));
    }

    if is_call(view) {
        let pointer_bits = common::pointer_bits(machine);
        let stack_pointer = stack_pointer_location(machine);
        let target = view
            .operands()
            .first()
            .and_then(|operand| operand_expr(machine, operand))
            .unwrap_or_else(|| SemanticExpression::Undefined {
                bits: common::pointer_bits(machine),
            });
        let return_target = common::const_u64(view.address + view.bytes.len() as u64, pointer_bits);
        return Some(common::complete(
            SemanticTerminator::Call {
                target,
                return_target: Some(return_target.clone()),
                does_return: Some(true),
            },
            vec![
                SemanticEffect::Set {
                    dst: stack_pointer.clone(),
                    expression: common::sub(
                        SemanticExpression::Read(Box::new(stack_pointer.clone())),
                        common::const_u64(pointer_bits as u64 / 8, pointer_bits),
                        pointer_bits,
                    ),
                },
                SemanticEffect::Store {
                    space: crate::semantics::SemanticAddressSpace::Default,
                    addr: SemanticExpression::Read(Box::new(stack_pointer)),
                    expression: return_target,
                    bits: pointer_bits,
                },
            ],
        ));
    }

    if is_setcc(view) {
        let mnemonic = view.mnemonic.as_str();
        let Some(dst) = view
            .operands()
            .first()
            .and_then(|operand| operand_location(machine, operand))
        else {
            return Some(unsupported_with_kind_from_view(
                view,
                SemanticDiagnosticKind::UnsupportedOperandForm,
                "setcc destination operand not supported",
                SemanticTerminator::FallThrough,
            ));
        };
        let Some(condition) = common::condition_from_mnemonic(mnemonic) else {
            return Some(common::partial_with_effects(
                SemanticTerminator::FallThrough,
                vec![common::diagnostic(
                    SemanticDiagnosticKind::PartialFlags,
                    format!("0x{:x}: setcc condition modeled as intrinsic", view.address),
                )],
                vec![SemanticEffect::Set {
                    dst,
                    expression: condition_intrinsic(mnemonic),
                }],
            ));
        };
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Set {
                dst,
                expression: condition,
            }],
        ));
    }

    if is_cmovcc(view) {
        let mnemonic = view.mnemonic.as_str();
        let Some(dst) = view
            .operands()
            .first()
            .and_then(|operand| operand_location(machine, operand))
        else {
            return Some(unsupported_with_kind_from_view(
                view,
                SemanticDiagnosticKind::UnsupportedOperandForm,
                "cmovcc destination operand not supported",
                SemanticTerminator::FallThrough,
            ));
        };
        let Some(when_true) = view
            .operands()
            .get(1)
            .and_then(|operand| operand_expr(machine, operand))
        else {
            return Some(unsupported_with_kind_from_view(
                view,
                SemanticDiagnosticKind::UnsupportedOperandForm,
                "cmovcc source operand not supported",
                SemanticTerminator::FallThrough,
            ));
        };
        let bits = common::location_bits(&dst);
        let when_false = SemanticExpression::Read(Box::new(dst.clone()));
        let Some(condition) = common::condition_from_mnemonic(mnemonic) else {
            return Some(common::partial_with_effects(
                SemanticTerminator::FallThrough,
                vec![common::diagnostic(
                    SemanticDiagnosticKind::PartialFlags,
                    format!(
                        "0x{:x}: cmovcc condition modeled as intrinsic",
                        view.address
                    ),
                )],
                vec![SemanticEffect::Set {
                    dst,
                    expression: SemanticExpression::Select {
                        condition: Box::new(condition_intrinsic(mnemonic)),
                        when_true: Box::new(when_true),
                        when_false: Box::new(when_false),
                        bits,
                    },
                }],
            ));
        };
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Set {
                dst,
                expression: SemanticExpression::Select {
                    condition: Box::new(condition),
                    when_true: Box::new(when_true),
                    when_false: Box::new(when_false),
                    bits,
                },
            }],
        ));
    }

    if is_conditional_jump(view) {
        let true_target = view
            .operands()
            .first()
            .and_then(|operand| operand_expr(machine, operand))
            .unwrap_or_else(|| SemanticExpression::Undefined {
                bits: common::pointer_bits(machine),
            });
        let false_target = common::const_u64(
            view.address + view.bytes.len() as u64,
            common::pointer_bits(machine),
        );
        if is_count_zero_jump(view) {
            let counter = count_zero_jump_location(view, machine);
            let counter_bits = common::location_bits(&counter);
            return Some(common::complete(
                SemanticTerminator::Branch {
                    condition: common::compare(
                        crate::semantics::SemanticOperationCompare::Eq,
                        SemanticExpression::Read(Box::new(counter)),
                        common::const_u64(0, counter_bits),
                    ),
                    true_target,
                    false_target,
                },
                Vec::new(),
            ));
        }
        let mnemonic = view.mnemonic.as_str();
        if let Some(condition) = common::condition_from_mnemonic(mnemonic) {
            return Some(common::complete(
                SemanticTerminator::Branch {
                    condition,
                    true_target,
                    false_target,
                },
                Vec::new(),
            ));
        }
        return Some(common::partial(
            SemanticTerminator::Branch {
                condition: condition_intrinsic(mnemonic),
                true_target,
                false_target,
            },
            vec![common::diagnostic(
                SemanticDiagnosticKind::PartialFlags,
                format!(
                    "0x{:x}: branch condition modeled as intrinsic",
                    view.address
                ),
            )],
        ));
    }

    if is_loop_family(view) {
        let true_target = view
            .operands()
            .first()
            .and_then(|operand| operand_expr(machine, operand))
            .unwrap_or_else(|| SemanticExpression::Undefined {
                bits: common::pointer_bits(machine),
            });
        let false_target = common::const_u64(
            view.address + view.bytes.len() as u64,
            common::pointer_bits(machine),
        );
        let counter = loop_counter_location(machine);
        let counter_bits = common::location_bits(&counter);
        let decremented_counter = common::sub(
            SemanticExpression::Read(Box::new(counter.clone())),
            common::const_u64(1, counter_bits),
            counter_bits,
        );
        let counter_nonzero = common::compare(
            crate::semantics::SemanticOperationCompare::Ne,
            SemanticExpression::Read(Box::new(counter.clone())),
            common::const_u64(0, counter_bits),
        );
        let condition = match view.mnemonic.as_str() {
            "loope" => common::and(counter_nonzero, common::flag_expr("zf"), 1),
            "loopne" => common::and(
                counter_nonzero,
                common::compare(
                    crate::semantics::SemanticOperationCompare::Eq,
                    common::flag_expr("zf"),
                    common::bool_const(false),
                ),
                1,
            ),
            _ => counter_nonzero,
        };
        return Some(common::complete(
            SemanticTerminator::Branch {
                condition,
                true_target,
                false_target,
            },
            vec![SemanticEffect::Set {
                dst: counter,
                expression: decremented_counter,
            }],
        ));
    }

    if is_jump(view) {
        let target = view
            .operands()
            .first()
            .and_then(|operand| operand_expr(machine, operand))
            .unwrap_or_else(|| SemanticExpression::Undefined {
                bits: common::pointer_bits(machine),
            });
        return Some(common::complete(
            SemanticTerminator::Jump { target },
            Vec::new(),
        ));
    }

    None
}

fn is_jump(view: &X86InstructionView) -> bool {
    matches!(view.mnemonic.as_str(), "jmp" | "ljmp")
}

fn is_conditional_jump(view: &X86InstructionView) -> bool {
    matches!(
        view.mnemonic.as_str(),
        "jae"
            | "ja"
            | "jbe"
            | "jb"
            | "jcxz"
            | "jecxz"
            | "je"
            | "jge"
            | "jg"
            | "jle"
            | "jl"
            | "jne"
            | "jno"
            | "jnp"
            | "jns"
            | "jo"
            | "jp"
            | "jrcxz"
            | "js"
    )
}

fn is_loop_family(view: &X86InstructionView) -> bool {
    matches!(view.mnemonic.as_str(), "loop" | "loope" | "loopne")
}

fn is_count_zero_jump(view: &X86InstructionView) -> bool {
    matches!(view.mnemonic.as_str(), "jcxz" | "jecxz" | "jrcxz")
}

fn count_zero_jump_location(view: &X86InstructionView, machine: Architecture) -> SemanticLocation {
    match view.mnemonic.as_str() {
        "jcxz" => common::reg("cx".to_string(), 16),
        "jecxz" => common::reg("ecx".to_string(), 32),
        "jrcxz" => common::reg("rcx".to_string(), 64),
        _ => loop_counter_location(machine),
    }
}

fn loop_counter_location(machine: Architecture) -> SemanticLocation {
    match machine {
        Architecture::AMD64 => common::reg("rcx".to_string(), 64),
        Architecture::I386 => common::reg("ecx".to_string(), 32),
        _ => common::reg("cx".to_string(), 16),
    }
}

fn is_call(view: &X86InstructionView) -> bool {
    matches!(view.mnemonic.as_str(), "call" | "lcall")
}

fn is_return(view: &X86InstructionView) -> bool {
    matches!(view.mnemonic.as_str(), "ret" | "retf")
}

fn stack_pointer_location(machine: Architecture) -> SemanticLocation {
    match machine {
        Architecture::AMD64 => common::reg("rsp", 64),
        Architecture::I386 => common::reg("esp", 32),
        _ => common::reg("rsp", 64),
    }
}

fn return_stack_adjust(machine: Architecture, view: &X86InstructionView) -> u64 {
    let base = (common::pointer_bits(machine) / 8) as u64;
    let immediate = view
        .operands()
        .first()
        .and_then(|operand| operand.immediate_value())
        .unwrap_or(0);
    base + immediate as i64 as u64
}

fn is_setcc(view: &X86InstructionView) -> bool {
    view.mnemonic.starts_with("set")
}

fn is_cmovcc(view: &X86InstructionView) -> bool {
    view.mnemonic.starts_with("cmov")
}

fn operand_expr(machine: Architecture, operand: &X86OperandView) -> Option<SemanticExpression> {
    match operand.kind {
        X86OperandKind::Register => Some(SemanticExpression::Read(Box::new(common::reg(
            operand.register_name()?,
            operand.size_bits,
        )))),
        X86OperandKind::Immediate => Some(SemanticExpression::Const {
            value: operand.immediate_value()? as i128 as u128,
            bits: operand.size_bits,
        }),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    SemanticExpression::Read(Box::new(common::reg(
                        name,
                        common::pointer_bits(machine),
                    ))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(SemanticExpression::Load {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}

fn operand_location(machine: Architecture, operand: &X86OperandView) -> Option<SemanticLocation> {
    match operand.kind {
        X86OperandKind::Register => Some(common::reg(operand.register_name()?, operand.size_bits)),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    SemanticExpression::Read(Box::new(common::reg(
                        name,
                        common::pointer_bits(machine),
                    ))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(SemanticLocation::Memory {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}

fn condition_intrinsic(mnemonic: &str) -> SemanticExpression {
    SemanticExpression::Intrinsic {
        name: format!("x86.condition.{mnemonic}"),
        args: Vec::new(),
        bits: 1,
    }
}

fn unsupported_with_kind_from_view(
    view: &X86InstructionView,
    kind: SemanticDiagnosticKind,
    message: &str,
    terminator: SemanticTerminator,
) -> InstructionSemantics {
    common::partial(
        terminator,
        vec![common::diagnostic(
            kind,
            format!("0x{:x}: {} ({})", view.address, message, view.mnemonic),
        )],
    )
}
