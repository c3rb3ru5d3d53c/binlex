use super::*;

pub(crate) fn build_structured_load(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    register_count: usize,
) -> Option<InstructionSemantics> {
    let destinations = operands
        .iter()
        .take(register_count)
        .map(|operand| operand_location(machine, operand))
        .collect::<Option<Vec<_>>>()?;
    let memory_operand = operands.get(register_count)?;
    let writeback_operand = operands.get(register_count + 1);
    let base_addr = effective_memory_address(instruction, memory_operand, writeback_operand)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
    let lane_bytes = (lane_bits / 8) as u64;

    let mut effects = Vec::with_capacity(register_count + 1);
    for (register_index, dst) in destinations.into_iter().enumerate() {
        let dst_bits = location_bits(&dst);
        let parts = (0..lane_count)
            .rev()
            .map(|lane| {
                let offset =
                    ((lane as usize * register_count) + register_index) as u64 * lane_bytes;
                let addr = binary(
                    SemanticOperationBinary::Add,
                    base_addr.clone(),
                    const_u64(offset, 64),
                    64,
                );
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(addr),
                    bits: lane_bits,
                }
            })
            .collect::<Vec<_>>();
        let arrangement_bits = lane_count * lane_bits;
        effects.push(SemanticEffect::Set {
            dst,
            expression: zero_extend_if_needed(
                SemanticExpression::Concat {
                    parts,
                    bits: arrangement_bits,
                },
                arrangement_bits,
                dst_bits,
            ),
        });
    }

    if let Some(writeback) = writeback_effect(instruction, memory_operand, writeback_operand) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}
