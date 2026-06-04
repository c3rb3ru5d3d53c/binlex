use crate::irs::mir::analysis::{reachable_blocks, validate_targets};
use crate::irs::mir::{Mir, MirTerminator, MirValue};

pub fn optimize_targets(mir: &mut Mir) {
    for block in mir.blocks_mut() {
        if let Some(terminator) = block.terminator.as_mut() {
            simplify_terminator(terminator);
        }
    }

    let reachable = reachable_blocks(mir);
    mir.blocks_mut()
        .retain(|block| reachable.contains(block.name.as_str()));
}

pub fn verify_targets(mir: &Mir) -> Result<(), String> {
    validate_targets(mir)
}

fn simplify_terminator(terminator: &mut MirTerminator) {
    if let MirTerminator::CondBr {
        condition,
        then_target,
        then_arguments,
        else_target,
        else_arguments,
    } = terminator
    {
        let jump = match condition {
            MirValue::Boolean(true) => Some(MirTerminator::Jump {
                target: then_target.clone(),
                arguments: then_arguments.clone(),
            }),
            MirValue::Boolean(false) => Some(MirTerminator::Jump {
                target: else_target.clone(),
                arguments: else_arguments.clone(),
            }),
            MirValue::Integer { value, .. } if *value == 0 => Some(MirTerminator::Jump {
                target: else_target.clone(),
                arguments: else_arguments.clone(),
            }),
            MirValue::Integer { value, .. } if *value != 0 => Some(MirTerminator::Jump {
                target: then_target.clone(),
                arguments: then_arguments.clone(),
            }),
            _ => None,
        };

        if let Some(jump) = jump {
            *terminator = jump;
        }
    }
}
