use crate::ir::mir::{Mir, MirTerminator};
use std::collections::HashMap;

pub fn optimize_branches(mir: &mut Mir) {
    loop {
        let trivial_jumps = trivial_jump_targets(mir);
        let mut changed = false;

        for block in mir.blocks_mut() {
            let Some(terminator) = block.terminator.as_mut() else {
                continue;
            };

            match terminator {
                MirTerminator::Jump { target, arguments } => {
                    if arguments.is_empty() {
                        if let Some((new_target, new_arguments)) =
                            trivial_jumps.get(target).cloned()
                        {
                            *target = new_target;
                            *arguments = new_arguments;
                            changed = true;
                        }
                    }
                }
                MirTerminator::CondBr {
                    then_target,
                    then_arguments,
                    else_target,
                    else_arguments,
                    ..
                } => {
                    if then_target == else_target && then_arguments == else_arguments {
                        *terminator = MirTerminator::Jump {
                            target: then_target.clone(),
                            arguments: then_arguments.clone(),
                        };
                        changed = true;
                        continue;
                    }

                    if then_arguments.is_empty() {
                        if let Some((new_target, new_arguments)) =
                            trivial_jumps.get(then_target).cloned()
                        {
                            *then_target = new_target;
                            *then_arguments = new_arguments;
                            changed = true;
                        }
                    }
                    if else_arguments.is_empty() {
                        if let Some((new_target, new_arguments)) =
                            trivial_jumps.get(else_target).cloned()
                        {
                            *else_target = new_target;
                            *else_arguments = new_arguments;
                            changed = true;
                        }
                    }
                }
                MirTerminator::Return { .. } | MirTerminator::Trap | MirTerminator::Unreachable => {
                }
            }
        }

        if !changed {
            break;
        }
    }
}

fn trivial_jump_targets(mir: &Mir) -> HashMap<String, (String, Vec<crate::ir::mir::MirValue>)> {
    let mut map = HashMap::new();
    for block in mir.blocks() {
        if !block.parameters.is_empty() || !block.operations.is_empty() {
            continue;
        }
        let Some(MirTerminator::Jump { target, arguments }) = block.terminator.as_ref() else {
            continue;
        };
        map.insert(block.name.clone(), (target.clone(), arguments.clone()));
    }
    map
}
