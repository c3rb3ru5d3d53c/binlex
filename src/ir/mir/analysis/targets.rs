use crate::ir::mir::Mir;
use crate::ir::mir::analysis::mir_successors;

pub fn validate_targets(mir: &Mir) -> Result<(), String> {
    let names = mir
        .blocks()
        .iter()
        .map(|block| block.name.as_str())
        .collect::<std::collections::HashSet<_>>();
    for (source, targets) in mir_successors(mir) {
        for target in targets {
            if !names.contains(target.as_str()) {
                return Err(format!("block {source} targets missing block {target}"));
            }
        }
    }
    Ok(())
}
