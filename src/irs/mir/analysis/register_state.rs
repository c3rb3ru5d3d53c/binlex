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

use crate::irs::mir::analysis::mir_predecessors;
use crate::irs::mir::{Mir, MirOperationKind, MirValue};
use std::collections::HashMap;

pub type MirRegisterAliases = HashMap<String, MirValue>;

pub fn block_register_aliases(mir: &Mir) -> HashMap<String, MirRegisterAliases> {
    let predecessors = mir_predecessors(mir);
    let mut outgoing = HashMap::<String, MirRegisterAliases>::new();
    let mut changed = true;

    while changed {
        changed = false;

        for block in mir.blocks() {
            let incoming = incoming_aliases(&block.name, &predecessors, &outgoing);
            let mut aliases = incoming.clone();

            for operation in &block.operations {
                if let Some((result, source)) = alias_from_operation(operation) {
                    aliases.insert(result, source);
                }
            }

            if outgoing.get(&block.name) != Some(&aliases) {
                outgoing.insert(block.name.clone(), aliases);
                changed = true;
            }
        }
    }

    outgoing
}

pub fn incoming_register_aliases(mir: &Mir) -> HashMap<String, MirRegisterAliases> {
    let predecessors = mir_predecessors(mir);
    let outgoing = block_register_aliases(mir);
    mir.blocks()
        .iter()
        .map(|block| {
            (
                block.name.clone(),
                incoming_aliases(&block.name, &predecessors, &outgoing),
            )
        })
        .collect()
}

fn incoming_aliases(
    block: &str,
    predecessors: &HashMap<String, Vec<String>>,
    outgoing: &HashMap<String, MirRegisterAliases>,
) -> MirRegisterAliases {
    let Some(preds) = predecessors.get(block) else {
        return HashMap::new();
    };
    let Some((first, rest)) = preds.split_first() else {
        return HashMap::new();
    };
    let Some(first_aliases) = outgoing.get(first) else {
        return HashMap::new();
    };

    let mut shared = first_aliases.clone();
    for predecessor in rest {
        let Some(current) = outgoing.get(predecessor) else {
            shared.clear();
            break;
        };
        shared.retain(|name, value| current.get(name) == Some(value));
    }
    shared
}

fn alias_from_operation(
    operation: &crate::irs::mir::MirOperation,
) -> Option<(String, crate::irs::mir::MirValue)> {
    let result = operation.result.clone()?;
    match &operation.kind {
        MirOperationKind::Copy { value, .. } => Some((result, value.clone())),
        _ => None,
    }
}
