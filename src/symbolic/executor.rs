use crate::semantics::{Semantic, SemanticStatus, SemanticTerminator, Semantics};
use crate::symbolic::Error;
use crate::symbolic::SymbolicCpuState;
use std::collections::{BTreeSet, HashMap};

#[derive(Clone)]
pub struct SymbolicExecutor {
    breakpoints: BTreeSet<u64>,
    hooks: BTreeSet<u64>,
}

impl SymbolicExecutor {
    pub fn new() -> Self {
        Self {
            breakpoints: BTreeSet::new(),
            hooks: BTreeSet::new(),
        }
    }

    pub fn set_breakpoint(&mut self, address: u64) {
        self.breakpoints.insert(address);
    }

    pub fn remove_breakpoint(&mut self, address: u64) {
        self.breakpoints.remove(&address);
    }

    pub fn clear_breakpoints(&mut self) {
        self.breakpoints.clear();
    }

    pub fn breakpoints(&self) -> Vec<u64> {
        self.breakpoints.iter().copied().collect()
    }

    pub fn add_hook(&mut self, address: u64) {
        self.hooks.insert(address);
    }

    pub fn remove_hook(&mut self, address: u64) {
        self.hooks.remove(&address);
    }

    pub fn clear_hooks(&mut self) {
        self.hooks.clear();
    }

    pub fn hooks(&self) -> Vec<u64> {
        self.hooks.iter().copied().collect()
    }

    pub fn step(
        &self,
        semantics: &Semantics,
        state: &SymbolicCpuState,
    ) -> Result<Vec<SymbolicCpuState>, Error> {
        if semantics.semantics.is_empty() {
            return Ok(vec![state.clone()]);
        }
        let (semantics, working, _, start_index) =
            self.prepare_state_and_semantics(semantics.clone(), state)?;
        self.step_instruction(&semantics.semantics[start_index], &working)
    }

    pub fn run(
        &self,
        semantics: &Semantics,
        state: &SymbolicCpuState,
        steps: Option<usize>,
    ) -> Result<Vec<SymbolicCpuState>, Error> {
        let (semantics, initial_state, address_to_index, start_index) =
            self.prepare_state_and_semantics(semantics.clone(), state)?;
        let semantics = semantics.semantics.iter().collect::<Vec<_>>();
        if semantics.is_empty() {
            return Ok(vec![state.clone()]);
        }
        let mut active_states = vec![(start_index, initial_state, steps)];
        let mut final_states = Vec::new();

        while !active_states.is_empty() {
            let mut next_states = Vec::new();
            for (index, live, remaining_steps) in active_states {
                let instruction = semantics[index];
                if let Some(address) = instruction
                    .encoding
                    .as_ref()
                    .map(|encoding| encoding.address)
                {
                    if self.breakpoints.contains(&address) || self.hooks.contains(&address) {
                        final_states.push(live);
                        continue;
                    }
                }

                if remaining_steps == Some(0) {
                    final_states.push(live);
                    continue;
                }

                let previous_pc = live.eval_program_counter_u64()?;
                let mut stepped = Vec::new();
                for candidate in self.step_instruction(instruction, &live)? {
                    if candidate.satisfiable()? {
                        stepped.push(candidate);
                    }
                }
                let next_remaining_steps = remaining_steps.map(|value| value.saturating_sub(1));

                if stepped.is_empty() {
                    continue;
                }

                if stepped.len() > 1 {
                    final_states.extend(stepped);
                    continue;
                }

                let successor = stepped.pop().expect("single satisfiable successor");
                let next_index = self.resolve_successor_index(
                    &semantics,
                    &address_to_index,
                    index,
                    previous_pc,
                    &successor,
                )?;
                if let Some(next_index) = next_index {
                    next_states.push((next_index, successor, next_remaining_steps));
                } else {
                    final_states.push(successor);
                }
            }
            active_states = next_states;
        }

        Ok(final_states)
    }

    fn resolve_successor_index(
        &self,
        semantics: &[&Semantic],
        address_to_index: &HashMap<u64, usize>,
        current_index: usize,
        previous_pc: Option<u64>,
        successor: &SymbolicCpuState,
    ) -> Result<Option<usize>, Error> {
        let current = semantics[current_index];
        let current_pc = successor.eval_program_counter_u64()?;
        let sequential_next = (current_index + 1 < semantics.len()).then_some(current_index + 1);

        let follow_concrete_target = |address: u64| address_to_index.get(&address).copied();

        match &current.terminator {
            SemanticTerminator::FallThrough => {
                if current_pc != previous_pc {
                    if let Some(address) = current_pc {
                        return Ok(follow_concrete_target(address));
                    }
                }
                Ok(sequential_next)
            }
            SemanticTerminator::Return { expression } => {
                if expression.is_none() {
                    return Ok(None);
                }
                Ok(current_pc.and_then(follow_concrete_target))
            }
            SemanticTerminator::Jump { .. }
            | SemanticTerminator::Branch { .. }
            | SemanticTerminator::Call { .. } => Ok(current_pc.and_then(follow_concrete_target)),
            SemanticTerminator::Trap | SemanticTerminator::Unreachable => Ok(None),
        }
    }

    fn prepare_state_and_semantics(
        &self,
        semantics: Semantics,
        state: &SymbolicCpuState,
    ) -> Result<(Semantics, SymbolicCpuState, HashMap<u64, usize>, usize), Error> {
        let mut working_state = state.clone();
        working_state.load_semantic_data(&semantics.data)?;
        let mut address_to_index = HashMap::new();
        for (index, instruction) in semantics.semantics.iter().enumerate() {
            if let Some(encoding) = instruction.encoding.as_ref() {
                address_to_index.entry(encoding.address).or_insert(index);
            }
        }
        let start_index = working_state
            .eval_program_counter_u64()?
            .and_then(|address| address_to_index.get(&address).copied())
            .unwrap_or(0);
        Ok((semantics, working_state, address_to_index, start_index))
    }

    fn step_instruction(
        &self,
        semantics: &Semantic,
        state: &SymbolicCpuState,
    ) -> Result<Vec<SymbolicCpuState>, Error> {
        if !matches!(semantics.status, SemanticStatus::Complete) {
            return Err(Error::UnsupportedExpression(
                "partial instruction semantics are not executable",
            ));
        }
        let mut working = state.clone();
        for effect in &semantics.effects {
            self.apply_effect(&mut working, semantics.encoding.as_ref(), effect)?;
        }
        self.apply_terminator(working, semantics.encoding.as_ref(), &semantics.terminator)
    }
}

#[cfg(test)]
mod tests {
    use super::SymbolicCpuState;
    use super::SymbolicExecutor;
    use crate::Architecture;
    use crate::Configuration;
    use crate::assemblers::{Assembler, AssemblerBackend};
    use crate::controlflow::Graph;
    use crate::disassemblers::capstone::Disassembler;
    use crate::formats::Image;
    use crate::semantics::{
        Semantic, SemanticAddressSpace, SemanticCpu, SemanticData, SemanticEffect,
        SemanticEncoding, SemanticExpression, SemanticLocation, SemanticOperationBinary,
        SemanticOperationCast, SemanticOperationCompare, SemanticOperationUnary, SemanticStatus,
        SemanticTerminator, Semantics,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Cursor;

    fn assembled_semantics(architecture: Architecture, assembly: &str) -> Vec<Semantic> {
        let config = Configuration::default();
        let assembler = Assembler::new(architecture, config.clone(), AssemblerBackend::Default)
            .expect("assembler");
        let bytes = assembler.assemble(0, assembly).expect("assemble");
        let mut ranges = BTreeMap::new();
        ranges.insert(0, bytes.len() as u64);
        let disassembler = Disassembler::from_bytes(architecture, &bytes, ranges, config.clone())
            .expect("disassembler");
        let mut graph = Graph::new(architecture, config);
        let mut entrypoints = BTreeSet::new();
        entrypoints.insert(0);
        disassembler
            .disassemble(entrypoints, &mut graph)
            .expect("disassemble");
        let mut instructions = graph.instructions();
        instructions.sort_by_key(|instruction| instruction.address);
        instructions
            .into_iter()
            .map(|instruction| {
                instruction
                    .semantics
                    .clone()
                    .expect("instruction semantics")
            })
            .collect()
    }

    fn semantics_of(semantic: Semantic) -> Semantics {
        Semantics {
            semantics: vec![semantic],
            data: Vec::new(),
        }
    }

    fn semantics_many(semantics: Vec<Semantic>) -> Semantics {
        Semantics {
            semantics,
            data: Vec::new(),
        }
    }

    #[test]
    fn symbolic_branch_forks() {
        let executor = SymbolicExecutor::new();
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::ARM64).expect("cpu"),
        );
        state
            .symbolize_register("x0", 64, Some("input_x0"))
            .expect("symbolize register");

        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::Branch {
                condition: SemanticExpression::Compare {
                    op: SemanticOperationCompare::Eq,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x0".to_string(),
                            bits: 64,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Const { value: 0, bits: 64 }),
                    bits: 1,
                },
                true_target: SemanticExpression::Const {
                    value: 0x1000,
                    bits: 64,
                },
                false_target: SemanticExpression::Const {
                    value: 0x2000,
                    bits: 64,
                },
            },
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        assert_eq!(states.len(), 2);
        assert!(
            states
                .iter()
                .all(|state| state.satisfiable().expect("sat check"))
        );
        let targets = states
            .iter()
            .map(|state| {
                state
                    .evaluate_register("pc", 64)
                    .expect("evaluate ip register")
                    .expect("concrete ip register")
            })
            .collect::<Vec<_>>();
        assert!(targets.contains(&0x1000));
        assert!(targets.contains(&0x2000));
    }

    #[test]
    fn symbolic_semantics_data_supports_step_and_run() {
        let executor = SymbolicExecutor::new();
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu"),
        );
        state.set_register("rdi", 64, 2).expect("set register");

        let body = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::ZeroExtend,
                    arg: Box::new(SemanticExpression::Load {
                        space: SemanticAddressSpace::Global,
                        addr: Box::new(SemanticExpression::Binary {
                            op: SemanticOperationBinary::Add,
                            left: Box::new(SemanticExpression::DataAddress {
                                name: "digits".to_string(),
                                bits: 64,
                            }),
                            right: Box::new(SemanticExpression::Read(Box::new(
                                SemanticLocation::Register {
                                    name: "rdi".to_string(),
                                    bits: 64,
                                },
                            ))),
                            bits: 64,
                        }),
                        bits: 8,
                    }),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::Return { expression: None },
            diagnostics: Vec::new(),
        };
        let semantics = Semantics {
            semantics: vec![body],
            data: vec![SemanticData {
                name: "digits".to_string(),
                bytes: b"0123456789".to_vec(),
            }],
        };

        let step_states = executor.step(&semantics, &state).expect("step");
        let step_state = step_states.first().expect("step state");
        assert_eq!(
            step_state
                .evaluate_register("rax", 64)
                .expect("evaluate register"),
            Some(u64::from(b'2'))
        );

        let run_states = executor.run(&semantics, &state, None).expect("run");
        let run_state = run_states.first().expect("run state");
        assert_eq!(
            run_state
                .evaluate_register("rax", 64)
                .expect("evaluate register"),
            Some(u64::from(b'2'))
        );
    }

    #[test]
    fn symbolic_map_image_reads_global_bytes_without_preload_copy() {
        let executor = SymbolicExecutor::new();
        let state_cpu = SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu");
        let mut state = SymbolicCpuState::new(state_cpu);

        let temp_path = std::env::temp_dir().join(format!(
            "binlex-symbolic-map-image-{}-{}.img",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let mut image = Image::new(temp_path.clone(), false).expect("image");
        image.set_base(0x1000);
        image.write_padding(0x2000).expect("padding");
        image.seek(0x234).expect("seek");
        image
            .write(Cursor::new([0x41u8, 0x42u8, 0x43u8, 0x44u8]))
            .expect("write bytes");

        state.map_image(&image);

        let semantics = Semantics {
            semantics: vec![Semantic {
                version: 1,
                status: SemanticStatus::Complete,
                abi: None,
                encoding: None,
                temporaries: Vec::new(),
                effects: vec![SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "rax".to_string(),
                        bits: 32,
                    },
                    expression: SemanticExpression::Load {
                        space: SemanticAddressSpace::Global,
                        addr: Box::new(SemanticExpression::Const {
                                    value: 0x1234,
                            bits: 64,
                        }),
                        bits: 32,
                    },
                }],
                terminator: SemanticTerminator::Return { expression: None },
                diagnostics: Vec::new(),
            }],
            data: Vec::new(),
        };

        let states = executor.run(&semantics, &state, None).expect("run");
        let state = states.first().expect("state");
        assert_eq!(
            state.evaluate_register("rax", 32).expect("rax"),
            Some(0x4443_4241)
        );
    }

    #[test]
    fn symbolic_memory_store_then_load() {
        let executor = SymbolicExecutor::new();
        let state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu"),
        );

        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Store {
                    space: crate::semantics::SemanticAddressSpace::Default,
                    addr: SemanticExpression::Const {
                        value: 0x3000,
                        bits: 64,
                    },
                    expression: SemanticExpression::Const {
                        value: 0x41,
                        bits: 8,
                    },
                    bits: 8,
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "rax".to_string(),
                        bits: 8,
                    },
                    expression: SemanticExpression::Load {
                        space: crate::semantics::SemanticAddressSpace::Default,
                        addr: Box::new(SemanticExpression::Const {
                            value: 0x3000,
                            bits: 64,
                        }),
                        bits: 8,
                    },
                },
            ],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        let value = states[0]
            .evaluate_register("rax", 8)
            .expect("evaluate register")
            .expect("concrete register");
        assert_eq!(value, 0x41);
    }

    #[test]
    fn symbolic_indexed_memory_store_then_read() {
        let executor = SymbolicExecutor::new();
        let state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));

        let location = SemanticLocation::IndexedMemory {
            name: "locals".to_string(),
            index: Box::new(SemanticExpression::Const { value: 2, bits: 32 }),
            bits: 32,
        };
        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: location.clone(),
                    expression: SemanticExpression::Const {
                        value: 0x41424344,
                        bits: 32,
                    },
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    },
                    expression: SemanticExpression::Read(Box::new(location)),
                },
            ],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        let value = states[0]
            .evaluate_register("eax", 32)
            .expect("evaluate register")
            .expect("concrete register");
        assert_eq!(value, 0x41424344);
    }

    #[test]
    fn symbolic_stack_memory_store_then_read() {
        let executor = SymbolicExecutor::new();
        let state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));

        let location = SemanticLocation::StackMemory {
            name: "value_stack".to_string(),
            offset: 0,
            bits: 32,
        };
        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: location.clone(),
                    expression: SemanticExpression::Const {
                        value: 0x11223344,
                        bits: 32,
                    },
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    },
                    expression: SemanticExpression::Read(Box::new(location)),
                },
            ],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        let value = states[0]
            .evaluate_register("eax", 32)
            .expect("evaluate register")
            .expect("concrete register");
        assert_eq!(value, 0x11223344);
    }

    #[test]
    fn symbolic_stack_push_and_pop_execute() {
        let executor = SymbolicExecutor::new();
        let state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));

        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Push {
                    stack: "value_stack".to_string(),
                    expression: SemanticExpression::Const { value: 1, bits: 32 },
                },
                SemanticEffect::Push {
                    stack: "value_stack".to_string(),
                    expression: SemanticExpression::Const { value: 2, bits: 32 },
                },
                SemanticEffect::Pop {
                    stack: "value_stack".to_string(),
                    dst: SemanticLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    },
                },
                SemanticEffect::Pop {
                    stack: "value_stack".to_string(),
                    dst: SemanticLocation::Register {
                        name: "ebx".to_string(),
                        bits: 32,
                    },
                },
            ],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("eax", 32)
                .expect("evaluate eax")
                .expect("concrete eax"),
            2
        );
        assert_eq!(
            states[0]
                .evaluate_register("ebx", 32)
                .expect("evaluate ebx")
                .expect("concrete ebx"),
            1
        );
    }

    #[test]
    fn symbolic_reference_property_write_then_read() {
        let executor = SymbolicExecutor::new();
        let state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::CIL).expect("cpu"));

        let object = SemanticExpression::Allocate {
            kind: "object".to_string(),
            bits: 64,
        };
        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Temporary { id: 0, bits: 64 },
                    expression: object,
                },
                SemanticEffect::WriteProperty {
                    reference: SemanticExpression::Read(Box::new(SemanticLocation::Temporary {
                        id: 0,
                        bits: 64,
                    })),
                    name: "length".to_string(),
                    expression: SemanticExpression::Const { value: 7, bits: 32 },
                    bits: 32,
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "pc".to_string(),
                        bits: 32,
                    },
                    expression: SemanticExpression::ReadProperty {
                        reference: Box::new(SemanticExpression::Read(Box::new(
                            SemanticLocation::Temporary { id: 0, bits: 64 },
                        ))),
                        name: "length".to_string(),
                        bits: 32,
                    },
                },
            ],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("pc", 32)
                .expect("evaluate pc")
                .expect("concrete pc"),
            7
        );
    }

    #[test]
    fn symbolic_reference_element_write_then_read() {
        let executor = SymbolicExecutor::new();
        let state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::CIL).expect("cpu"));

        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Temporary { id: 0, bits: 64 },
                    expression: SemanticExpression::Allocate {
                        kind: "array".to_string(),
                        bits: 64,
                    },
                },
                SemanticEffect::WriteElement {
                    reference: SemanticExpression::Read(Box::new(SemanticLocation::Temporary {
                        id: 0,
                        bits: 64,
                    })),
                    index: SemanticExpression::Const { value: 3, bits: 32 },
                    expression: SemanticExpression::Const {
                        value: 0x55,
                        bits: 8,
                    },
                    bits: 8,
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "pc".to_string(),
                        bits: 8,
                    },
                    expression: SemanticExpression::ReadElement {
                        reference: Box::new(SemanticExpression::Read(Box::new(
                            SemanticLocation::Temporary { id: 0, bits: 64 },
                        ))),
                        index: Box::new(SemanticExpression::Const { value: 3, bits: 32 }),
                        bits: 8,
                    },
                },
            ],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("pc", 8)
                .expect("evaluate pc")
                .expect("concrete pc"),
            0x55
        );
    }

    #[test]
    fn symbolic_state_read_memory_returns_concrete_bytes() {
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu"),
        );
        state.map_memory(0x5000, 4);
        state
            .write_memory(0x5000, &[0x44, 0x33, 0x22, 0x11])
            .expect("write memory");

        let bytes = state
            .read_memory(0x5000, 4)
            .expect("read memory")
            .expect("concrete bytes");
        assert_eq!(bytes, vec![0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn symbolic_unary_popcount_executes() {
        let executor = SymbolicExecutor::new();
        let state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::ARM64).expect("cpu"),
        );
        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x0".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Unary {
                    op: SemanticOperationUnary::PopCount,
                    arg: Box::new(SemanticExpression::Const {
                        value: 0b1011,
                        bits: 64,
                    }),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("x0", 64)
                .expect("eval register")
                .expect("concrete value"),
            3
        );
    }

    #[test]
    fn symbolic_mul_high_executes() {
        let executor = SymbolicExecutor::new();
        let state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::ARM64).expect("cpu"),
        );
        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x0".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::UMulHigh,
                    left: Box::new(SemanticExpression::Const {
                        value: u64::MAX as u128,
                        bits: 64,
                    }),
                    right: Box::new(SemanticExpression::Const { value: 2, bits: 64 }),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("x0", 64)
                .expect("eval register")
                .expect("concrete value"),
            1
        );
    }

    #[test]
    fn partial_semantics_are_rejected() {
        let executor = SymbolicExecutor::new();
        let state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu"),
        );
        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Partial,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        assert!(executor.step(&semantics_of(semantics), &state).is_err());
    }

    #[test]
    fn symbolic_trace_run_executes() {
        let executor = SymbolicExecutor::new();
        let state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu"),
        );
        let first = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Const { value: 7, bits: 64 },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let second = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "rbx".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::Add,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "rax".to_string(),
                            bits: 64,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Const { value: 5, bits: 64 }),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::Jump {
                target: SemanticExpression::Const {
                    value: 0x401000,
                    bits: 64,
                },
            },
            diagnostics: Vec::new(),
        };
        let states = executor
            .run(&semantics_many(vec![first, second]), &state, None)
            .expect("run");
        assert_eq!(states.len(), 1);
        assert_eq!(
            states[0]
                .evaluate_register("rbx", 64)
                .expect("eval register")
                .expect("concrete value"),
            12
        );
        assert_eq!(
            states[0]
                .eval_program_counter_u64()
                .expect("eval program counter")
                .expect("concrete pc"),
            0x401000
        );
    }

    #[test]
    fn symbolic_run_follows_concrete_control_flow() {
        let executor = SymbolicExecutor::new();
        let state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        let setup = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "i386".to_string(),
                mnemonic: "mov".to_string(),
                disassembly: "mov ecx, 3".to_string(),
                address: 0x1000,
                bytes: vec![0xb9, 0x03, 0x00, 0x00, 0x00],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "ecx".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Const { value: 3, bits: 32 },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let loop_body = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "i386".to_string(),
                mnemonic: "dec".to_string(),
                disassembly: "dec ecx".to_string(),
                address: 0x1005,
                bytes: vec![0x49],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "ecx".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::Sub,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "ecx".to_string(),
                            bits: 32,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Const { value: 1, bits: 32 }),
                    bits: 32,
                },
            }],
            terminator: SemanticTerminator::Branch {
                condition: SemanticExpression::Compare {
                    op: SemanticOperationCompare::Eq,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "ecx".to_string(),
                            bits: 32,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Const { value: 0, bits: 32 }),
                    bits: 1,
                },
                true_target: SemanticExpression::Const {
                    value: 0x1006,
                    bits: 32,
                },
                false_target: SemanticExpression::Const {
                    value: 0x1005,
                    bits: 32,
                },
            },
            diagnostics: Vec::new(),
        };
        let exit = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "i386".to_string(),
                mnemonic: "mov".to_string(),
                disassembly: "mov eax, 0x41".to_string(),
                address: 0x1006,
                bytes: vec![0xb8, 0x41, 0x00, 0x00, 0x00],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Const {
                    value: 0x41,
                    bits: 32,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![setup, loop_body, exit]), &state, None)
            .expect("run");
        assert_eq!(states.len(), 1);
        assert_eq!(
            states[0]
                .evaluate_register("ecx", 32)
                .expect("eval register")
                .expect("concrete value"),
            0
        );
        assert_eq!(
            states[0]
                .evaluate_register("eax", 32)
                .expect("eval register")
                .expect("concrete value"),
            0x41
        );
    }

    #[test]
    fn symbolic_run_stops_at_non_concrete_control_flow() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state
            .symbolize_register("eax", 32, Some("input_eax"))
            .expect("symbolize register");

        let branch = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "i386".to_string(),
                mnemonic: "jne".to_string(),
                disassembly: "jne 0x1005".to_string(),
                address: 0x1000,
                bytes: vec![0x75, 0x03],
            }),
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::Branch {
                condition: SemanticExpression::Compare {
                    op: SemanticOperationCompare::Eq,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Const { value: 0, bits: 32 }),
                    bits: 1,
                },
                true_target: SemanticExpression::Const {
                    value: 0x1002,
                    bits: 32,
                },
                false_target: SemanticExpression::Const {
                    value: 0x1005,
                    bits: 32,
                },
            },
            diagnostics: Vec::new(),
        };
        let taken = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "i386".to_string(),
                mnemonic: "mov".to_string(),
                disassembly: "mov ebx, 1".to_string(),
                address: 0x1002,
                bytes: vec![0xbb, 0x01, 0x00, 0x00, 0x00],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "ebx".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Const { value: 1, bits: 32 },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let not_taken = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "i386".to_string(),
                mnemonic: "mov".to_string(),
                disassembly: "mov ebx, 2".to_string(),
                address: 0x1005,
                bytes: vec![0xbb, 0x02, 0x00, 0x00, 0x00],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "ebx".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Const { value: 2, bits: 32 },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![branch, taken, not_taken]), &state, None)
            .expect("run");
        assert_eq!(states.len(), 2);
        let targets = states
            .iter()
            .map(|state| {
                state
                    .eval_program_counter_u64()
                    .expect("eval program counter")
                    .expect("concrete pc")
            })
            .collect::<Vec<_>>();
        assert!(targets.contains(&0x1002));
        assert!(targets.contains(&0x1005));
        for state in states {
            assert_eq!(
                state.evaluate_register("ebx", 32).expect("eval register"),
                None
            );
        }
    }

    #[test]
    fn symbolic_run_honors_step_budget() {
        let executor = SymbolicExecutor::new();
        let state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu"),
        );
        let first = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "mov".to_string(),
                disassembly: "mov rax, 7".to_string(),
                address: 0x401000,
                bytes: vec![0x48, 0xc7, 0xc0, 0x07, 0x00, 0x00, 0x00],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Const { value: 7, bits: 64 },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let second = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "mov".to_string(),
                disassembly: "mov rbx, 9".to_string(),
                address: 0x401001,
                bytes: vec![0x48, 0xc7, 0xc3, 0x09, 0x00, 0x00, 0x00],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "rbx".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Const { value: 9, bits: 64 },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![first, second]), &state, Some(1))
            .expect("run");
        assert_eq!(states.len(), 1);
        assert_eq!(
            states[0]
                .evaluate_register("rax", 64)
                .expect("eval register")
                .expect("concrete value"),
            7
        );
        assert_eq!(
            states[0]
                .evaluate_register("rbx", 64)
                .expect("eval register"),
            None
        );
    }

    #[test]
    fn symbolic_run_stops_at_breakpoint_before_execution() {
        let mut executor = SymbolicExecutor::new();
        executor.set_breakpoint(0x401001);
        let state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu"),
        );
        let first = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "mov".to_string(),
                disassembly: "mov rax, 7".to_string(),
                address: 0x401000,
                bytes: vec![0x48, 0xc7, 0xc0, 0x07, 0x00, 0x00, 0x00],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Const { value: 7, bits: 64 },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let second = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "mov".to_string(),
                disassembly: "mov rbx, 9".to_string(),
                address: 0x401001,
                bytes: vec![0x48, 0xc7, 0xc3, 0x09, 0x00, 0x00, 0x00],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "rbx".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Const { value: 9, bits: 64 },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![first, second]), &state, None)
            .expect("run");
        assert_eq!(states.len(), 1);
        assert_eq!(executor.breakpoints(), vec![0x401001]);
        assert_eq!(
            states[0]
                .evaluate_register("rax", 64)
                .expect("eval register")
                .expect("concrete value"),
            7
        );
        assert_eq!(
            states[0]
                .evaluate_register("rbx", 64)
                .expect("eval register"),
            None
        );

        executor.remove_breakpoint(0x401001);
        assert!(executor.breakpoints().is_empty());
        executor.set_breakpoint(0x401002);
        executor.clear_breakpoints();
        assert!(executor.breakpoints().is_empty());
    }

    #[test]
    fn symbolic_run_stops_at_hook_before_execution() {
        let mut executor = SymbolicExecutor::new();
        executor.add_hook(0x401001);
        let state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu"),
        );
        let first = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "mov".to_string(),
                disassembly: "mov rax, 7".to_string(),
                address: 0x401000,
                bytes: vec![0x48, 0xc7, 0xc0, 0x07, 0x00, 0x00, 0x00],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Const { value: 7, bits: 64 },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let second = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "mov".to_string(),
                disassembly: "mov rbx, 9".to_string(),
                address: 0x401001,
                bytes: vec![0x48, 0xc7, 0xc3, 0x09, 0x00, 0x00, 0x00],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "rbx".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Const { value: 9, bits: 64 },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![first, second]), &state, None)
            .expect("run");
        assert_eq!(states.len(), 1);
        assert_eq!(executor.hooks(), vec![0x401001]);
        assert_eq!(
            states[0]
                .evaluate_register("rax", 64)
                .expect("eval register")
                .expect("concrete value"),
            7
        );
        assert_eq!(
            states[0]
                .evaluate_register("rbx", 64)
                .expect("eval register"),
            None
        );

        executor.remove_hook(0x401001);
        assert!(executor.hooks().is_empty());
        executor.add_hook(0x401002);
        executor.clear_hooks();
        assert!(executor.hooks().is_empty());
    }

    #[test]
    fn symbolic_run_follows_i386_call_and_return() {
        let semantics = assembled_semantics(
            Architecture::I386,
            "
            call callee
            mov eax, 1
            ret
        callee:
            mov ebx, 2
            ret
            ",
        );
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("esp", 32, 0x3000).expect("set register");
        state.map_memory(0x2000, 0x2000);
        state
            .write_memory(0x3000, &0x9000u32.to_le_bytes())
            .expect("write memory");
        let states = executor
            .run(&Semantics { semantics, data: Vec::new() }, &state, None)
            .expect("run");
        assert_eq!(states.len(), 1);
        assert_eq!(
            states[0]
                .evaluate_register("eax", 32)
                .expect("eval register")
                .expect("concrete value"),
            1
        );
        assert_eq!(
            states[0]
                .evaluate_register("ebx", 32)
                .expect("eval register")
                .expect("concrete value"),
            2
        );
    }

    #[test]
    fn symbolic_run_follows_amd64_call_and_return() {
        let semantics = assembled_semantics(
            Architecture::AMD64,
            "
            call callee
            mov eax, 1
            ret
        callee:
            mov ebx, 2
            ret
            ",
        );
        let executor = SymbolicExecutor::new();
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu"),
        );
        state.set_register("rsp", 64, 0x3000).expect("set register");
        state.map_memory(0x2000, 0x2000);
        state
            .write_memory(0x3000, &0x9000u64.to_le_bytes())
            .expect("write memory");
        let states = executor
            .run(&Semantics { semantics, data: Vec::new() }, &state, None)
            .expect("run");
        assert_eq!(states.len(), 1);
        assert_eq!(
            states[0]
                .evaluate_register("eax", 32)
                .expect("eval register")
                .expect("concrete value"),
            1
        );
        assert_eq!(
            states[0]
                .evaluate_register("ebx", 32)
                .expect("eval register")
                .expect("concrete value"),
            2
        );
    }

    #[test]
    fn symbolic_run_follows_arm64_call_and_return() {
        let semantics = assembled_semantics(
            Architecture::ARM64,
            "
            bl callee
            mov w0, #1
            ret
        callee:
            mov w1, #2
            ret
            ",
        );
        let mut executor = SymbolicExecutor::new();
        executor.set_breakpoint(0x4);
        let state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::ARM64).expect("cpu"),
        );
        let states = executor
            .run(&Semantics { semantics, data: Vec::new() }, &state, None)
            .expect("run");
        assert_eq!(states.len(), 1);
        assert_eq!(
            states[0]
                .eval_program_counter_u64()
                .expect("eval program counter")
                .expect("concrete pc"),
            0x4
        );
        assert_eq!(
            states[0]
                .evaluate_register("x0", 64)
                .expect("eval register"),
            None
        );
    }

    #[test]
    fn symbolic_memory_u64_eval_executes() {
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu"),
        );
        state
            .write_memory(0x5000, &[0x44, 0x33, 0x22, 0x11])
            .expect("write memory");
        assert_eq!(
            state
                .evaluate_memory(0x5000, 4)
                .expect("eval memory")
                .expect("concrete memory"),
            0x11223344
        );
    }

    #[test]
    fn symbolic_call_sets_program_counter() {
        let executor = SymbolicExecutor::new();
        let state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::ARM64).expect("cpu"),
        );
        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::Call {
                target: SemanticExpression::Const {
                    value: 0x1000,
                    bits: 64,
                },
                return_target: None,
                does_return: Some(true),
            },
            diagnostics: Vec::new(),
        };
        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        assert_eq!(
            states[0]
                .eval_program_counter_u64()
                .expect("eval program counter")
                .expect("concrete pc"),
            0x1000
        );
    }

    #[test]
    fn slice_from_register_returns_dependency_chain() {
        let executor = SymbolicExecutor::new();
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu"),
        );
        state
            .symbolize_memory(0x1000, 1, Some("input"))
            .expect("symbolize memory");
        state.set_register("rdi", 64, 0x1000).expect("set register");

        let first = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "movzx".to_string(),
                disassembly: "movzx eax, byte ptr [rdi]".to_string(),
                address: 0x40058b,
                bytes: vec![0x0f, 0xb6, 0x07],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Load {
                    space: crate::semantics::SemanticAddressSpace::Default,
                    addr: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "rdi".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 8,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let second = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "sub".to_string(),
                disassembly: "sub eax, 1".to_string(),
                address: 0x400591,
                bytes: vec![0x83, 0xe8, 0x01],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::Sub,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Const { value: 1, bits: 32 }),
                    bits: 32,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let third = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "mov".to_string(),
                disassembly: "mov ecx, eax".to_string(),
                address: 0x400597,
                bytes: vec![0x89, 0xc1],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "ecx".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Read(Box::new(SemanticLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                })),
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![first, second, third]), &state, None)
            .expect("run");
        let slice = states[0]
            .slice_from_register("ecx", 32)
            .expect("slice register");
        let nodes = slice.nodes();
        assert_eq!(nodes.len(), 4);
        assert_eq!(nodes[1].instruction.as_ref().unwrap().mnemonic, "movzx");
        assert_eq!(nodes[2].instruction.as_ref().unwrap().mnemonic, "sub");
        assert_eq!(nodes[3].instruction.as_ref().unwrap().mnemonic, "mov");
        assert_eq!(nodes[3].location, "register:ecx");
    }

    #[test]
    fn slice_from_memory_returns_store_dependency() {
        let executor = SymbolicExecutor::new();
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu"),
        );
        state
            .symbolize_register("al", 8, Some("input_al"))
            .expect("symbolize register");

        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "mov".to_string(),
                disassembly: "mov byte ptr [0x3000], al".to_string(),
                address: 0x401000,
                bytes: vec![0x88, 0x05, 0x00, 0x30, 0x00, 0x00],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Store {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: SemanticExpression::Const {
                    value: 0x3000,
                    bits: 64,
                },
                expression: SemanticExpression::Read(Box::new(SemanticLocation::Register {
                    name: "al".to_string(),
                    bits: 8,
                })),
                bits: 8,
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        let slice = states[0]
            .slice_from_memory(0x3000, 1)
            .expect("slice memory");
        let nodes = slice.nodes();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[1].instruction.as_ref().unwrap().mnemonic, "mov");
        assert_eq!(nodes[1].location, "memory[0x3000]");
    }

    #[test]
    fn slice_from_register_preserves_x86_subregister_dependencies() {
        let executor = SymbolicExecutor::new();
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::AMD64).expect("cpu"),
        );
        state
            .symbolize_memory(0x1000, 1, Some("input"))
            .expect("symbolize memory");
        state.set_register("rdi", 64, 0x1000).expect("set register");

        let first = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "movzx".to_string(),
                disassembly: "movzx eax, byte ptr [rdi]".to_string(),
                address: 0x40058b,
                bytes: vec![0x0f, 0xb6, 0x07],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Load {
                    space: crate::semantics::SemanticAddressSpace::Default,
                    addr: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "rdi".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 8,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let second = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "movsx".to_string(),
                disassembly: "movsx eax, al".to_string(),
                address: 0x40058e,
                bytes: vec![0x0f, 0xbe, 0xc0],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Cast {
                    op: crate::semantics::SemanticOperationCast::SignExtend,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "al".to_string(),
                            bits: 8,
                        },
                    ))),
                    bits: 32,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let third = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(SemanticEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "mov".to_string(),
                disassembly: "mov ecx, eax".to_string(),
                address: 0x400597,
                bytes: vec![0x89, 0xc1],
            }),
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "ecx".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Read(Box::new(SemanticLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                })),
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![first, second, third]), &state, None)
            .expect("run");
        let slice = states[0]
            .slice_from_register("ecx", 32)
            .expect("slice register");
        let mnemonics = slice
            .nodes()
            .iter()
            .filter_map(|node| {
                node.instruction
                    .as_ref()
                    .map(|instruction| instruction.mnemonic.as_str())
            })
            .collect::<Vec<_>>();
        assert_eq!(mnemonics, vec!["movzx", "movsx", "mov"]);
    }

    #[test]
    fn symbolic_fp_add32_executes() {
        let executor = SymbolicExecutor::new();
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::ARM64).expect("cpu"),
        );
        state
            .set_register("s0", 32, 1.5f32.to_bits() as u64)
            .expect("set register");
        state
            .set_register("s1", 32, 2.25f32.to_bits() as u64)
            .expect("set register");

        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "s2".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::FAdd,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "s0".to_string(),
                            bits: 32,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "s1".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 32,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("s2", 32)
                .expect("eval register")
                .expect("concrete value"),
            (1.5f32 + 2.25f32).to_bits() as u64
        );
    }

    #[test]
    fn symbolic_fp_casts_execute() {
        let executor = SymbolicExecutor::new();
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::ARM64).expect("cpu"),
        );
        state.set_register("x0", 64, 42).expect("set register");

        let to_float = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "d0".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let from_float = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::FloatToInt,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "d0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![to_float, from_float]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("d0", 64)
                .expect("eval register")
                .expect("concrete value"),
            (42f64).to_bits()
        );
        assert_eq!(
            states[0]
                .evaluate_register("x1", 64)
                .expect("eval register")
                .expect("concrete value"),
            42
        );
    }

    #[test]
    fn symbolic_fp_unordered_compare_executes() {
        let executor = SymbolicExecutor::new();
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::ARM64).expect("cpu"),
        );
        state
            .set_register("d0", 64, f64::NAN.to_bits())
            .expect("set register");
        state
            .set_register("d1", 64, 1.0f64.to_bits())
            .expect("set register");

        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x2".to_string(),
                    bits: 1,
                },
                expression: SemanticExpression::Compare {
                    op: SemanticOperationCompare::Unordered,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "d0".to_string(),
                            bits: 64,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "d1".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 1,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("x2", 1)
                .expect("eval register")
                .expect("concrete value"),
            1
        );
    }

    #[test]
    fn symbolic_fp_neg_executes() {
        let executor = SymbolicExecutor::new();
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::ARM64).expect("cpu"),
        );
        state
            .set_register("d0", 64, 3.5f64.to_bits())
            .expect("set register");

        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "d1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Unary {
                    op: SemanticOperationUnary::Neg,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "d0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("d1", 64)
                .expect("eval register")
                .expect("concrete value"),
            (-3.5f64).to_bits()
        );
    }

    #[test]
    fn symbolic_fp_neg_of_const_executes() {
        let executor = SymbolicExecutor::new();
        let state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::ARM64).expect("cpu"),
        );

        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "d1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Unary {
                    op: SemanticOperationUnary::Neg,
                    arg: Box::new(SemanticExpression::Const {
                        value: 3.5f64.to_bits() as u128,
                        bits: 64,
                    }),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("d1", 64)
                .expect("eval register")
                .expect("concrete value"),
            (-3.5f64).to_bits()
        );
    }

    #[test]
    fn symbolic_fp_neg_of_memory_load_executes() {
        let executor = SymbolicExecutor::new();
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::ARM64).expect("cpu"),
        );
        state
            .write_memory(0x8000, &3.5f64.to_bits().to_le_bytes())
            .expect("write memory");

        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "d1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Unary {
                    op: SemanticOperationUnary::Neg,
                    arg: Box::new(SemanticExpression::Load {
                        space: crate::semantics::SemanticAddressSpace::Default,
                        addr: Box::new(SemanticExpression::Const {
                            value: 0x8000,
                            bits: 64,
                        }),
                        bits: 64,
                    }),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("d1", 64)
                .expect("eval register")
                .expect("concrete value"),
            (-3.5f64).to_bits()
        );
    }

    #[test]
    fn symbolic_integer_neg_still_executes() {
        let executor = SymbolicExecutor::new();
        let mut state = SymbolicCpuState::new(
            SemanticCpu::from_architecture(Architecture::ARM64).expect("cpu"),
        );
        state.set_register("x0", 64, 7).expect("set register");

        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Unary {
                    op: SemanticOperationUnary::Neg,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor.step(&semantics_of(semantics), &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("x1", 64)
                .expect("eval register")
                .expect("concrete value"),
            (!7u64).wrapping_add(1)
        );
    }

    #[test]
    fn symbolic_float80_compare_executes() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 1).expect("set register");
        state.set_register("ebx", 32, 2).expect("set register");

        let to_fp80_left = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let to_fp80_right = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st1".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "ebx".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let compare = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "ecx".to_string(),
                    bits: 1,
                },
                expression: SemanticExpression::Compare {
                    op: SemanticOperationCompare::Olt,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st1".to_string(),
                            bits: 80,
                        },
                    ))),
                    bits: 1,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![to_fp80_left, to_fp80_right, compare]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("ecx", 32)
                .expect("eval register")
                .expect("concrete value"),
            1
        );
    }

    #[test]
    fn symbolic_float80_truncate_to_f64_executes() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 42).expect("set register");

        let to_fp80 = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let truncate = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm0".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::FloatTruncate,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![to_fp80, truncate]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("xmm0", 64)
                .expect("eval register")
                .expect("concrete value"),
            (42f64).to_bits()
        );
    }

    #[test]
    fn symbolic_x87_const_add_store_executes() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 7).expect("set register");
        state.set_register("ebx", 32, 2).expect("set register");

        let lhs = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let rhs = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st1".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "ebx".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let add = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.add".to_string(),
                    args: vec![
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        })),
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st1".to_string(),
                            bits: 80,
                        })),
                    ],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm0".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![lhs, rhs, add, store]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("xmm0", 64)
                .expect("eval register")
                .expect("concrete value"),
            (9.0f64).to_bits()
        );
    }

    #[test]
    fn symbolic_x87_load_f32_executes() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state
            .write_memory(0x9000, &3.25f32.to_bits().to_le_bytes())
            .expect("write memory");

        let load = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.load_f32".to_string(),
                    args: vec![SemanticExpression::Load {
                        space: crate::semantics::SemanticAddressSpace::Default,
                        addr: Box::new(SemanticExpression::Const {
                            value: 0x9000,
                            bits: 32,
                        }),
                        bits: 32,
                    }],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm0".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![load, store]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("xmm0", 64)
                .expect("eval register")
                .expect("concrete value"),
            (3.25f32 as f64).to_bits()
        );
    }

    #[test]
    fn symbolic_x87_store_i32_executes() {
        let executor = SymbolicExecutor::new();
        let state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));

        let load = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.const_pi".to_string(),
                    args: Vec::new(),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Store {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: SemanticExpression::Const {
                    value: 0xA000,
                    bits: 32,
                },
                expression: SemanticExpression::Extract {
                    arg: Box::new(SemanticExpression::Intrinsic {
                        name: "x86.x87.store_i32".to_string(),
                        args: vec![SemanticExpression::Read(Box::new(
                            SemanticLocation::Register {
                                name: "x87_st0".to_string(),
                                bits: 80,
                            },
                        ))],
                        bits: 80,
                    }),
                    lsb: 0,
                    bits: 32,
                },
                bits: 32,
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![load, store]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_memory(0xA000, 4)
                .expect("eval memory")
                .expect("concrete value"),
            3
        );
    }

    #[test]
    fn symbolic_x87_store_i32_trunc_executes() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 7).expect("set register");
        state.set_register("ebx", 32, 2).expect("set register");

        let to_fp80 = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let divide = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "x87_st1".to_string(),
                        bits: 80,
                    },
                    expression: SemanticExpression::Cast {
                        op: SemanticOperationCast::IntToFloat,
                        arg: Box::new(SemanticExpression::Read(Box::new(
                            SemanticLocation::Register {
                                name: "ebx".to_string(),
                                bits: 32,
                            },
                        ))),
                        bits: 80,
                    },
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    },
                    expression: SemanticExpression::Intrinsic {
                        name: "x86.x87.div".to_string(),
                        args: vec![
                            SemanticExpression::Read(Box::new(SemanticLocation::Register {
                                name: "x87_st0".to_string(),
                                bits: 80,
                            })),
                            SemanticExpression::Read(Box::new(SemanticLocation::Register {
                                name: "x87_st1".to_string(),
                                bits: 80,
                            })),
                        ],
                        bits: 80,
                    },
                },
            ],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Store {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: SemanticExpression::Const {
                    value: 0xA100,
                    bits: 32,
                },
                expression: SemanticExpression::Extract {
                    arg: Box::new(SemanticExpression::Intrinsic {
                        name: "x86.x87.store_i32_trunc".to_string(),
                        args: vec![SemanticExpression::Read(Box::new(
                            SemanticLocation::Register {
                                name: "x87_st0".to_string(),
                                bits: 80,
                            },
                        ))],
                        bits: 80,
                    }),
                    lsb: 0,
                    bits: 32,
                },
                bits: 32,
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![to_fp80, divide, store]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_memory(0xA100, 4)
                .expect("eval memory")
                .expect("concrete value"),
            3
        );
    }

    #[test]
    fn symbolic_x87_xam_negative_zero_executes() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state
            .set_register("xmm0", 64, (-0.0f64).to_bits())
            .expect("set register");

        let load = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::FloatExtend,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "xmm0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Intrinsic {
                name: "x86.x87.xam".to_string(),
                args: vec![SemanticExpression::Read(Box::new(
                    SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    },
                ))],
                outputs: vec![
                    SemanticLocation::Register {
                        name: "c0".to_string(),
                        bits: 1,
                    },
                    SemanticLocation::Register {
                        name: "c1".to_string(),
                        bits: 1,
                    },
                    SemanticLocation::Register {
                        name: "c2".to_string(),
                        bits: 1,
                    },
                    SemanticLocation::Register {
                        name: "c3".to_string(),
                        bits: 1,
                    },
                ],
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![load, semantics]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("c0", 1)
                .expect("eval")
                .expect("value"),
            0
        );
        assert_eq!(
            states[0]
                .evaluate_register("c1", 1)
                .expect("eval")
                .expect("value"),
            1
        );
        assert_eq!(
            states[0]
                .evaluate_register("c2", 1)
                .expect("eval")
                .expect("value"),
            0
        );
        assert_eq!(
            states[0]
                .evaluate_register("c3", 1)
                .expect("eval")
                .expect("value"),
            1
        );
    }

    #[test]
    fn symbolic_x87_xam_infinity_executes() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state
            .set_register("xmm0", 64, f64::INFINITY.to_bits())
            .expect("set register");

        let load = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::FloatExtend,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "xmm0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Intrinsic {
                name: "x86.x87.xam".to_string(),
                args: vec![SemanticExpression::Read(Box::new(
                    SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    },
                ))],
                outputs: vec![
                    SemanticLocation::Register {
                        name: "c0".to_string(),
                        bits: 1,
                    },
                    SemanticLocation::Register {
                        name: "c1".to_string(),
                        bits: 1,
                    },
                    SemanticLocation::Register {
                        name: "c2".to_string(),
                        bits: 1,
                    },
                    SemanticLocation::Register {
                        name: "c3".to_string(),
                        bits: 1,
                    },
                ],
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![load, semantics]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("c0", 1)
                .expect("eval")
                .expect("value"),
            1
        );
        assert_eq!(
            states[0]
                .evaluate_register("c1", 1)
                .expect("eval")
                .expect("value"),
            0
        );
        assert_eq!(
            states[0]
                .evaluate_register("c2", 1)
                .expect("eval")
                .expect("value"),
            1
        );
        assert_eq!(
            states[0]
                .evaluate_register("c3", 1)
                .expect("eval")
                .expect("value"),
            0
        );
    }

    #[test]
    fn symbolic_x87_sin_executes() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state
            .set_register("xmm0", 64, 0.0f64.to_bits())
            .expect("set register");

        let load = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::FloatExtend,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "xmm0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let sin = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.sin".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![load, sin, store]), &state, None)
            .expect("run");
        let value = states[0]
            .evaluate_register("xmm1", 64)
            .expect("eval")
            .expect("value");
        assert!(f64::from_bits(value).abs() < 1e-300);
    }

    #[test]
    fn symbolic_x87_cos_executes() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state
            .set_register("xmm0", 64, 0.0f64.to_bits())
            .expect("set register");

        let load = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::FloatExtend,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "xmm0".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let cos = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.cos".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![load, cos, store]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("xmm1", 64)
                .expect("eval")
                .expect("value"),
            1.0f64.to_bits()
        );
    }

    #[test]
    fn symbolic_x87_atan2_executes() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 1).expect("set register");

        let lhs = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    },
                    expression: SemanticExpression::Cast {
                        op: SemanticOperationCast::IntToFloat,
                        arg: Box::new(SemanticExpression::Read(Box::new(
                            SemanticLocation::Register {
                                name: "eax".to_string(),
                                bits: 32,
                            },
                        ))),
                        bits: 80,
                    },
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "x87_st1".to_string(),
                        bits: 80,
                    },
                    expression: SemanticExpression::Cast {
                        op: SemanticOperationCast::IntToFloat,
                        arg: Box::new(SemanticExpression::Read(Box::new(
                            SemanticLocation::Register {
                                name: "eax".to_string(),
                                bits: 32,
                            },
                        ))),
                        bits: 80,
                    },
                },
            ],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let atan2 = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st1".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.atan2".to_string(),
                    args: vec![
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st1".to_string(),
                            bits: 80,
                        })),
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        })),
                    ],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st1".to_string(),
                            bits: 80,
                        },
                    ))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![lhs, atan2, store]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("xmm1", 64)
                .expect("eval")
                .expect("value"),
            std::f64::consts::FRAC_PI_4.to_bits()
        );
    }

    #[test]
    fn symbolic_x87_scale_executes() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 3).expect("set register");
        state.set_register("ebx", 32, 2).expect("set register");

        let load = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    },
                    expression: SemanticExpression::Cast {
                        op: SemanticOperationCast::IntToFloat,
                        arg: Box::new(SemanticExpression::Read(Box::new(
                            SemanticLocation::Register {
                                name: "eax".to_string(),
                                bits: 32,
                            },
                        ))),
                        bits: 80,
                    },
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "x87_st1".to_string(),
                        bits: 80,
                    },
                    expression: SemanticExpression::Cast {
                        op: SemanticOperationCast::IntToFloat,
                        arg: Box::new(SemanticExpression::Read(Box::new(
                            SemanticLocation::Register {
                                name: "ebx".to_string(),
                                bits: 32,
                            },
                        ))),
                        bits: 80,
                    },
                },
            ],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let scale = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.scale".to_string(),
                    args: vec![
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        })),
                        SemanticExpression::Read(Box::new(SemanticLocation::Register {
                            name: "x87_st1".to_string(),
                            bits: 80,
                        })),
                    ],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![load, scale, store]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("xmm1", 64)
                .expect("eval")
                .expect("value"),
            (12.0f64).to_bits()
        );
    }

    #[test]
    fn symbolic_x87_f2xm1_executes() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 1).expect("set register");

        let load = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let op = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.f2xm1".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![load, op, store]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("xmm1", 64)
                .expect("eval")
                .expect("value"),
            1.0f64.to_bits()
        );
    }

    #[test]
    fn symbolic_x87_load_bcd_executes() {
        let executor = SymbolicExecutor::new();
        let state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));

        let load = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.load_bcd".to_string(),
                    args: vec![SemanticExpression::Const {
                        value: 0x80000001234567890123,
                        bits: 80,
                    }],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))],
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![load, store]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_register("xmm1", 64)
                .expect("eval")
                .expect("value"),
            (-1234567890123.0f64).to_bits()
        );
    }

    #[test]
    fn symbolic_x87_store_bcd_executes() {
        let executor = SymbolicExecutor::new();
        let mut state =
            SymbolicCpuState::new(SemanticCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 42).expect("set register");

        let load = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: SemanticExpression::Cast {
                    op: SemanticOperationCast::IntToFloat,
                    arg: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                    ))),
                    bits: 80,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let store = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Store {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: SemanticExpression::Const {
                    value: 0xA200,
                    bits: 32,
                },
                expression: SemanticExpression::Intrinsic {
                    name: "x86.x87.store_bcd".to_string(),
                    args: vec![SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        },
                    ))],
                    bits: 80,
                },
                bits: 80,
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let states = executor
            .run(&semantics_many(vec![load, store]), &state, None)
            .expect("run");
        assert_eq!(
            states[0]
                .evaluate_memory(0xA200, 8)
                .expect("eval memory")
                .expect("concrete value"),
            0x42
        );
        assert_eq!(
            states[0]
                .evaluate_memory(0xA208, 2)
                .expect("eval memory")
                .expect("concrete value"),
            0
        );
    }
}
