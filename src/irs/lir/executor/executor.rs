use crate::irs::lir::executor::LirExecutorError;
use crate::irs::lir::executor::LirExecutorState;
use crate::irs::lir::{LirInstruction, LirModule, LirStatus, LirTerminator};
use std::collections::{BTreeSet, HashMap};

pub const DEFAULT_RUN_STEP_LIMIT: usize = 1024;

#[derive(Clone)]
pub struct LirExecutor {
    breakpoints: BTreeSet<u64>,
    hooks: BTreeSet<u64>,
}

impl LirExecutor {
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
        lir: &LirModule,
        state: &LirExecutorState,
    ) -> Result<Vec<LirExecutorState>, LirExecutorError> {
        if lir.instructions().is_empty() {
            return Ok(vec![state.clone()]);
        }
        let (lir, working, _, start_index) = self.prepare_state_and_lir(lir.clone(), state)?;
        let instructions = lir.instructions();
        let instruction = instructions[start_index];
        let previous_pc = working.eval_program_counter_u64()?;
        let mut states = self.step_instruction(instruction, &working)?;

        if matches!(instruction.terminator, LirTerminator::FallThrough)
            && previous_pc == working.eval_program_counter_u64()?
            && start_index + 1 < instructions.len()
        {
            if let Some(address) = instructions[start_index + 1].address {
                for state in &mut states {
                    if state.eval_program_counter_u64()? == previous_pc {
                        self.materialize_program_counter(state, instruction.address, address)?;
                    }
                }
            }
        }

        Ok(states)
    }

    pub fn run(
        &self,
        lir: &LirModule,
        state: &LirExecutorState,
        steps: Option<usize>,
    ) -> Result<Vec<LirExecutorState>, LirExecutorError> {
        let (lir, initial_state, address_to_index, start_index) =
            self.prepare_state_and_lir(lir.clone(), state)?;
        let lir = lir.instructions();
        if lir.is_empty() {
            return Ok(vec![state.clone()]);
        }
        let step_limit = steps.unwrap_or(DEFAULT_RUN_STEP_LIMIT);
        let mut active_states = vec![(start_index, initial_state, step_limit)];
        let mut final_states = Vec::new();

        while !active_states.is_empty() {
            let mut next_states = Vec::new();
            for (index, live, remaining_steps) in active_states {
                let instruction = lir[index];
                if let Some(address) = instruction.address {
                    if self.breakpoints.contains(&address) || self.hooks.contains(&address) {
                        final_states.push(live);
                        continue;
                    }
                }

                if remaining_steps == 0 {
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
                let next_remaining_steps = remaining_steps.saturating_sub(1);

                if stepped.is_empty() {
                    continue;
                }

                if stepped.len() > 1 {
                    final_states.extend(stepped);
                    continue;
                }

                let successor = stepped.pop().expect("single satisfiable successor");
                let next_index = self.resolve_successor_index(
                    &lir,
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
        lir: &[&LirInstruction],
        address_to_index: &HashMap<u64, usize>,
        current_index: usize,
        previous_pc: Option<u64>,
        successor: &LirExecutorState,
    ) -> Result<Option<usize>, LirExecutorError> {
        let current = lir[current_index];
        let current_pc = successor.eval_program_counter_u64()?;
        let sequential_next = (current_index + 1 < lir.len()).then_some(current_index + 1);

        let follow_concrete_target = |address: u64| address_to_index.get(&address).copied();

        match &current.terminator {
            LirTerminator::FallThrough => {
                if current_pc != previous_pc {
                    if let Some(address) = current_pc {
                        return Ok(follow_concrete_target(address));
                    }
                }
                Ok(sequential_next)
            }
            LirTerminator::Return { expression } => {
                if expression.is_none() {
                    return Ok(None);
                }
                Ok(current_pc.and_then(follow_concrete_target))
            }
            LirTerminator::Jump { .. }
            | LirTerminator::Branch { .. }
            | LirTerminator::Call { .. } => Ok(current_pc.and_then(follow_concrete_target)),
            LirTerminator::Trap | LirTerminator::Unreachable => Ok(None),
        }
    }

    fn prepare_state_and_lir(
        &self,
        lir: LirModule,
        state: &LirExecutorState,
    ) -> Result<(LirModule, LirExecutorState, HashMap<u64, usize>, usize), LirExecutorError> {
        let mut working_state = state.clone();
        working_state.load_lir_data(&lir.data)?;
        let mut address_to_index = HashMap::new();
        for (index, instruction) in lir.instructions().into_iter().enumerate() {
            if let Some(address) = instruction.address {
                address_to_index.entry(address).or_insert(index);
            }
        }
        let start_index = working_state
            .eval_program_counter_u64()?
            .and_then(|address| address_to_index.get(&address).copied())
            .unwrap_or(0);
        Ok((lir, working_state, address_to_index, start_index))
    }

    fn step_instruction(
        &self,
        lir: &LirInstruction,
        state: &LirExecutorState,
    ) -> Result<Vec<LirExecutorState>, LirExecutorError> {
        if !matches!(lir.status, LirStatus::Complete) {
            return Err(LirExecutorError::UnsupportedExpression(
                "partial LIR bindings are not executable",
            ));
        }
        let mut working = state.clone();
        for effect in &lir.effects {
            self.apply_effect(&mut working, lir.address, effect)?;
        }
        self.apply_terminator(working, lir.address, &lir.terminator)
    }

    fn materialize_program_counter(
        &self,
        state: &mut LirExecutorState,
        instruction: Option<u64>,
        address: u64,
    ) -> Result<(), LirExecutorError> {
        let value = state
            .backend()
            .const_bv(address as u128, state.address_bits())?;
        let def_id = state.define_location(
            instruction,
            "program_counter".to_string(),
            &value,
            &BTreeSet::new(),
        );
        state.set_program_counter(value, def_id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::LirExecutor;
    use super::LirExecutorState;
    use crate::Architecture;
    use crate::Configuration;
    use crate::assemblers::{Assembler, AssemblerBackend};
    use crate::controlflow::Graph;
    use crate::disassemblers::capstone::Disassembler;
    use crate::formats::{Image, ImagePermissions, ImageSegment};
    use crate::irs::lir::{
        LirAddressSpace, LirCpu, LirData, LirEffect, LirExpression, LirInstruction, LirLocation,
        LirModule, LirOperationBinary, LirOperationCast, LirOperationCompare, LirOperationUnary,
        LirStatus, LirTerminator,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn assembled_lir(architecture: Architecture, assembly: &str) -> Vec<LirInstruction> {
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
            .map(|instruction| instruction.build_lir().expect("LIR bindings"))
            .collect()
    }

    fn lir_of(lir: LirInstruction) -> LirModule {
        LirModule::from_instructions(vec![lir])
    }

    fn lir_many(lir: Vec<LirInstruction>) -> LirModule {
        LirModule::from_instructions(lir)
    }

    #[test]
    fn symbolic_branch_forks() {
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::ARM64).expect("cpu"));
        state
            .symbolize_register("x0", 64, Some("input_x0"))
            .expect("symbolize register");

        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: Vec::new(),
            terminator: LirTerminator::Branch {
                condition: LirExpression::Compare {
                    op: LirOperationCompare::Eq,
                    left: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x0".to_string(),
                        bits: 64,
                    }))),
                    right: Box::new(LirExpression::Const { value: 0, bits: 64 }),
                    bits: 1,
                },
                true_target: LirExpression::Const {
                    value: 0x1000,
                    bits: 64,
                },
                false_target: LirExpression::Const {
                    value: 0x2000,
                    bits: 64,
                },
            },
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
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
    fn symbolic_lir_data_supports_step_and_run() {
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
        state.set_register("rdi", 64, 2).expect("set register");

        let body = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::ZeroExtend,
                    arg: Box::new(LirExpression::Load {
                        space: LirAddressSpace::Global,
                        addr: Box::new(LirExpression::Binary {
                            op: LirOperationBinary::Add,
                            left: Box::new(LirExpression::DataAddress {
                                name: "digits".to_string(),
                                bits: 64,
                            }),
                            right: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                                name: "rdi".to_string(),
                                bits: 64,
                            }))),
                            bits: 64,
                        }),
                        bits: 8,
                    }),
                    bits: 64,
                },
            }],
            terminator: LirTerminator::Return { expression: None },
        };
        let lir = LirModule::from_instructions_with_data(
            vec![body],
            vec![LirData {
                name: "digits".to_string(),
                bytes: b"0123456789".to_vec(),
            }],
        );

        let step_states = executor.step(&lir, &state).expect("step");
        let step_state = step_states.first().expect("step state");
        assert_eq!(
            step_state
                .evaluate_register("rax", 64)
                .expect("evaluate register"),
            Some(u64::from(b'2'))
        );

        let run_states = executor.run(&lir, &state, None).expect("run");
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
        let executor = LirExecutor::new();
        let state_cpu = LirCpu::from_architecture(Architecture::AMD64).expect("cpu");
        let mut state = LirExecutorState::new(state_cpu);

        let mut image = Image::new();
        image.add_segment(ImageSegment::bytes(
            Some("fixture".to_string()),
            0x1234,
            vec![0x41, 0x42, 0x43, 0x44],
            ImagePermissions::readable(),
        ));

        state.map_image(&image);

        let lir = LirModule::from_instructions(vec![LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "rax".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Load {
                    space: LirAddressSpace::Global,
                    addr: Box::new(LirExpression::Const {
                        value: 0x1234,
                        bits: 64,
                    }),
                    bits: 32,
                },
            }],
            terminator: LirTerminator::Return { expression: None },
        }]);

        let states = executor.run(&lir, &state, None).expect("run");
        let state = states.first().expect("state");
        assert_eq!(
            state.evaluate_register("rax", 32).expect("rax"),
            Some(0x4443_4241)
        );
    }

    #[test]
    fn symbolic_memory_store_then_load() {
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));

        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Store {
                    space: crate::irs::lir::LirAddressSpace::Default,
                    addr: LirExpression::Const {
                        value: 0x3000,
                        bits: 64,
                    },
                    expression: LirExpression::Const {
                        value: 0x41,
                        bits: 8,
                    },
                    bits: 8,
                },
                LirEffect::Set {
                    dst: LirLocation::Register {
                        name: "rax".to_string(),
                        bits: 8,
                    },
                    expression: LirExpression::Load {
                        space: crate::irs::lir::LirAddressSpace::Default,
                        addr: Box::new(LirExpression::Const {
                            value: 0x3000,
                            bits: 64,
                        }),
                        bits: 8,
                    },
                },
            ],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
        let value = states[0]
            .evaluate_register("rax", 8)
            .expect("evaluate register")
            .expect("concrete register");
        assert_eq!(value, 0x41);
    }

    #[test]
    fn symbolic_indexed_memory_store_then_read() {
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));

        let location = LirLocation::IndexedMemory {
            name: "locals".to_string(),
            index: Box::new(LirExpression::Const { value: 2, bits: 32 }),
            bits: 32,
        };
        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Set {
                    dst: location.clone(),
                    expression: LirExpression::Const {
                        value: 0x41424344,
                        bits: 32,
                    },
                },
                LirEffect::Set {
                    dst: LirLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    },
                    expression: LirExpression::Read(Box::new(location)),
                },
            ],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
        let value = states[0]
            .evaluate_register("eax", 32)
            .expect("evaluate register")
            .expect("concrete register");
        assert_eq!(value, 0x41424344);
    }

    #[test]
    fn symbolic_stack_memory_store_then_read() {
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));

        let location = LirLocation::StackMemory {
            name: "value_stack".to_string(),
            offset: 0,
            bits: 32,
        };
        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Set {
                    dst: location.clone(),
                    expression: LirExpression::Const {
                        value: 0x11223344,
                        bits: 32,
                    },
                },
                LirEffect::Set {
                    dst: LirLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    },
                    expression: LirExpression::Read(Box::new(location)),
                },
            ],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
        let value = states[0]
            .evaluate_register("eax", 32)
            .expect("evaluate register")
            .expect("concrete register");
        assert_eq!(value, 0x11223344);
    }

    #[test]
    fn symbolic_stack_push_and_pop_execute() {
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));

        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Push {
                    stack: "value_stack".to_string(),
                    expression: LirExpression::Const { value: 1, bits: 32 },
                },
                LirEffect::Push {
                    stack: "value_stack".to_string(),
                    expression: LirExpression::Const { value: 2, bits: 32 },
                },
                LirEffect::Pop {
                    stack: "value_stack".to_string(),
                    dst: LirLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    },
                },
                LirEffect::Pop {
                    stack: "value_stack".to_string(),
                    dst: LirLocation::Register {
                        name: "ebx".to_string(),
                        bits: 32,
                    },
                },
            ],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
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
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::CIL).expect("cpu"));

        let object = LirExpression::Allocate {
            kind: "object".to_string(),
            bits: 64,
        };
        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Set {
                    dst: LirLocation::Temporary { id: 0, bits: 64 },
                    expression: object,
                },
                LirEffect::WriteProperty {
                    reference: LirExpression::Read(Box::new(LirLocation::Temporary {
                        id: 0,
                        bits: 64,
                    })),
                    name: "length".to_string(),
                    expression: LirExpression::Const { value: 7, bits: 32 },
                    bits: 32,
                },
                LirEffect::Set {
                    dst: LirLocation::Register {
                        name: "pc".to_string(),
                        bits: 32,
                    },
                    expression: LirExpression::ReadProperty {
                        reference: Box::new(LirExpression::Read(Box::new(
                            LirLocation::Temporary { id: 0, bits: 64 },
                        ))),
                        name: "length".to_string(),
                        bits: 32,
                    },
                },
            ],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
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
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::CIL).expect("cpu"));

        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Set {
                    dst: LirLocation::Temporary { id: 0, bits: 64 },
                    expression: LirExpression::Allocate {
                        kind: "array".to_string(),
                        bits: 64,
                    },
                },
                LirEffect::WriteElement {
                    reference: LirExpression::Read(Box::new(LirLocation::Temporary {
                        id: 0,
                        bits: 64,
                    })),
                    index: LirExpression::Const { value: 3, bits: 32 },
                    expression: LirExpression::Const {
                        value: 0x55,
                        bits: 8,
                    },
                    bits: 8,
                },
                LirEffect::Set {
                    dst: LirLocation::Register {
                        name: "pc".to_string(),
                        bits: 8,
                    },
                    expression: LirExpression::ReadElement {
                        reference: Box::new(LirExpression::Read(Box::new(
                            LirLocation::Temporary { id: 0, bits: 64 },
                        ))),
                        index: Box::new(LirExpression::Const { value: 3, bits: 32 }),
                        bits: 8,
                    },
                },
            ],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
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
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
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
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::ARM64).expect("cpu"));
        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x0".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Unary {
                    op: LirOperationUnary::PopCount,
                    arg: Box::new(LirExpression::Const {
                        value: 0b1011,
                        bits: 64,
                    }),
                    bits: 64,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let states = executor.step(&lir_of(lir), &state).expect("step");
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
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::ARM64).expect("cpu"));
        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x0".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Binary {
                    op: LirOperationBinary::UMulHigh,
                    left: Box::new(LirExpression::Const {
                        value: u64::MAX as u128,
                        bits: 64,
                    }),
                    right: Box::new(LirExpression::Const { value: 2, bits: 64 }),
                    bits: 64,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let states = executor.step(&lir_of(lir), &state).expect("step");
        assert_eq!(
            states[0]
                .evaluate_register("x0", 64)
                .expect("eval register")
                .expect("concrete value"),
            1
        );
    }

    #[test]
    fn partial_lir_are_rejected() {
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
        let lir = LirInstruction {
            address: None,
            status: LirStatus::Partial,
            effects: Vec::new(),
            terminator: LirTerminator::FallThrough,
        };
        assert!(executor.step(&lir_of(lir), &state).is_err());
    }

    #[test]
    fn symbolic_trace_run_executes() {
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
        let first = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Const { value: 7, bits: 64 },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let second = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "rbx".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Binary {
                    op: LirOperationBinary::Add,
                    left: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "rax".to_string(),
                        bits: 64,
                    }))),
                    right: Box::new(LirExpression::Const { value: 5, bits: 64 }),
                    bits: 64,
                },
            }],
            terminator: LirTerminator::Jump {
                target: LirExpression::Const {
                    value: 0x401000,
                    bits: 64,
                },
            },
        };
        let states = executor
            .run(&lir_many(vec![first, second]), &state, None)
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
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        let setup = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x1000),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "ecx".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Const { value: 3, bits: 32 },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let loop_body = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x1005),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "ecx".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Binary {
                    op: LirOperationBinary::Sub,
                    left: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "ecx".to_string(),
                        bits: 32,
                    }))),
                    right: Box::new(LirExpression::Const { value: 1, bits: 32 }),
                    bits: 32,
                },
            }],
            terminator: LirTerminator::Branch {
                condition: LirExpression::Compare {
                    op: LirOperationCompare::Eq,
                    left: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "ecx".to_string(),
                        bits: 32,
                    }))),
                    right: Box::new(LirExpression::Const { value: 0, bits: 32 }),
                    bits: 1,
                },
                true_target: LirExpression::Const {
                    value: 0x1006,
                    bits: 32,
                },
                false_target: LirExpression::Const {
                    value: 0x1005,
                    bits: 32,
                },
            },
        };
        let exit = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x1006),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Const {
                    value: 0x41,
                    bits: 32,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![setup, loop_body, exit]), &state, None)
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state
            .symbolize_register("eax", 32, Some("input_eax"))
            .expect("symbolize register");

        let branch = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x1000),
            effects: Vec::new(),
            terminator: LirTerminator::Branch {
                condition: LirExpression::Compare {
                    op: LirOperationCompare::Eq,
                    left: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    }))),
                    right: Box::new(LirExpression::Const { value: 0, bits: 32 }),
                    bits: 1,
                },
                true_target: LirExpression::Const {
                    value: 0x1002,
                    bits: 32,
                },
                false_target: LirExpression::Const {
                    value: 0x1005,
                    bits: 32,
                },
            },
        };
        let taken = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x1002),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "ebx".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Const { value: 1, bits: 32 },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let not_taken = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x1005),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "ebx".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Const { value: 2, bits: 32 },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![branch, taken, not_taken]), &state, None)
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
            let smt = state.smt();
            assert!(smt.contains("(assert"));
            assert!(smt.contains("state_register_eax"));
            assert!(smt.contains("input_eax"));
            assert!(smt.contains("(check-sat)"));
            assert!(smt.contains("(get-model)"));
            assert_eq!(
                state.evaluate_register("ebx", 32).expect("eval register"),
                None
            );
        }
    }

    #[test]
    fn symbolic_run_honors_step_budget() {
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
        let first = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x401000),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Const { value: 7, bits: 64 },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let second = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x401001),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "rbx".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Const { value: 9, bits: 64 },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![first, second]), &state, Some(1))
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
    fn symbolic_step_materializes_fallthrough_program_counter() {
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
        let first = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x401000),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Const { value: 7, bits: 64 },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let second = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x401004),
            effects: Vec::new(),
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .step(&lir_many(vec![first, second]), &state)
            .expect("step");
        assert_eq!(states.len(), 1);
        assert_eq!(
            states[0]
                .evaluate_register("rip", 64)
                .expect("eval register")
                .expect("concrete value"),
            0x401004
        );
    }

    #[test]
    fn symbolic_run_defaults_to_bounded_execution() {
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
        let instruction = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x401000),
            effects: Vec::new(),
            terminator: LirTerminator::Jump {
                target: LirExpression::Const {
                    value: 0x401000,
                    bits: 64,
                },
            },
        };

        let states = executor
            .run(&lir_of(instruction), &state, None)
            .expect("run");
        assert_eq!(states.len(), 1);
        assert_eq!(
            states[0]
                .evaluate_register("rip", 64)
                .expect("eval register"),
            Some(0x401000)
        );
    }

    #[test]
    fn symbolic_run_stops_at_breakpoint_before_execution() {
        let mut executor = LirExecutor::new();
        executor.set_breakpoint(0x401001);
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
        let first = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x401000),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Const { value: 7, bits: 64 },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let second = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x401001),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "rbx".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Const { value: 9, bits: 64 },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![first, second]), &state, None)
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
        let mut executor = LirExecutor::new();
        executor.add_hook(0x401001);
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
        let first = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x401000),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Const { value: 7, bits: 64 },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let second = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x401001),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "rbx".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Const { value: 9, bits: 64 },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![first, second]), &state, None)
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
        let lir = assembled_lir(
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("esp", 32, 0x3000).expect("set register");
        state.map_memory(0x2000, 0x2000);
        state
            .write_memory(0x3000, &0x9000u32.to_le_bytes())
            .expect("write memory");
        let states = executor
            .run(&LirModule::from_instructions(lir), &state, None)
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
        let lir = assembled_lir(
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
        state.set_register("rsp", 64, 0x3000).expect("set register");
        state.map_memory(0x2000, 0x2000);
        state
            .write_memory(0x3000, &0x9000u64.to_le_bytes())
            .expect("write memory");
        let states = executor
            .run(&LirModule::from_instructions(lir), &state, None)
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
        let lir = assembled_lir(
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
        let mut executor = LirExecutor::new();
        executor.set_breakpoint(0x4);
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::ARM64).expect("cpu"));
        let states = executor
            .run(&LirModule::from_instructions(lir), &state, None)
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
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
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
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::ARM64).expect("cpu"));
        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: Vec::new(),
            terminator: LirTerminator::Call {
                target: LirExpression::Const {
                    value: 0x1000,
                    bits: 64,
                },
                return_target: None,
                does_return: Some(true),
            },
        };
        let states = executor.step(&lir_of(lir), &state).expect("step");
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
        state
            .symbolize_memory(0x1000, 1, Some("input"))
            .expect("symbolize memory");
        state.set_register("rdi", 64, 0x1000).expect("set register");

        let first = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x40058b),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Load {
                    space: crate::irs::lir::LirAddressSpace::Default,
                    addr: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "rdi".to_string(),
                        bits: 64,
                    }))),
                    bits: 8,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let second = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x400591),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Binary {
                    op: LirOperationBinary::Sub,
                    left: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    }))),
                    right: Box::new(LirExpression::Const { value: 1, bits: 32 }),
                    bits: 32,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let third = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x400597),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "ecx".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Read(Box::new(LirLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                })),
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![first, second, third]), &state, None)
            .expect("run");
        let slice = states[0]
            .slice_from_register("ecx", 32)
            .expect("slice register");
        let nodes = slice.nodes();
        assert_eq!(nodes.len(), 4);
        assert_eq!(nodes[1].instruction.as_ref().unwrap().address, 0x40058b);
        assert_eq!(nodes[2].instruction.as_ref().unwrap().address, 0x400591);
        assert_eq!(nodes[3].instruction.as_ref().unwrap().address, 0x400597);
        assert_eq!(nodes[3].location, "register:ecx");
    }

    #[test]
    fn slice_from_memory_returns_store_dependency() {
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
        state
            .symbolize_register("al", 8, Some("input_al"))
            .expect("symbolize register");

        let lir = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x401000),
            effects: vec![LirEffect::Store {
                space: crate::irs::lir::LirAddressSpace::Default,
                addr: LirExpression::Const {
                    value: 0x3000,
                    bits: 64,
                },
                expression: LirExpression::Read(Box::new(LirLocation::Register {
                    name: "al".to_string(),
                    bits: 8,
                })),
                bits: 8,
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
        let slice = states[0]
            .slice_from_memory(0x3000, 1)
            .expect("slice memory");
        let nodes = slice.nodes();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[1].instruction.as_ref().unwrap().address, 0x401000);
        assert_eq!(nodes[1].location, "memory[0x3000]");
    }

    #[test]
    fn slice_from_register_preserves_x86_subregister_dependencies() {
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::AMD64).expect("cpu"));
        state
            .symbolize_memory(0x1000, 1, Some("input"))
            .expect("symbolize memory");
        state.set_register("rdi", 64, 0x1000).expect("set register");

        let first = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x40058b),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Load {
                    space: crate::irs::lir::LirAddressSpace::Default,
                    addr: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "rdi".to_string(),
                        bits: 64,
                    }))),
                    bits: 8,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let second = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x40058e),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Cast {
                    op: crate::irs::lir::LirOperationCast::SignExtend,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "al".to_string(),
                        bits: 8,
                    }))),
                    bits: 32,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let third = LirInstruction {
            status: LirStatus::Complete,
            address: Some(0x400597),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "ecx".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Read(Box::new(LirLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                })),
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![first, second, third]), &state, None)
            .expect("run");
        let slice = states[0]
            .slice_from_register("ecx", 32)
            .expect("slice register");
        let addresses = slice
            .nodes()
            .iter()
            .filter_map(|node| {
                node.instruction
                    .as_ref()
                    .map(|instruction| instruction.address)
            })
            .collect::<Vec<_>>();
        assert_eq!(addresses, vec![0x40058b, 0x40058e, 0x400597]);
    }

    #[test]
    fn symbolic_fp_add32_executes() {
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::ARM64).expect("cpu"));
        state
            .set_register("s0", 32, 1.5f32.to_bits() as u64)
            .expect("set register");
        state
            .set_register("s1", 32, 2.25f32.to_bits() as u64)
            .expect("set register");

        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "s2".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Binary {
                    op: LirOperationBinary::FAdd,
                    left: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "s0".to_string(),
                        bits: 32,
                    }))),
                    right: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "s1".to_string(),
                        bits: 32,
                    }))),
                    bits: 32,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::ARM64).expect("cpu"));
        state.set_register("x0", 64, 42).expect("set register");

        let to_float = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "d0".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::IntToFloat,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x0".to_string(),
                        bits: 64,
                    }))),
                    bits: 64,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };
        let from_float = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x1".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::FloatToInt,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "d0".to_string(),
                        bits: 64,
                    }))),
                    bits: 64,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![to_float, from_float]), &state, None)
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::ARM64).expect("cpu"));
        state
            .set_register("d0", 64, f64::NAN.to_bits())
            .expect("set register");
        state
            .set_register("d1", 64, 1.0f64.to_bits())
            .expect("set register");

        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x2".to_string(),
                    bits: 1,
                },
                expression: LirExpression::Compare {
                    op: LirOperationCompare::Unordered,
                    left: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "d0".to_string(),
                        bits: 64,
                    }))),
                    right: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "d1".to_string(),
                        bits: 64,
                    }))),
                    bits: 1,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::ARM64).expect("cpu"));
        state
            .set_register("d0", 64, 3.5f64.to_bits())
            .expect("set register");

        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "d1".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Unary {
                    op: LirOperationUnary::Neg,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "d0".to_string(),
                        bits: 64,
                    }))),
                    bits: 64,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
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
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::ARM64).expect("cpu"));

        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "d1".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Unary {
                    op: LirOperationUnary::Neg,
                    arg: Box::new(LirExpression::Const {
                        value: 3.5f64.to_bits() as u128,
                        bits: 64,
                    }),
                    bits: 64,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::ARM64).expect("cpu"));
        state
            .write_memory(0x8000, &3.5f64.to_bits().to_le_bytes())
            .expect("write memory");

        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "d1".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Unary {
                    op: LirOperationUnary::Neg,
                    arg: Box::new(LirExpression::Load {
                        space: crate::irs::lir::LirAddressSpace::Default,
                        addr: Box::new(LirExpression::Const {
                            value: 0x8000,
                            bits: 64,
                        }),
                        bits: 64,
                    }),
                    bits: 64,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::ARM64).expect("cpu"));
        state.set_register("x0", 64, 7).expect("set register");

        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x1".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Unary {
                    op: LirOperationUnary::Neg,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x0".to_string(),
                        bits: 64,
                    }))),
                    bits: 64,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor.step(&lir_of(lir), &state).expect("step");
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 1).expect("set register");
        state.set_register("ebx", 32, 2).expect("set register");

        let to_fp80_left = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::IntToFloat,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    }))),
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let to_fp80_right = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st1".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::IntToFloat,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "ebx".to_string(),
                        bits: 32,
                    }))),
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let compare = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "ecx".to_string(),
                    bits: 1,
                },
                expression: LirExpression::Compare {
                    op: LirOperationCompare::Olt,
                    left: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))),
                    right: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st1".to_string(),
                        bits: 80,
                    }))),
                    bits: 1,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(
                &lir_many(vec![to_fp80_left, to_fp80_right, compare]),
                &state,
                None,
            )
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 42).expect("set register");

        let to_fp80 = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::IntToFloat,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    }))),
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let truncate = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "xmm0".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::FloatTruncate,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))),
                    bits: 64,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![to_fp80, truncate]), &state, None)
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 7).expect("set register");
        state.set_register("ebx", 32, 2).expect("set register");

        let lhs = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::IntToFloat,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    }))),
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let rhs = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st1".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::IntToFloat,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "ebx".to_string(),
                        bits: 32,
                    }))),
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let add = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.add".to_string(),
                    args: vec![
                        LirExpression::Read(Box::new(LirLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        })),
                        LirExpression::Read(Box::new(LirLocation::Register {
                            name: "x87_st1".to_string(),
                            bits: 80,
                        })),
                    ],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let store = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "xmm0".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![lhs, rhs, add, store]), &state, None)
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state
            .write_memory(0x9000, &3.25f32.to_bits().to_le_bytes())
            .expect("write memory");

        let load = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.load_f32".to_string(),
                    args: vec![LirExpression::Load {
                        space: crate::irs::lir::LirAddressSpace::Default,
                        addr: Box::new(LirExpression::Const {
                            value: 0x9000,
                            bits: 32,
                        }),
                        bits: 32,
                    }],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let store = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "xmm0".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![load, store]), &state, None)
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
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));

        let load = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.const_pi".to_string(),
                    args: Vec::new(),
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let store = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Store {
                space: crate::irs::lir::LirAddressSpace::Default,
                addr: LirExpression::Const {
                    value: 0xA000,
                    bits: 32,
                },
                expression: LirExpression::Extract {
                    arg: Box::new(LirExpression::Intrinsic {
                        name: "x86.x87.store_i32".to_string(),
                        args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        }))],
                        bits: 80,
                    }),
                    lsb: 0,
                    bits: 32,
                },
                bits: 32,
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![load, store]), &state, None)
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 7).expect("set register");
        state.set_register("ebx", 32, 2).expect("set register");

        let to_fp80 = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::IntToFloat,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    }))),
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let divide = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Set {
                    dst: LirLocation::Register {
                        name: "x87_st1".to_string(),
                        bits: 80,
                    },
                    expression: LirExpression::Cast {
                        op: LirOperationCast::IntToFloat,
                        arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                            name: "ebx".to_string(),
                            bits: 32,
                        }))),
                        bits: 80,
                    },
                },
                LirEffect::Set {
                    dst: LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    },
                    expression: LirExpression::Intrinsic {
                        name: "x86.x87.div".to_string(),
                        args: vec![
                            LirExpression::Read(Box::new(LirLocation::Register {
                                name: "x87_st0".to_string(),
                                bits: 80,
                            })),
                            LirExpression::Read(Box::new(LirLocation::Register {
                                name: "x87_st1".to_string(),
                                bits: 80,
                            })),
                        ],
                        bits: 80,
                    },
                },
            ],
            terminator: LirTerminator::FallThrough,
        };

        let store = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Store {
                space: crate::irs::lir::LirAddressSpace::Default,
                addr: LirExpression::Const {
                    value: 0xA100,
                    bits: 32,
                },
                expression: LirExpression::Extract {
                    arg: Box::new(LirExpression::Intrinsic {
                        name: "x86.x87.store_i32_trunc".to_string(),
                        args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        }))],
                        bits: 80,
                    }),
                    lsb: 0,
                    bits: 32,
                },
                bits: 32,
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![to_fp80, divide, store]), &state, None)
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state
            .set_register("xmm0", 64, (-0.0f64).to_bits())
            .expect("set register");

        let load = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::FloatExtend,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "xmm0".to_string(),
                        bits: 64,
                    }))),
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Intrinsic {
                name: "x86.x87.xam".to_string(),
                args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                }))],
                outputs: vec![
                    LirLocation::Register {
                        name: "c0".to_string(),
                        bits: 1,
                    },
                    LirLocation::Register {
                        name: "c1".to_string(),
                        bits: 1,
                    },
                    LirLocation::Register {
                        name: "c2".to_string(),
                        bits: 1,
                    },
                    LirLocation::Register {
                        name: "c3".to_string(),
                        bits: 1,
                    },
                ],
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![load, lir]), &state, None)
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state
            .set_register("xmm0", 64, f64::INFINITY.to_bits())
            .expect("set register");

        let load = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::FloatExtend,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "xmm0".to_string(),
                        bits: 64,
                    }))),
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Intrinsic {
                name: "x86.x87.xam".to_string(),
                args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                }))],
                outputs: vec![
                    LirLocation::Register {
                        name: "c0".to_string(),
                        bits: 1,
                    },
                    LirLocation::Register {
                        name: "c1".to_string(),
                        bits: 1,
                    },
                    LirLocation::Register {
                        name: "c2".to_string(),
                        bits: 1,
                    },
                    LirLocation::Register {
                        name: "c3".to_string(),
                        bits: 1,
                    },
                ],
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![load, lir]), &state, None)
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state
            .set_register("xmm0", 64, 0.0f64.to_bits())
            .expect("set register");

        let load = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::FloatExtend,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "xmm0".to_string(),
                        bits: 64,
                    }))),
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let sin = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.sin".to_string(),
                    args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let store = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![load, sin, store]), &state, None)
            .expect("run");
        let value = states[0]
            .evaluate_register("xmm1", 64)
            .expect("eval")
            .expect("value");
        assert!(f64::from_bits(value).abs() < 1e-300);
    }

    #[test]
    fn symbolic_x87_cos_executes() {
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state
            .set_register("xmm0", 64, 0.0f64.to_bits())
            .expect("set register");

        let load = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::FloatExtend,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "xmm0".to_string(),
                        bits: 64,
                    }))),
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let cos = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.cos".to_string(),
                    args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let store = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![load, cos, store]), &state, None)
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 1).expect("set register");

        let lhs = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Set {
                    dst: LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    },
                    expression: LirExpression::Cast {
                        op: LirOperationCast::IntToFloat,
                        arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        }))),
                        bits: 80,
                    },
                },
                LirEffect::Set {
                    dst: LirLocation::Register {
                        name: "x87_st1".to_string(),
                        bits: 80,
                    },
                    expression: LirExpression::Cast {
                        op: LirOperationCast::IntToFloat,
                        arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        }))),
                        bits: 80,
                    },
                },
            ],
            terminator: LirTerminator::FallThrough,
        };

        let atan2 = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st1".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.atan2".to_string(),
                    args: vec![
                        LirExpression::Read(Box::new(LirLocation::Register {
                            name: "x87_st1".to_string(),
                            bits: 80,
                        })),
                        LirExpression::Read(Box::new(LirLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        })),
                    ],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let store = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st1".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![lhs, atan2, store]), &state, None)
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 3).expect("set register");
        state.set_register("ebx", 32, 2).expect("set register");

        let load = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Set {
                    dst: LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    },
                    expression: LirExpression::Cast {
                        op: LirOperationCast::IntToFloat,
                        arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        }))),
                        bits: 80,
                    },
                },
                LirEffect::Set {
                    dst: LirLocation::Register {
                        name: "x87_st1".to_string(),
                        bits: 80,
                    },
                    expression: LirExpression::Cast {
                        op: LirOperationCast::IntToFloat,
                        arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                            name: "ebx".to_string(),
                            bits: 32,
                        }))),
                        bits: 80,
                    },
                },
            ],
            terminator: LirTerminator::FallThrough,
        };

        let scale = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.scale".to_string(),
                    args: vec![
                        LirExpression::Read(Box::new(LirLocation::Register {
                            name: "x87_st0".to_string(),
                            bits: 80,
                        })),
                        LirExpression::Read(Box::new(LirLocation::Register {
                            name: "x87_st1".to_string(),
                            bits: 80,
                        })),
                    ],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let store = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![load, scale, store]), &state, None)
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 1).expect("set register");

        let load = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::IntToFloat,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    }))),
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let op = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.f2xm1".to_string(),
                    args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let store = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![load, op, store]), &state, None)
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
        let executor = LirExecutor::new();
        let state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));

        let load = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.load_bcd".to_string(),
                    args: vec![LirExpression::Const {
                        value: 0x80000001234567890123,
                        bits: 80,
                    }],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let store = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "xmm1".to_string(),
                    bits: 64,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.store_f64".to_string(),
                    args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![load, store]), &state, None)
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
        let executor = LirExecutor::new();
        let mut state =
            LirExecutorState::new(LirCpu::from_architecture(Architecture::I386).expect("cpu"));
        state.set_register("eax", 32, 42).expect("set register");

        let load = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "x87_st0".to_string(),
                    bits: 80,
                },
                expression: LirExpression::Cast {
                    op: LirOperationCast::IntToFloat,
                    arg: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    }))),
                    bits: 80,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        let store = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Store {
                space: crate::irs::lir::LirAddressSpace::Default,
                addr: LirExpression::Const {
                    value: 0xA200,
                    bits: 32,
                },
                expression: LirExpression::Intrinsic {
                    name: "x86.x87.store_bcd".to_string(),
                    args: vec![LirExpression::Read(Box::new(LirLocation::Register {
                        name: "x87_st0".to_string(),
                        bits: 80,
                    }))],
                    bits: 80,
                },
                bits: 80,
            }],
            terminator: LirTerminator::FallThrough,
        };

        let states = executor
            .run(&lir_many(vec![load, store]), &state, None)
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
