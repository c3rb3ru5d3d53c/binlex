use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub(crate) struct Arm64Fixture {
    pub registers: Vec<(&'static str, u128)>,
    pub memory: Vec<(u64, Vec<u8>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Arm64CpuState {
    pub registers: BTreeMap<String, u128>,
    pub pc: u64,
    pub memory: BTreeMap<u64, u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Arm64Transition {
    pub pre: Arm64CpuState,
    pub post: Arm64CpuState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Arm64Execution {
    pub transition: Arm64Transition,
    pub memory_writes: Vec<(u64, usize)>,
}
