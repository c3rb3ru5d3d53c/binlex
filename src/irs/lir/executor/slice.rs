#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SliceInstruction {
    pub address: u64,
}

impl SliceInstruction {
    pub(crate) fn from_address(address: u64) -> Self {
        Self { address }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SliceNode {
    pub id: u64,
    pub instruction: Option<SliceInstruction>,
    pub location: String,
    pub value: String,
    pub parents: Vec<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Slice {
    nodes: Vec<SliceNode>,
}

impl Slice {
    pub(crate) fn new(nodes: Vec<SliceNode>) -> Self {
        Self { nodes }
    }

    pub fn nodes(&self) -> &[SliceNode] {
        &self.nodes
    }

    pub fn number_of_nodes(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}
