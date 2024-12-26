use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone)]
pub struct VecNode {
    id: u64,
    properties: BTreeMap<String, Vec<f64>>,
    relationships: Vec<u64>,
}

impl VecNode {
    pub fn new(id: u64) -> Self {
        VecNode {
            id,
            properties: BTreeMap::new(),
            relationships: Vec::new(),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn relationships(&self) -> &Vec<u64> {
        &self.relationships
    }

    pub fn add_property(&mut self, key: &str, value: f64) {
        self.properties
            .entry(key.to_string())
            .or_insert(Vec::new())
            .push(value);
    }

    pub fn add_properties(&mut self, key: &str, values: Vec<f64>) {
        self.properties
            .entry(key.to_string())
            .or_insert(Vec::new())
            .extend(values);
    }

    pub fn add_relationship(&mut self, id: u64) {
        if !self.relationships.contains(&id) {
            self.relationships.push(id);
        }
    }
}

#[derive(Debug)]
pub struct VecGraph {
    nodes: HashMap<u64, VecNode>,
}

impl VecGraph {
    pub fn new() -> Self {
        VecGraph {
            nodes: HashMap::new(),
        }
    }

    pub fn insert_node(&mut self, node: VecNode) {
        self.nodes.insert(node.id(), node);
    }

    pub fn get_node(&self, id: u64) -> Option<&VecNode> {
        self.nodes.get(&id)
    }

    pub fn add_relationship(&mut self, node1_id: u64, node2_id: u64) {
        if let Some(node1) = self.nodes.get_mut(&node1_id) {
            node1.add_relationship(node2_id);
        }
        if let Some(node2) = self.nodes.get_mut(&node2_id) {
            node2.add_relationship(node1_id);
        }
    }

    pub fn print(&self) {
        for node in self.nodes.values() {
            println!("Node ID: {}", node.id);
            println!("  Properties:");
            for (key, values) in &node.properties {
                println!("    {}: {:?}", key, values);
            }
            println!("  Relationships: {:?}", node.relationships);
        }
    }

    pub fn to_vec(&self) -> Vec<f64> {
        let mut graph_vector = Vec::new();
        let mut visited = HashMap::new();
        let mut next_index = 0;

        for node in self.nodes.values() {
            if !visited.contains_key(&node.id) {
                self.encode_node(node, &mut graph_vector, &mut visited, &mut next_index);
            }
        }

        graph_vector
    }

    fn encode_node(
        &self,
        node: &VecNode,
        graph_vector: &mut Vec<f64>,
        visited: &mut HashMap<u64, usize>,
        next_index: &mut usize,
    ) {
        let index = *visited.entry(node.id).or_insert_with(|| {
            let current = *next_index;
            *next_index += 1;
            current
        });

        graph_vector.push(index as f64);
        for values in node.properties.values() {
            graph_vector.extend(values);
        }

        for related_id in &node.relationships {
            if let Some(related_index) = visited.get(related_id) {
                graph_vector.push(*related_index as f64);
            }
        }
    }
}
