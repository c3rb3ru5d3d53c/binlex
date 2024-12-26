use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct VecNode {
    id: u64,
    properties: BTreeMap<String, Vec<f64>>,
    children: Vec<VecNode>,
    parents: Vec<VecNode>,
}

impl VecNode {
    pub fn new(id: u64) -> Self {
        VecNode {
            id,
            properties: BTreeMap::new(),
            children: Vec::new(),
            parents: Vec::new(),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn children(&self) -> &Vec<VecNode> {
        &self.children
    }

    pub fn parents(&self) -> &Vec<VecNode> {
        &self.parents
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

    pub fn add_child(&mut self, mut child: VecNode) {
        if !self.children.iter().any(|c| c.id == child.id) {
            self.children.push(child.clone());
        }

        if !child.parents.iter().any(|p| p.id == self.id) {
            child.parents.push(self.clone());
        }
    }

    pub fn add_parent(&mut self, mut parent: VecNode) {
        if !self.parents.iter().any(|p| p.id == parent.id) {
            self.parents.push(parent.clone());
        }

        if !parent.children.iter().any(|c| c.id == self.id) {
            parent.children.push(self.clone());
        }
    }

    pub fn print(&self) {
        self.print_internal(0);
    }

    fn print_internal(&self, depth: usize) {
        let indent = "  ".repeat(depth);
        println!("{}Node ID: {}", indent, self.id);

        if self.properties.is_empty() {
            println!("{}  Properties: None", indent);
        } else {
            println!("{}  Properties:", indent);
            for (key, values) in &self.properties {
                println!("{}    {}: {:?}", indent, key, values);
            }
        }

        if self.parents.is_empty() {
            println!("{}  Parents: None", indent);
        } else {
            println!(
                "{}  Parents: {:?}",
                indent,
                self.parents.iter().map(|p| p.id).collect::<Vec<_>>()
            );
        }

        if self.children.is_empty() {
            println!("{}  Children: None", indent);
        } else {
            println!("{}  Children:", indent);
            for child in &self.children {
                child.print_internal(depth + 1);
            }
        }
    }

    pub fn to_vec(&self) -> Vec<f64> {
        fn encode_tree(
            node: &VecNode,
            depth: usize,
            visited: &mut HashSet<u64>,
            id_to_index: &mut HashMap<u64, usize>,
            next_index: &mut usize,
        ) -> Vec<f64> {
            let mut node_vector = Vec::new();

            if visited.contains(&node.id) {
                let reference_index = *id_to_index.get(&node.id).unwrap();
                node_vector.push(reference_index as f64);
                return node_vector;
            }

            visited.insert(node.id);

            let index = *id_to_index.entry(node.id).or_insert_with(|| {
                let current = *next_index;
                *next_index += 1;
                current
            });

            node_vector.push(index as f64);
            node_vector.push(depth as f64);
            for values in node.properties.values() {
                node_vector.extend(values);
            }

            for child in &node.children {
                let child_vector =
                    encode_tree(child, depth + 1, visited, id_to_index, next_index);
                node_vector.extend(child_vector);
            }

            node_vector
        }

        let mut visited = HashSet::new();
        let mut id_to_index = HashMap::new();
        let mut next_index = 0;

        encode_tree(self, 0, &mut visited, &mut id_to_index, &mut next_index)
    }
}
