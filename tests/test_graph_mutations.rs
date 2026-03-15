use binlex::controlflow::{Graph, Instruction};
use binlex::{Architecture, Config};

#[test]
fn graph_mutations_track_structural_updates() {
    let config = Config::default();
    let mut graph = Graph::new(Architecture::AMD64, config.clone());

    assert_eq!(graph.mutations(), 0);

    let mut instruction = Instruction::create(0x1000, Architecture::AMD64, config);
    instruction.bytes = vec![0xC3];
    instruction.pattern = "c3".to_string();
    instruction.is_return = true;

    graph.insert_instruction(instruction);
    assert_eq!(graph.mutations(), 1);

    assert!(graph.set_block(0x1000));
    assert_eq!(graph.mutations(), 3);

    assert!(graph.set_function(0x1000));
    assert_eq!(graph.mutations(), 5);
}
