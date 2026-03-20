use binlex::controlflow::{Block, Function, Graph, Instruction};
use binlex::{Architecture, Config};

fn sample_graph() -> Graph {
    let config = Config::default();
    let mut graph = Graph::new(Architecture::AMD64, config.clone());

    let mut instruction = Instruction::create(0x1000, Architecture::AMD64, config);
    instruction.bytes = vec![0x00, 0x22, 0x44, 0x88, 0xaa, 0xcc, 0xee, 0xff];
    instruction.pattern = "00224488aacceeff".to_string();
    instruction.is_return = true;

    graph.insert_instruction(instruction);
    assert!(graph.set_block(0x1000));
    assert!(graph.set_function(0x1000));

    graph
}

#[test]
fn function_images_expose_existing_hash_accessors() {
    let graph = sample_graph();
    let function = Function::new(0x1000, &graph).expect("function should exist");

    let png = function
        .png()
        .expect("contiguous function should render to PNG");
    let svg = function
        .svg()
        .expect("contiguous function should render to SVG");

    assert!(png.phash().is_some());
    assert!(png.ahash().is_some());
    assert!(png.dhash().is_some());
    assert_eq!(png.phash(), svg.phash());
    assert_eq!(png.ahash(), svg.ahash());
    assert_eq!(png.dhash(), svg.dhash());
}

#[test]
fn block_images_expose_existing_hash_accessors() {
    let graph = sample_graph();
    let block = Block::new(0x1000, &graph).expect("block should exist");

    let png = block.png();
    let svg = block.svg();

    assert!(png.phash().is_some());
    assert!(png.ahash().is_some());
    assert!(png.dhash().is_some());
    assert_eq!(png.phash(), svg.phash());
    assert_eq!(png.ahash(), svg.ahash());
    assert_eq!(png.dhash(), svg.dhash());
}

#[test]
fn instruction_images_expose_existing_hash_accessors() {
    let graph = sample_graph();
    let instruction = Instruction::new(0x1000, &graph).expect("instruction should exist");

    let png = instruction.png();
    let svg = instruction.svg();

    assert!(png.phash().is_some());
    assert!(png.ahash().is_some());
    assert!(png.dhash().is_some());
    assert_eq!(png.phash(), svg.phash());
    assert_eq!(png.ahash(), svg.ahash());
    assert_eq!(png.dhash(), svg.dhash());
}
