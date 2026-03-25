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
        .imaging()
        .expect("contiguous function should expose imaging")
        .linear(None, None)
        .grayscale()
        .png();
    let svg = function
        .imaging()
        .expect("contiguous function should expose imaging")
        .linear(None, None)
        .grayscale()
        .svg();

    assert!(png.phash().is_some());
    assert!(png.ahash().is_some());
    assert!(png.dhash().is_some());
    assert_eq!(
        png.phash().and_then(|hash| hash.hexdigest()),
        svg.phash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.ahash().and_then(|hash| hash.hexdigest()),
        svg.ahash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.dhash().and_then(|hash| hash.hexdigest()),
        svg.dhash().and_then(|hash| hash.hexdigest())
    );
}

#[test]
fn function_imaging_pipeline_materializes_existing_renderers() {
    let graph = sample_graph();
    let function = Function::new(0x1000, &graph).expect("function should exist");

    let png = function
        .imaging()
        .expect("contiguous function should expose imaging")
        .linear(None, None)
        .grayscale()
        .png();
    let terminal = function
        .imaging()
        .expect("contiguous function should expose imaging")
        .linear(None, None)
        .grayscale()
        .terminal();

    assert!(png.phash().is_some());
    assert_eq!(
        png.phash().and_then(|hash| hash.hexdigest()),
        terminal.phash().and_then(|hash| hash.hexdigest())
    );
}

#[test]
fn block_images_expose_existing_hash_accessors() {
    let graph = sample_graph();
    let block = Block::new(0x1000, &graph).expect("block should exist");

    let png = block.imaging().linear(None, None).grayscale().png();
    let svg = block.imaging().linear(None, None).grayscale().svg();

    assert!(png.phash().is_some());
    assert!(png.ahash().is_some());
    assert!(png.dhash().is_some());
    assert_eq!(
        png.phash().and_then(|hash| hash.hexdigest()),
        svg.phash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.ahash().and_then(|hash| hash.hexdigest()),
        svg.ahash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.dhash().and_then(|hash| hash.hexdigest()),
        svg.dhash().and_then(|hash| hash.hexdigest())
    );
}

#[test]
fn instruction_images_expose_existing_hash_accessors() {
    let graph = sample_graph();
    let instruction = Instruction::new(0x1000, &graph).expect("instruction should exist");

    let png = instruction.imaging().linear(None, None).grayscale().png();
    let svg = instruction.imaging().linear(None, None).grayscale().svg();

    assert!(png.phash().is_some());
    assert!(png.ahash().is_some());
    assert!(png.dhash().is_some());
    assert_eq!(
        png.phash().and_then(|hash| hash.hexdigest()),
        svg.phash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.ahash().and_then(|hash| hash.hexdigest()),
        svg.ahash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.dhash().and_then(|hash| hash.hexdigest()),
        svg.dhash().and_then(|hash| hash.hexdigest())
    );
}
