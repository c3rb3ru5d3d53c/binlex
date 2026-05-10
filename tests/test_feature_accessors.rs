use binlex::Architecture;
use binlex::Configuration;
use binlex::controlflow::{Block, Function, Graph, Instruction, Reference};
use binlex::formats::file::File;
use binlex::genetics::Chromosome;
use binlex::imaging::{Imaging, PNG, Palette, SVG, Terminal};

#[test]
fn file_direct_accessors_ignore_serialization_flags() {
    let mut config = Configuration::default();
    config.formats.file.sha256.enabled = false;
    config.formats.file.tlsh.enabled = false;
    config.formats.file.entropy.enabled = false;

    let file = File::from_bytes(
        vec![
            0x3A, 0x7F, 0x92, 0x5C, 0xE4, 0xA1, 0xD8, 0x47, 0x29, 0xB3, 0x1E, 0x8D, 0x4F, 0x6A,
            0xCD, 0x72, 0x90, 0x33, 0xB6, 0xF1, 0xD4, 0x5E, 0xAA, 0x64, 0x13, 0xFA, 0x38, 0x9C,
            0x41, 0xB8, 0xD0, 0xE7, 0x6F, 0x25, 0xA9, 0x54, 0x1B, 0xC2, 0x8E, 0xF5, 0x77, 0x3D,
            0xAC, 0x12, 0x8A, 0x9E, 0x6B, 0xC7, 0x5A, 0xEF,
        ],
        config,
    );

    assert!(file.sha256().is_some());
    assert!(file.tlsh().is_some());
    assert!(file.entropy().is_some());

    let value: serde_json::Value =
        serde_json::from_str(&file.json().expect("file json should serialize"))
            .expect("file json should parse");
    assert!(value.get("sha256").is_none());
    assert!(value.get("tlsh").is_none());
    assert!(value.get("entropy").is_none());
}

#[test]
fn chromosome_direct_accessors_ignore_serialization_flags() {
    let mut config = Configuration::default();
    config.chromosomes.mask.enabled = false;
    config.chromosomes.masked.enabled = false;
    config.chromosomes.vector.enabled = false;
    config.chromosomes.sha256.enabled = false;
    config.chromosomes.tlsh.enabled = false;
    config.chromosomes.minhash.enabled = false;
    config.chromosomes.entropy.enabled = false;
    let imaging_config = config.clone();

    let chromosome = Chromosome::from_pattern(
        "3a7f925ce4a1d84729b31e8d4f6acd729033b6f1d45eaa6413fa389c41b8d0e76f25a9541bc28ef5773dac128a9e6bc75aef".to_string(),
        config,
    )
    .expect("chromosome should parse");

    assert!(!chromosome.vector().is_empty());
    assert!(chromosome.sha256().is_some());
    assert!(chromosome.tlsh().is_some());
    assert!(chromosome.minhash().is_some());
    assert!(chromosome.entropy().is_some());

    let png = Imaging::new(chromosome.masked(), imaging_config.clone())
        .linear(None, None)
        .grayscale()
        .png();
    let svg = Imaging::new(chromosome.masked(), imaging_config)
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

    let value: serde_json::Value =
        serde_json::from_str(&chromosome.json().expect("chromosome json should serialize"))
            .expect("chromosome json should parse");
    assert!(value.get("mask").is_none());
    assert!(value.get("masked").is_none());
    assert!(value.get("vector").is_none());
    assert!(value.get("sha256").is_none());
    assert!(value.get("tlsh").is_none());
    assert!(value.get("minhash").is_none());
    assert!(value.get("entropy").is_none());
}

#[test]
fn chromosome_imaging_uses_masked_bytes() {
    let config = Configuration::default();
    let chromosome = Chromosome::new(vec![0xAF, 0x12], vec![0x03, 0xF0], config.clone())
        .expect("chromosome should build");

    let direct = PNG::new(&chromosome.masked(), Palette::Grayscale, config.clone());
    let piped = Imaging::new(chromosome.masked(), config)
        .linear(None, None)
        .grayscale()
        .png();

    assert_eq!(
        direct.phash().and_then(|hash| hash.hexdigest()),
        piped.phash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        direct.dhash().and_then(|hash| hash.hexdigest()),
        piped.dhash().and_then(|hash| hash.hexdigest())
    );
}

#[test]
fn chromosome_bytes_zero_masked_bits_without_compaction() {
    let config = Configuration::default();
    let chromosome = Chromosome::new(vec![0xAF, 0x12], vec![0x03, 0xF0], config)
        .expect("chromosome should build");

    assert_eq!(chromosome.bytes(), vec![0xAF, 0x12]);
    assert_eq!(chromosome.mask(), vec![0x03, 0xF0]);
    assert_eq!(chromosome.masked(), vec![0xAC, 0x02]);
    assert_eq!(chromosome.vector(), vec![0xA, 0xC, 0x0, 0x2]);
    assert_eq!(chromosome.pattern(), "a??2");
}

#[test]
fn chromosome_json_includes_mask_and_masked_when_enabled() {
    let mut config = Configuration::default();
    config.chromosomes.mask.enabled = true;
    config.chromosomes.masked.enabled = true;
    config.chromosomes.vector.enabled = false;
    config.chromosomes.sha256.enabled = false;
    config.chromosomes.tlsh.enabled = false;
    config.chromosomes.minhash.enabled = false;
    config.chromosomes.entropy.enabled = false;

    let chromosome = Chromosome::new(vec![0xAF, 0x12], vec![0x03, 0xF0], config)
        .expect("chromosome should build");

    let value: serde_json::Value =
        serde_json::from_str(&chromosome.json().expect("chromosome json should serialize"))
            .expect("chromosome json should parse");

    assert_eq!(
        value.get("mask").and_then(|value| value.as_str()),
        Some("03f0")
    );
    assert_eq!(
        value.get("masked").and_then(|value| value.as_str()),
        Some("ac02")
    );
}

#[test]
fn imaging_direct_accessors_ignore_config_flags() {
    let mut config = Configuration::default();
    config.disable_hashing();

    let data = [0x00, 0x22, 0x44, 0x88, 0xaa, 0xcc, 0xee, 0xff];
    let png = PNG::with_options(&data, Palette::Grayscale, 2, 4, config.clone());
    let svg = SVG::with_options(&data, Palette::Grayscale, 2, 4, config.clone());
    let terminal = Terminal::with_options(&data, Palette::Grayscale, 2, 4, config);

    assert!(png.sha256().is_some());
    assert!(png.tlsh().is_some());
    assert!(png.minhash().is_some());
    assert!(png.ahash().is_some());
    assert!(png.dhash().is_some());
    assert!(png.phash().is_some());

    assert_eq!(
        png.sha256().and_then(|hash| hash.hexdigest()),
        svg.sha256().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.sha256().and_then(|hash| hash.hexdigest()),
        terminal.sha256().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.tlsh().and_then(|hash| hash.hexdigest()),
        svg.tlsh().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.tlsh().and_then(|hash| hash.hexdigest()),
        terminal.tlsh().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.minhash().and_then(|hash| hash.hexdigest()),
        svg.minhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.minhash().and_then(|hash| hash.hexdigest()),
        terminal.minhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.ahash().and_then(|hash| hash.hexdigest()),
        svg.ahash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.ahash().and_then(|hash| hash.hexdigest()),
        terminal.ahash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.dhash().and_then(|hash| hash.hexdigest()),
        svg.dhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.dhash().and_then(|hash| hash.hexdigest()),
        terminal.dhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.phash().and_then(|hash| hash.hexdigest()),
        svg.phash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.phash().and_then(|hash| hash.hexdigest()),
        terminal.phash().and_then(|hash| hash.hexdigest())
    );
}

#[test]
fn function_markov_direct_accessor_ignores_serialization_flag() {
    let mut config = Configuration::default();
    config.functions.markov.enabled = false;

    let mut graph = Graph::new(Architecture::AMD64, config.clone());

    let mut entry = Instruction::create(0x1000, Architecture::AMD64, config.clone());
    entry.bytes = vec![0x90];
    entry.pattern = "90".to_string();
    entry.is_conditional = true;
    entry.to = [0x1002].into_iter().collect();
    graph.insert_instruction(entry);

    let mut left = Instruction::create(0x1001, Architecture::AMD64, config.clone());
    left.bytes = vec![0x90];
    left.pattern = "90".to_string();
    left.is_return = true;
    graph.insert_instruction(left);

    let mut right = Instruction::create(0x1002, Architecture::AMD64, config);
    right.bytes = vec![0xC3];
    right.pattern = "c3".to_string();
    right.is_return = true;
    graph.insert_instruction(right);

    assert!(graph.set_block(0x1000));
    assert!(graph.set_block(0x1001));
    assert!(graph.set_block(0x1002));
    assert!(graph.set_function(0x1000));

    let function = Function::new(0x1000, &graph).expect("function should exist");
    let scores = function.markov();

    assert!(scores.len() >= 2);
    assert!(scores.contains_key(&0x1000));
    let total: f64 = scores.values().sum();
    assert!(
        (total - 1.0).abs() < 1e-9,
        "markov scores should be normalized"
    );

    let value: serde_json::Value =
        serde_json::from_str(&function.json().expect("function json should serialize"))
            .expect("function json should parse");
    assert!(value.get("markov").is_none());
}

#[test]
fn function_markov_serializes_when_enabled() {
    let mut config = Configuration::default();
    config.functions.markov.enabled = true;
    let mut graph = Graph::new(Architecture::AMD64, config.clone());

    let mut entry = Instruction::create(0x1000, Architecture::AMD64, config.clone());
    entry.bytes = vec![0x90];
    entry.pattern = "90".to_string();
    entry.is_conditional = true;
    entry.to = [0x1002].into_iter().collect();
    graph.insert_instruction(entry);

    let mut left = Instruction::create(0x1001, Architecture::AMD64, config.clone());
    left.bytes = vec![0x90];
    left.pattern = "90".to_string();
    left.is_return = true;
    graph.insert_instruction(left);

    let mut right = Instruction::create(0x1002, Architecture::AMD64, config);
    right.bytes = vec![0xC3];
    right.pattern = "c3".to_string();
    right.is_return = true;
    graph.insert_instruction(right);

    assert!(graph.set_block(0x1000));
    assert!(graph.set_block(0x1001));
    assert!(graph.set_block(0x1002));
    assert!(graph.set_function(0x1000));

    let function = Function::new(0x1000, &graph).expect("function should exist");
    let value: serde_json::Value =
        serde_json::from_str(&function.json().expect("function json should serialize"))
            .expect("function json should parse");

    let markov = value
        .get("markov")
        .and_then(|value| value.as_object())
        .expect("markov scores should be serialized");
    assert!(markov.len() >= 2);
    assert!(markov.contains_key("4096"));
}

#[test]
fn function_number_of_blocks_accessor_matches_default_json() {
    let config = Configuration::default();
    let mut graph = Graph::new(Architecture::AMD64, config.clone());

    let mut entry = Instruction::create(0x1000, Architecture::AMD64, config.clone());
    entry.bytes = vec![0x90];
    entry.pattern = "90".to_string();
    entry.is_conditional = true;
    entry.to = [0x1002].into_iter().collect();
    graph.insert_instruction(entry);

    let mut left = Instruction::create(0x1001, Architecture::AMD64, config.clone());
    left.bytes = vec![0x90];
    left.pattern = "90".to_string();
    left.is_return = true;
    graph.insert_instruction(left);

    let mut right = Instruction::create(0x1002, Architecture::AMD64, config);
    right.bytes = vec![0xC3];
    right.pattern = "c3".to_string();
    right.is_return = true;
    graph.insert_instruction(right);

    assert!(graph.set_block(0x1000));
    assert!(graph.set_block(0x1001));
    assert!(graph.set_block(0x1002));
    assert!(graph.set_function(0x1000));

    let function = Function::new(0x1000, &graph).expect("function should exist");
    let number_of_blocks = function.number_of_blocks();
    assert!(number_of_blocks >= 1);

    let value: serde_json::Value =
        serde_json::from_str(&function.json().expect("function json should serialize"))
            .expect("function json should parse");
    assert_eq!(
        value
            .get("number_of_blocks")
            .and_then(|value| value.as_u64()),
        Some(number_of_blocks as u64)
    );
}

#[test]
fn function_call_relationship_accessors_and_json_are_consistent() {
    let config = Configuration::default();
    let mut graph = Graph::new(Architecture::AMD64, config.clone());

    let mut caller_a_call = Instruction::create(0x1000, Architecture::AMD64, config.clone());
    caller_a_call.bytes = vec![0xE8, 0x00, 0x00, 0x00, 0x00];
    caller_a_call.pattern = "e800000000".to_string();
    caller_a_call.is_call = true;
    caller_a_call.functions.insert(0x3000);
    graph.insert_instruction(caller_a_call);

    let mut caller_a_ret = Instruction::create(0x1005, Architecture::AMD64, config.clone());
    caller_a_ret.bytes = vec![0xC3];
    caller_a_ret.pattern = "c3".to_string();
    caller_a_ret.is_return = true;
    graph.insert_instruction(caller_a_ret);

    let mut caller_b_call = Instruction::create(0x2000, Architecture::AMD64, config.clone());
    caller_b_call.bytes = vec![0xE8, 0x00, 0x00, 0x00, 0x00];
    caller_b_call.pattern = "e800000000".to_string();
    caller_b_call.is_call = true;
    caller_b_call.functions.insert(0x3000);
    graph.insert_instruction(caller_b_call);

    let mut caller_b_ret = Instruction::create(0x2005, Architecture::AMD64, config.clone());
    caller_b_ret.bytes = vec![0xC3];
    caller_b_ret.pattern = "c3".to_string();
    caller_b_ret.is_return = true;
    graph.insert_instruction(caller_b_ret);

    let mut callee_ret = Instruction::create(0x3000, Architecture::AMD64, config);
    callee_ret.bytes = vec![0xC3];
    callee_ret.pattern = "c3".to_string();
    callee_ret.is_return = true;
    graph.insert_instruction(callee_ret);

    assert!(graph.set_block(0x1000));
    assert!(graph.set_block(0x2000));
    assert!(graph.set_block(0x3000));
    assert!(graph.set_function(0x1000));
    assert!(graph.set_function(0x2000));
    assert!(graph.set_function(0x3000));

    let caller_a = Function::new(0x1000, &graph).expect("caller A should exist");
    let callee = Function::new(0x3000, &graph).expect("callee should exist");
    let caller_a_block = Block::new(0x1000, &graph).expect("caller A block should exist");
    let caller_a_instruction =
        Instruction::new(0x1000, &graph).expect("caller A instruction should exist");

    assert_eq!(caller_a.callee_references().get(&0x1000), Some(&0x3000));
    assert_eq!(caller_a.callees().len(), 1);
    assert_eq!(caller_a.callees()[0].address(), 0x3000);
    assert_eq!(caller_a_instruction.callees().len(), 1);
    assert_eq!(caller_a_instruction.callees()[0].address(), 0x3000);
    assert_eq!(
        caller_a_instruction.callee_references(),
        vec![Reference::new(0x1000, 0x3000)]
    );
    assert_eq!(caller_a_block.callees().len(), 1);
    assert_eq!(caller_a_block.callees()[0].address(), 0x3000);
    assert_eq!(
        caller_a_block.callee_references(),
        vec![Reference::new(0x1000, 0x3000)]
    );

    let caller_addresses: std::collections::BTreeSet<u64> = callee
        .callers()
        .into_iter()
        .map(|function| function.address())
        .collect();
    assert_eq!(
        caller_addresses,
        [0x1000_u64, 0x2000_u64].into_iter().collect()
    );
    assert_eq!(callee.caller_references().get(&0x1000), Some(&0x1000));
    assert_eq!(callee.caller_references().get(&0x2000), Some(&0x2000));

    let value: serde_json::Value = serde_json::from_str(
        &caller_a_instruction
            .json()
            .expect("instruction json should serialize"),
    )
    .expect("instruction json should parse");
    assert!(value.get("functions").is_none());
    let callees = value
        .get("callee_references")
        .and_then(|value| value.as_array())
        .expect("instruction callee references should be serialized");
    assert_eq!(callees.len(), 1);
    assert_eq!(
        callees[0].get("location").and_then(|value| value.as_u64()),
        Some(0x1000)
    );
    assert_eq!(
        callees[0].get("address").and_then(|value| value.as_u64()),
        Some(0x3000)
    );

    let value: serde_json::Value =
        serde_json::from_str(&caller_a_block.json().expect("block json should serialize"))
            .expect("block json should parse");
    assert!(value.get("functions").is_none());
    let callees = value
        .get("callee_references")
        .and_then(|value| value.as_array())
        .expect("block callee references should be serialized");
    assert_eq!(callees.len(), 1);
    assert_eq!(
        callees[0].get("location").and_then(|value| value.as_u64()),
        Some(0x1000)
    );
    assert_eq!(
        callees[0].get("address").and_then(|value| value.as_u64()),
        Some(0x3000)
    );

    let value: serde_json::Value =
        serde_json::from_str(&callee.json().expect("function json should serialize"))
            .expect("function json should parse");
    assert_eq!(
        value
            .get("caller_references")
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("4096"))
            .and_then(|value| value.as_u64()),
        Some(0x1000)
    );
    assert_eq!(
        value
            .get("caller_references")
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("8192"))
            .and_then(|value| value.as_u64()),
        Some(0x2000)
    );
}

#[test]
fn block_relationship_accessors_and_json_are_consistent() {
    let config = Configuration::default();
    let mut graph = Graph::new(Architecture::AMD64, config.clone());

    let mut branch = Instruction::create(0x1000, Architecture::AMD64, config.clone());
    branch.bytes = vec![0x75, 0x03];
    branch.pattern = "7503".to_string();
    branch.is_jump = true;
    branch.is_conditional = true;
    branch.to = [0x1005].into_iter().collect();
    branch.edges = 2;
    graph.insert_instruction(branch);

    let mut fallthrough_ret = Instruction::create(0x1002, Architecture::AMD64, config.clone());
    fallthrough_ret.bytes = vec![0xC3];
    fallthrough_ret.pattern = "c3".to_string();
    fallthrough_ret.is_return = true;
    graph.insert_instruction(fallthrough_ret);

    let mut target_ret = Instruction::create(0x1005, Architecture::AMD64, config);
    target_ret.bytes = vec![0xC3];
    target_ret.pattern = "c3".to_string();
    target_ret.is_return = true;
    graph.insert_instruction(target_ret);

    assert!(graph.set_block(0x1000));
    assert!(graph.set_block(0x1002));
    assert!(graph.set_block(0x1005));

    let branch_instruction =
        Instruction::new(0x1000, &graph).expect("branch instruction should exist");
    let entry = Block::new(0x1000, &graph).expect("entry block should exist");
    let target = Block::new(0x1005, &graph).expect("target block should exist");

    let instruction_successor_addresses: std::collections::BTreeSet<u64> = branch_instruction
        .successor_blocks()
        .into_iter()
        .map(|block| block.address())
        .collect();
    assert_eq!(
        instruction_successor_addresses,
        [0x1002_u64, 0x1005_u64].into_iter().collect()
    );
    assert_eq!(
        branch_instruction.successor_block_references(),
        vec![
            Reference::new(0x1000, 0x1002),
            Reference::new(0x1000, 0x1005)
        ]
    );

    let successor_addresses: std::collections::BTreeSet<u64> = entry
        .successors()
        .into_iter()
        .map(|block| block.address())
        .collect();
    assert_eq!(
        successor_addresses,
        [0x1002_u64, 0x1005_u64].into_iter().collect()
    );
    assert_eq!(
        entry.successor_references(),
        vec![
            Reference::new(0x1000, 0x1002),
            Reference::new(0x1000, 0x1005)
        ]
    );

    let predecessor_addresses: std::collections::BTreeSet<u64> = target
        .predecessors()
        .into_iter()
        .map(|block| block.address())
        .collect();
    assert_eq!(predecessor_addresses, [0x1000_u64].into_iter().collect());
    assert_eq!(
        target.predecessor_references(),
        vec![Reference::new(0x1000, 0x1005)]
    );

    let value: serde_json::Value = serde_json::from_str(
        &branch_instruction
            .json()
            .expect("instruction json should serialize"),
    )
    .expect("instruction json should parse");
    assert!(value.get("blocks").is_none());
    let successors = value
        .get("successor_block_references")
        .and_then(|value| value.as_array())
        .expect("instruction successor block references should be serialized");
    assert_eq!(successors.len(), 2);

    let value: serde_json::Value =
        serde_json::from_str(&entry.json().expect("block json should serialize"))
            .expect("block json should parse");
    assert!(value.get("blocks").is_none());
    let successors = value
        .get("successor_references")
        .and_then(|value| value.as_array())
        .expect("successor references should be serialized");
    assert_eq!(successors.len(), 2);
}
