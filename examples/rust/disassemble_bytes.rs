// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::collections::{BTreeMap, BTreeSet};

use binlex::controlflow::Graph;
use binlex::disassemblers::capstone::Disassembler;
use binlex::{Architecture, Config};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new();

    // xor rax, rax; ret
    let code: Vec<u8> = vec![0x48, 0x31, 0xc0, 0xc3];

    let mut ranges = BTreeMap::new();
    ranges.insert(0, code.len() as u64);

    let entrypoints = BTreeSet::from([0_u64]);

    let disassembler = Disassembler::from_bytes(Architecture::AMD64, &code, ranges, config.clone())?;
    let mut graph = Graph::new(Architecture::AMD64, config);
    disassembler.disassemble(entrypoints, &mut graph)?;

    println!("instructions: {}", graph.instructions().len());
    println!("blocks: {}", graph.blocks().len());
    println!("functions: {}", graph.functions().len());

    if let Some(function) = graph.functions().first() {
        println!("first function address: 0x{:x}", function.address());
        println!("first function size: {}", function.size());
    }

    Ok(())
}
