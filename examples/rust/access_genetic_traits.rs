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

use binlex::controlflow::{Block, Function, Graph, Instruction};
use binlex::{Architecture, Config};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new();
    let mut cfg = Graph::new(Architecture::AMD64, config.clone());

    let mut instruction = Instruction::create(0x1000, Architecture::AMD64, config);
    instruction.bytes = vec![0x48, 0x31, 0xc0, 0xc3];
    instruction.pattern = "4831c0c3".to_string();
    instruction.is_return = true;
    cfg.insert_instruction(instruction);

    cfg.instructions.insert_processed(0x1000);
    cfg.instructions.insert_valid(0x1000);
    cfg.set_block(0x1000);
    cfg.set_function(0x1000);

    for address in cfg.instructions.valid_addresses() {
        let instruction = Instruction::new(address, &cfg)?;
        instruction.print();
    }

    for address in cfg.blocks.valid_addresses() {
        let block = Block::new(address, &cfg)?;
        block.print();
    }

    for address in cfg.functions.valid_addresses() {
        let function = Function::new(address, &cfg)?;
        function.print();
    }

    Ok(())
}
