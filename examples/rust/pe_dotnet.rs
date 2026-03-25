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

use binlex::Config;
use binlex::controlflow::Graph;
use binlex::disassemblers::cil::Disassembler;
use binlex::formats::PE;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "rust_pe_dotnet".to_string());
    let input = match args.next() {
        Some(path) => path,
        None => {
            eprintln!("usage: {} <dotnet-pe-file>", program);
            std::process::exit(1);
        }
    };

    let mut config = Config::new();
    config.general.threads = 16;

    let pe = PE::new(input, config.clone())?;
    if !pe.is_dotnet() {
        return Err("input is not a .NET PE".into());
    }

    let mut mapped_file = pe.image()?;
    let image = mapped_file.mmap()?;

    let disassembler = Disassembler::new(
        pe.architecture(),
        image,
        pe.dotnet_metadata_token_virtual_addresses(),
        pe.dotnet_executable_virtual_address_ranges(),
        config.clone(),
    )?;

    let mut cfg = Graph::new(pe.architecture(), config);
    disassembler.disassemble(pe.dotnet_entrypoint_virtual_addresses(), &mut cfg)?;

    println!("instructions: {}", cfg.instructions().len());
    println!("blocks: {}", cfg.blocks().len());
    println!("functions: {}", cfg.functions().len());

    Ok(())
}
