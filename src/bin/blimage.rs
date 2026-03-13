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

use binlex::AUTHOR;
use binlex::VERSION;
use binlex::hashing::SHA256;
use binlex::imaging::Palette;
use binlex::imaging::SVG;
use binlex::imaging::Terminal;
use clap::Parser;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::ErrorKind;
use std::io::Read;
use std::process;

#[derive(Parser, Debug)]
#[command(
    name = "blimage",
    version = VERSION,
    about =  format!("A Binlex Binary Visualization Tool\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
struct Args {
    #[arg(short, long)]
    input: String,
    #[arg(short, long)]
    output: Option<String>,
    #[arg(short, long, value_enum, default_value = "grayscale")]
    color: Palette,
    #[arg(long, default_value_t = 1)]
    cell_size: usize,
    #[arg(long, default_value_t = 16)]
    fixed_width: usize,
}

fn main() {
    let args = Args::parse();
    let mut file = File::open(args.input).unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });

    let mut byte_data = Vec::new();

    file.read_to_end(&mut byte_data).unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });

    if let Some(output) = args.output {
        let mut svg = build_svg(&byte_data, args.color, args.cell_size, args.fixed_width);

        for (key, value) in metadata(&byte_data) {
            svg.add_metadata(key, value);
        }

        svg.write(&output).unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });
    } else {
        let terminal = build_terminal(&byte_data, args.color, args.cell_size, args.fixed_width);

        terminal.print().unwrap_or_else(|error| {
            if error.kind() == ErrorKind::BrokenPipe {
                process::exit(0);
            }

            eprintln!("error writing terminal preview: {}", error);
            process::exit(1);
        });
    }

    process::exit(0);
}

fn metadata(byte_data: &[u8]) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::<String, String>::new();
    metadata.insert(
        "sha256".to_string(),
        SHA256::new(byte_data).hexdigest().unwrap(),
    );
    metadata
}

fn build_svg(byte_data: &[u8], palette: Palette, cell_size: usize, fixed_width: usize) -> SVG {
    SVG::new_with_options(byte_data, palette, cell_size, fixed_width)
}

fn build_terminal(
    byte_data: &[u8],
    palette: Palette,
    cell_size: usize,
    fixed_width: usize,
) -> Terminal {
    Terminal::new_with_options(byte_data, palette, cell_size, fixed_width)
}
