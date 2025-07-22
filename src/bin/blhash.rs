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

use std::process;
use clap::Parser;
use binlex::AUTHOR;
use binlex::VERSION;
use clap::ValueEnum;
use std::fmt;
use binlex::Config;
use binlex::formats::File;

#[derive(Parser, Debug)]
#[command(
    name = "blhash",
    version = VERSION,
    about =  format!("A Binlex File Hashing Tool\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
struct Args {
    #[arg(short, long)]
    input: String,
    #[arg(long, value_enum, default_value = "tlsh")]
    hashtype: HashType,
}


#[derive(Debug, Clone, ValueEnum)]
pub enum HashType {
    Sha256,
    Tlsh,
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                HashType::Sha256 => "sha256",
                HashType::Tlsh => "tlsh",
            }
        )
    }
}

fn main () {

    let mut config = Config::new();

    config.formats.file.hashing.tlsh.enabled = true;
    config.formats.file.hashing.sha256.enabled = true;
    config.formats.file.hashing.minhash.enabled = true;

    let args = Args::parse();

    let mut file = File::new(args.input, config).unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });

    file.read().unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });

    let hash = match args.hashtype.to_string().as_str() {
        "sha256" => {
            file.sha256()
        },
        "tlsh" => {
            file.tlsh()
        },
        _ => { None }
    };

    if hash.is_some() {
        println!("{}", hash.unwrap());
    } else {
        eprintln!("unable to calculate hash");
        process::exit(1);
    }

    process::exit(0);
}
