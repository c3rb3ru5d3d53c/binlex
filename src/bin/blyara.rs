//                    GNU LESSER GENERAL PUBLIC LICENSE
//                        Version 3, 29 June 2007
//
//  Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
//  Everyone is permitted to copy and distribute verbatim copies
//  of this license document, but changing it is not allowed.
//
//
//   This version of the GNU Lesser General Public License incorporates
// the terms and conditions of version 3 of the GNU General Public
// License, supplemented by the additional permissions listed below.
//
//   0. Additional Definitions.
//
//   As used herein, "this License" refers to version 3 of the GNU Lesser
// General Public License, and the "GNU GPL" refers to version 3 of the GNU
// General Public License.
//
//   "The Library" refers to a covered work governed by this License,
// other than an Application or a Combined Work as defined below.
//
//   An "Application" is any work that makes use of an interface provided
// by the Library, but which is not otherwise based on the Library.
// Defining a subclass of a class defined by the Library is deemed a mode
// of using an interface provided by the Library.
//
//   A "Combined Work" is a work produced by combining or linking an
// Application with the Library.  The particular version of the Library
// with which the Combined Work was made is also called the "Linked
// Version".
//
//   The "Minimal Corresponding Source" for a Combined Work means the
// Corresponding Source for the Combined Work, excluding any source code
// for portions of the Combined Work that, considered in isolation, are
// based on the Application, and not on the Linked Version.
//
//   The "Corresponding Application Code" for a Combined Work means the
// object code and/or source code for the Application, including any data
// and utility programs needed for reproducing the Combined Work from the
// Application, but excluding the System Libraries of the Combined Work.
//
//   1. Exception to Section 3 of the GNU GPL.
//
//   You may convey a covered work under sections 3 and 4 of this License
// without being bound by section 3 of the GNU GPL.
//
//   2. Conveying Modified Versions.
//
//   If you modify a copy of the Library, and, in your modifications, a
// facility refers to a function or data to be supplied by an Application
// that uses the facility (other than as an argument passed when the
// facility is invoked), then you may convey a copy of the modified
// version:
//
//    a) under this License, provided that you make a good faith effort to
//    ensure that, in the event an Application does not supply the
//    function or data, the facility still operates, and performs
//    whatever part of its purpose remains meaningful, or
//
//    b) under the GNU GPL, with none of the additional permissions of
//    this License applicable to that copy.
//
//   3. Object Code Incorporating Material from Library Header Files.
//
//   The object code form of an Application may incorporate material from
// a header file that is part of the Library.  You may convey such object
// code under terms of your choice, provided that, if the incorporated
// material is not limited to numerical parameters, data structure
// layouts and accessors, or small macros, inline functions and templates
// (ten or fewer lines in length), you do both of the following:
//
//    a) Give prominent notice with each copy of the object code that the
//    Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the object code with a copy of the GNU GPL and this license
//    document.
//
//   4. Combined Works.
//
//   You may convey a Combined Work under terms of your choice that,
// taken together, effectively do not restrict modification of the
// portions of the Library contained in the Combined Work and reverse
// engineering for debugging such modifications, if you also do each of
// the following:
//
//    a) Give prominent notice with each copy of the Combined Work that
//    the Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the Combined Work with a copy of the GNU GPL and this license
//    document.
//
//    c) For a Combined Work that displays copyright notices during
//    execution, include the copyright notice for the Library among
//    these notices, as well as a reference directing the user to the
//    copies of the GNU GPL and this license document.
//
//    d) Do one of the following:
//
//        0) Convey the Minimal Corresponding Source under the terms of this
//        License, and the Corresponding Application Code in a form
//        suitable for, and under terms that permit, the user to
//        recombine or relink the Application with a modified version of
//        the Linked Version to produce a modified Combined Work, in the
//        manner specified by section 6 of the GNU GPL for conveying
//        Corresponding Source.
//
//        1) Use a suitable shared library mechanism for linking with the
//        Library.  A suitable mechanism is one that (a) uses at run time
//        a copy of the Library already present on the user's computer
//        system, and (b) will operate properly with a modified version
//        of the Library that is interface-compatible with the Linked
//        Version.
//
//    e) Provide Installation Information, but only if you would otherwise
//    be required to provide such information under section 6 of the
//    GNU GPL, and only to the extent that such information is
//    necessary to install and execute a modified version of the
//    Combined Work produced by recombining or relinking the
//    Application with a modified version of the Linked Version. (If
//    you use option 4d0, the Installation Information must accompany
//    the Minimal Corresponding Source and Corresponding Application
//    Code. If you use option 4d1, you must provide the Installation
//    Information in the manner specified by section 6 of the GNU GPL
//    for conveying Corresponding Source.)
//
//   5. Combined Libraries.
//
//   You may place library facilities that are a work based on the
// Library side by side in a single library together with other library
// facilities that are not Applications and are not covered by this
// License, and convey such a combined library under terms of your
// choice, if you do both of the following:
//
//    a) Accompany the combined library with a copy of the same work based
//    on the Library, uncombined with any other library facilities,
//    conveyed under the terms of this License.
//
//    b) Give prominent notice with the combined library that part of it
//    is a work based on the Library, and explaining where to find the
//    accompanying uncombined form of the same work.
//
//   6. Revised Versions of the GNU Lesser General Public License.
//
//   The Free Software Foundation may publish revised and/or new versions
// of the GNU Lesser General Public License from time to time. Such new
// versions will be similar in spirit to the present version, but may
// differ in detail to address new problems or concerns.
//
//   Each version is given a distinguishing version number. If the
// Library as you received it specifies that a certain numbered version
// of the GNU Lesser General Public License "or any later version"
// applies to it, you have the option of following the terms and
// conditions either of that published version or of any later version
// published by the Free Software Foundation. If the Library as you
// received it does not specify a version number of the GNU Lesser
// General Public License, you may choose any version of the GNU Lesser
// General Public License ever published by the Free Software Foundation.
//
//   If the Library as you received it specifies that a proxy can decide
// whether future versions of the GNU Lesser General Public License shall
// apply, that proxy's public statement of acceptance of any version is
// permanent authorization for you to choose that version for the
// Library.

use clap::Parser;
use serde_json::{Map, Value};
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::process;
use binlex::AUTHOR;
use binlex::VERSION;
use binlex::io::Stdout;

#[derive(Parser, Debug)]
#[command(
    name = "blyara",
    version = VERSION,
    about = format!("A Binlex YARA Generation Tool\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
struct Cli {
    #[arg(short, long)]
    input: Option<String>,
    #[arg(
        short,
        long,
        num_args(2),
        value_names = ["KEY", "VALUE"],
        action = clap::ArgAction::Append
    )]
    metadata: Vec<String>,
    #[arg(short, long, required = true)]
    name: String,
    #[arg(short, long, default_value_t = 1)]
    count: usize,
    #[arg(short, long)]
    output: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    let metadata_map = collect_metadata(&cli.metadata);
    let pattern_map = collect_patterns(&cli.input);

    if pattern_map.is_empty() {
        eprintln!("no signature patterns collected.");
        process::exit(1);
    }

    let signature = generate_signature(&cli.name, &metadata_map, &pattern_map, cli.count);

    if let Some(output_file) = &cli.output {
        if let Err(e) = write_to_file(output_file, &signature) {
            eprintln!("failed to write yara rule to output file: {}", e);
            process::exit(1);
        }
    } else {
        Stdout::print(signature);
    }
}

fn collect_metadata(metadata_vec: &[String]) -> Map<String, Value> {
    let mut metadata_map = Map::new();
    for chunk in metadata_vec.chunks(2) {
        if let [key, value] = chunk {
            metadata_map.insert(key.clone(), Value::String(value.clone()));
        }
    }
    metadata_map
}

fn collect_patterns(input_file: &Option<String>) -> Map<String, Value> {
    let reader: Box<dyn BufRead> = match input_file {
        Some(file_name) => {
            let file = File::open(file_name).unwrap_or_else(|_| {
                eprintln!("failed to open input file: {}", file_name);
                process::exit(1);
            });
            Box::new(io::BufReader::new(file))
        }
        None => Box::new(io::BufReader::new(io::stdin())),
    };

    let mut pattern_map = Map::new();
    for (count, line) in reader.lines().enumerate() {
        match line {
            Ok(l) => {
                pattern_map.insert(
                    format!("trait_{}", count),
                    Value::String(format!("{{{}}}", l)),
                );
            }
            Err(e) => {
                eprintln!("failed to read line: {}", e);
                process::exit(1);
            }
        }
    }
    pattern_map
}

fn generate_signature(
    name: &str,
    metadata_map: &Map<String, Value>,
    pattern_map: &Map<String, Value>,
    count: usize,
) -> String {
    let mut signature = format!("rule {} {{\n", name);

    if !metadata_map.is_empty() {
        signature.push_str("    meta:\n");
        for (key, value) in metadata_map {
            signature.push_str(&format!("        {} = {}\n", key, value));
        }
    }

    signature.push_str("    strings:\n");
    for (key, value) in pattern_map {
        signature.push_str(&format!(
            "        ${} = {}\n",
            key,
            value.as_str().unwrap_or("")
        ));
    }

    signature.push_str("    condition:\n");
    signature.push_str(&format!("        {} of them\n", count));
    signature.push_str("}\n");

    signature
}

fn write_to_file(output_file: &str, content: &str) -> io::Result<()> {
    let mut file = File::create(output_file)?;
    file.write_all(content.as_bytes())
}
