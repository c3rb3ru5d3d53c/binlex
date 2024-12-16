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

use std::process;
use std::path::Path;
use std::sync::Arc;

use clap::Parser;
use glob::glob;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use binlex::{AUTHOR, VERSION};
use binlex::hashing::TLSH;
use binlex::hashing::MinHash32;
use binlex::io::{JSON, Stdout};

#[derive(Serialize, Deserialize)]
pub struct SimilarityScoreJson{
    pub tlsh: Option<f64>,
    pub minhash: Option<f64>,
}

/// Structure to represent the comparison result between two JSON entries.
#[derive(Serialize, Deserialize)]
pub struct ComparisonJson {
    /// The type of this entity, always `"comparison"`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The JSON entry from the LHS.
    pub lhs: Value,
    /// The JSON entry from the RHS.
    pub rhs: Value,
    /// TLSH Similarity Score
    pub similarity: SimilarityScoreJson,
}

#[derive(Parser, Debug)]
#[command(
    name = "blcompare",
    version = VERSION,
    about =  format!("A Binlex Trait Comparison Tool\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
struct Args {
    /// Input file or glob pattern for LHS (Left-Hand Side).
    #[arg(long)]
    input_lhs: Option<String>,

    /// Input file or glob pattern for RHS (Right-Hand Side).
    #[arg(long)]
    input_rhs: String,

    /// Number of threads to use.
    #[arg(short, long, default_value_t = 1)]
    pub threads: usize,

    #[arg(long, default_value_t = 0.75)]
    pub non_contiguous_threshold: f64,

    /// Enable recursive glob expansion.
    #[arg(short = 'r', long = "recursive")]
    pub recursive: bool,
}

fn main() {
    let args = Args::parse();

    initialize_thread_pool(args.threads);

    let rhs_files = expand_paths(&args.input_rhs, args.recursive);
    if rhs_files.is_empty() {
        eprintln!("No RHS files matched the pattern.");
        process::exit(1);
    }

    match args.input_lhs {
        Some(lhs_pattern) => handle_lhs_files(&lhs_pattern, &rhs_files, args.recursive, args.non_contiguous_threshold),
        None => handle_stdin_lhs(&rhs_files, args.non_contiguous_threshold),
    }

    process::exit(0);
}

fn initialize_thread_pool(num_threads: usize) {
    ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .unwrap_or_else(|error| {
            eprintln!("Error building thread pool: {}", error);
            process::exit(1);
        });
}

fn expand_paths(pattern: &str, recursive: bool) -> Vec<String> {
    let modified_pattern = if recursive {
        let path = Path::new(pattern);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_pattern = path.file_name().unwrap_or_default().to_str().unwrap_or("");
        parent.join("**").join(file_pattern).to_string_lossy().to_string()
    } else {
        pattern.to_string()
    };

    glob(&modified_pattern)
        .expect("Failed to read glob pattern")
        .filter_map(|entry| {
            match entry {
                Ok(path) if path.is_file() => Some(path.to_string_lossy().to_string()),
                Ok(_) => None,
                Err(e) => {
                    eprintln!("Glob pattern error: {:?}", e);
                    None
                }
            }
        })
        .collect()
}

fn handle_lhs_files(lhs_pattern: &str, rhs_files: &[String], recursive: bool, non_contiguous_threshold: f64) {
    let lhs_files = expand_paths(lhs_pattern, recursive);
    if lhs_files.is_empty() {
        eprintln!("No LHS files matched the pattern.");
        process::exit(1);
    }

    let pairs: Vec<(String, String)> = lhs_files
        .iter()
        .flat_map(|lhs| rhs_files.iter().map(move |rhs| (lhs.clone(), rhs.clone())))
        .collect();

    pairs.par_iter().for_each(|(lhs_path, rhs_path)| {
        let json_lhs = load_json_with_filter(lhs_path);
        let json_rhs = load_json_with_filter(rhs_path);

        if let (Some(json_lhs), Some(json_rhs)) = (json_lhs, json_rhs) {
            compare_json_entries(&json_lhs, &json_rhs, non_contiguous_threshold);
        }
    });
}

fn handle_stdin_lhs(rhs_files: &[String], non_contiguous_threshold: f64) {
    let json_lhs = match JSON::from_stdin_with_filter(filter_json) {
        Ok(json) => Arc::new(json),
        Err(e) => {
            eprintln!("Error reading LHS from stdin: {}", e);
            process::exit(1);
        }
    };

    rhs_files.par_iter().for_each(|rhs_path| {
        let json_rhs = load_json_with_filter(rhs_path);

        if let Some(json_rhs) = json_rhs {
            compare_json_entries(&json_lhs, &json_rhs, non_contiguous_threshold);
        }
    });
}

fn load_json_with_filter(path: &str) -> Option<JSON> {
    match JSON::from_file_with_filter(path, filter_json) {
        Ok(json) => Some(json),
        Err(e) => {
            eprintln!("{}", e);
            None
        }
    }
}

fn filter_json(value: &mut Value) -> bool {
    value.get("architecture").and_then(|v| v.as_str()).is_some()
        && value
            .get("chromosome")
            .is_some()
}

fn compare_json_entries(json_lhs: &JSON, json_rhs: &JSON, non_contiguous_threshold: f64) {
    let lhs_entries = json_lhs.values();
    let rhs_entries: Vec<Value> = json_rhs.values().into_iter().cloned().collect();

    for lhs in lhs_entries {

        let lhs_type = match extract_string_value(lhs, "type") {
            Some(t) => t,
            None => continue,
        };

        let lhs_arch = match extract_string_value(lhs, "architecture") {
            Some(a) => a,
            None => continue,
        };

        let lhs_tlsh = extract_nested_field(lhs, "chromosome", "tlsh");

        let lhs_minhash = extract_nested_field(lhs, "chromosome", "minhash");

        let lhs_contiguous = match extract_boolean_value(lhs, "contiguous") {
            Some(t) => t,
            None => continue,
        };

        for rhs in &rhs_entries {
            let rhs_type = match extract_string_value(rhs, "type") {
                Some(t) => t,
                None => continue,
            };

            let rhs_arch = match extract_string_value(rhs, "architecture") {
                Some(a) => a,
                None => continue,
            };

            let rhs_tlsh = extract_nested_field(rhs, "chromosome", "tlsh");

            let rhs_minhash = extract_nested_field(rhs, "chromosome", "minhash");

            let rhs_contiguous = match extract_boolean_value(rhs, "contiguous") {
                Some(t) => t,
                None => continue,
            };

            if lhs_type != rhs_type || lhs_arch != rhs_arch {
                continue;
            }

            let mut tlsh_similarity: Option<f64> = None;
            let mut minhash_similarity: Option<f64> = None;

            if lhs_contiguous == true && rhs_contiguous == true && lhs_tlsh.is_some() && rhs_tlsh.is_some() {
                tlsh_similarity = TLSH::compare(
                    lhs_tlsh.clone().unwrap(),
                    rhs_tlsh.clone().unwrap())
                        .ok()
                        .map(|score| score as f64);

            }

            if lhs_contiguous == true && rhs_contiguous == true && lhs_minhash.is_some() && rhs_minhash.is_some() {
                minhash_similarity = Some(MinHash32::compare_jaccard_similarity(&lhs_minhash.clone().unwrap(), &rhs_minhash.clone().unwrap()));
            }

            // Handle Non-Contiguous Function Similarity
            if (lhs_contiguous == false || rhs_contiguous == false) && lhs_type == "function" && rhs_type == "function" {
                if let (Some(lhs_blocks), Some(rhs_blocks)) = (
                    lhs.get("blocks").and_then(|b| b.as_array()),
                    rhs.get("blocks").and_then(|b| b.as_array()),
                ) {
                    if get_blocks_minhash_ratio(&lhs_blocks) >= non_contiguous_threshold && get_blocks_minhash_ratio(&rhs_blocks) >= non_contiguous_threshold {
                        minhash_similarity = calculate_non_contiguous_minhash_similarity(lhs_blocks, rhs_blocks);
                    }
                    if get_blocks_tlsh_ratio(&lhs_blocks) >= non_contiguous_threshold && get_blocks_tlsh_ratio(&rhs_blocks) >= non_contiguous_threshold {
                        tlsh_similarity = calculate_non_contiguous_tlsh_similarity(lhs_blocks, rhs_blocks);
                    }
                }
            }

            // Skip if Similarity Cannot be Compared
            if tlsh_similarity.is_none() && minhash_similarity.is_none() { continue; }

            let comparison = ComparisonJson {
                type_: "comparison".to_string(),
                lhs: lhs.clone(),
                rhs: rhs.clone(),
                similarity: SimilarityScoreJson {
                    tlsh: tlsh_similarity,
                    minhash: minhash_similarity,
                },
            };

            match serde_json::to_string(&comparison) {
                Ok(serialized) => Stdout::print(serialized),
                Err(e) => eprintln!("Serialization error: {}", e),
            }
        }
    }
}

fn calculate_non_contiguous_minhash_similarity(lhs_blocks: &[Value], rhs_blocks: &[Value]) -> Option<f64> {
    let lhs_minhash_values = extract_minhash_values(lhs_blocks);
    let rhs_minhash_values = extract_minhash_values(rhs_blocks);

    if lhs_blocks.len() != lhs_minhash_values.len() || rhs_blocks.len() != rhs_minhash_values.len() {
        return None;
    }

    let mut similarities = Vec::new();

    for lhs_tlsh in lhs_minhash_values {
        let mut best_similarity: Option<f64> = None;

        for rhs_tlsh in &rhs_minhash_values {
            let similarity = MinHash32::compare_jaccard_similarity(&lhs_tlsh.clone(), &rhs_tlsh.clone());
            best_similarity = match best_similarity {
                Some(current_best) => Some(current_best.max(similarity)),
                None => Some(similarity),
            };
        }

        if let Some(similarity) = best_similarity {
            similarities.push(similarity as f64);
        }
    }

    if !similarities.is_empty() {
        let total_similarity: f64 = similarities.iter().sum();
        return Some(total_similarity / similarities.len() as f64);
    }

    None
}

fn calculate_non_contiguous_tlsh_similarity(lhs_blocks: &[Value], rhs_blocks: &[Value]) -> Option<f64> {
    let lhs_tlsh_values = extract_tlsh_values(lhs_blocks);
    let rhs_tlsh_values = extract_tlsh_values(rhs_blocks);

    if lhs_blocks.len() != lhs_tlsh_values.len() || rhs_blocks.len() != rhs_tlsh_values.len() {
        return None;
    }

    let mut similarities = Vec::new();

    for lhs_tlsh in lhs_tlsh_values {
        let mut best_similarity: Option<u32> = None;

        for rhs_tlsh in &rhs_tlsh_values {
            if let Ok(similarity) = TLSH::compare(lhs_tlsh.clone(), rhs_tlsh.clone()) {
                best_similarity = match best_similarity {
                    Some(current_best) => Some(current_best.min(similarity)),
                    None => Some(similarity),
                };
            }
        }

        if let Some(similarity) = best_similarity {
            similarities.push(similarity as f64);
        }
    }

    if !similarities.is_empty() {
        let total_similarity: f64 = similarities.iter().sum();
        return Some(total_similarity / similarities.len() as f64);
    }

    None
}

fn extract_minhash_values(blocks: &[Value]) -> Vec<String> {
    blocks
        .iter()
        .filter_map(|block| extract_nested_field(block, "chromosome", "minhash"))
        .collect()
}

fn get_blocks_minhash_ratio(blocks: &[Value]) -> f64 {
    let mut minhash_size: usize = 0;
    let mut total_size: usize = 0;
    for block in blocks {
        let minhash = extract_nested_field(block, "chromosome", "minhash");
        let size = extract_u64_value(block, "size").unwrap_or(0) as usize;
        total_size += size;
        if minhash.is_some() {
            minhash_size += size;
        }
    }
    return minhash_size as f64 / total_size as f64;
}

fn get_blocks_tlsh_ratio(blocks: &[Value]) -> f64 {
    let mut tlsh_size: usize = 0;
    let mut total_size: usize = 0;
    for block in blocks {
        let tlsh = extract_nested_field(block, "chromosome", "tlsh");
        let size = extract_u64_value(block, "size").unwrap_or(0) as usize;
        total_size += size;
        if tlsh.is_some() {
            tlsh_size += size;
        }
    }
    return tlsh_size as f64 / total_size as f64;
}

fn extract_tlsh_values(blocks: &[Value]) -> Vec<String> {
    blocks
        .iter()
        .filter_map(|block| extract_nested_field(block, "chromosome", "tlsh"))
        .collect()
}

fn extract_u64_value<'a>(value: &'a Value, field: &str) -> Option<u64> {
    value.get(field)?.as_u64()
}

fn extract_boolean_value<'a>(value: &'a Value, field: &str) -> Option<bool> {
    value.get(field)?.as_bool()
}

fn extract_string_value<'a>(value: &'a Value, field: &str) -> Option<String> {
    value.get(field)?.as_str().map(String::from)
}

fn extract_nested_field<'a>(value: &'a Value, field: &str, subfield: &str) -> Option<String> {
    value.get(field)?.get(subfield)?.as_str().map(String::from)
}
