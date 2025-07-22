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

use std::io::{stdin, ErrorKind};
use std::io::{self, BufRead, IsTerminal, Write};
use std::fmt::Display;
use std::process;
use crate::io::Stdout;

/// Represents a wrapper for standard input operations.
pub struct Stdin;

impl Stdin {

    #[allow(dead_code)]
    pub fn is_terminal() -> bool {
        stdin().is_terminal()
    }

    /// Reads lines from standard input and writes each line to standard output.
    ///
    /// This function reads lines from standard input if it's not a terminal,
    /// locking the input for safe handling in buffered mode. If a line is read
    /// successfully, it's printed using `Stdout`. If an error occurs, it prints
    /// the error message and exits with a non-zero status code.
    #[allow(dead_code)]
    pub fn passthrough() {
        let stdin = io::stdin();
        if !stdin.is_terminal() {
            let handle = stdin.lock();
            for line in handle.lines() {
                match line {
                    Ok(line) => {
                        Stdout::print(line);
                    },
                    Err(error) => {
                        eprintln!("{}", error);
                        process::exit(1);
                    },
                }
            }
        }
    }
    /// Prints a line to standard error.
    ///
    /// # Arguments
    ///
    /// * `line` - The line to be printed, which implements the `Display` trait.
    ///
    /// If an error occurs, this method checks if it was due to a broken pipe.
    /// If it was, the program exits with code `0`. For other errors, it logs
    /// an error message to standard error and exits with code `1`.
    #[allow(dead_code)]
    pub fn print<T: Display>(line: T) {
        writeln!(io::stderr(), "{}", line).unwrap_or_else(|e| {
            if e.kind() == ErrorKind::BrokenPipe {
                std::process::exit(0);
            } else {
                eprintln!("error writing to stdout: {}", e);
                std::process::exit(1);
            }
        });
    }

}
