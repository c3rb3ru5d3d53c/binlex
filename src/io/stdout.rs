use std::io::ErrorKind;
use std::io::{self, Write};
use std::fmt::Display;
/// Represents a wrapper for standard output operations.
pub struct Stdout;

impl Stdout {
    /// Prints a line to standard output.
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
        writeln!(io::stdout(), "{}", line).unwrap_or_else(|e| {
            if e.kind() == ErrorKind::BrokenPipe {
                std::process::exit(0);
            } else {
                eprintln!("error writing to stdout: {}", e);
                std::process::exit(1);
            }
        });
    }
}
