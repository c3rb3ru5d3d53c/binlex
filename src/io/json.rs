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

use serde_json::{Deserializer, Value};
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal, Read};

#[derive(Debug)]
pub enum JSONError {
    FileOpenError(String),
    StdinReadError,
    JSONParseError(String),
    JSONToStringError(String),
    FileWriteError(String),
}

impl fmt::Display for JSONError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JSONError::FileOpenError(path) => write!(f, "failed to open file: {}", path),
            JSONError::StdinReadError => write!(f, "failed to read from standard input"),
            JSONError::JSONParseError(err) => write!(f, "failed parsing json: {}", err),
            JSONError::JSONToStringError(err) => {
                write!(f, "error converting json value to string: {}", err)
            }
            JSONError::FileWriteError(path) => write!(f, "failed to write to file: {}", path),
        }
    }
}

pub struct JSON {
    values: Vec<Value>,
}

impl JSON {
    /// Private method to deserialize JSON with filtering and in-place modification.
    fn deserialize_with_filter<R, F>(reader: R, filter: F) -> Result<Self, JSONError>
    where
        R: BufRead,
        F: Fn(&mut Value) -> bool,
    {
        let mut values = Vec::new();

        for item in Deserializer::from_reader(reader).into_iter::<Value>() {
            match item {
                Ok(mut value) => {
                    if filter(&mut value) {
                        values.push(value);
                    }
                }
                Err(e) => return Err(JSONError::JSONParseError(e.to_string())),
            }
        }

        Ok(JSON { values })
    }

    /// Constructs a `JSON` instance from standard input with filtering and in-place modification.
    pub fn from_stdin_with_filter<F>(filter: F) -> Result<Self, JSONError>
    where
        F: Fn(&mut Value) -> bool,
    {
        if io::stdin().is_terminal() {
            return Err(JSONError::StdinReadError);
        }

        let reader = BufReader::new(io::stdin());
        Self::deserialize_with_filter(reader, filter)
    }

    #[allow(dead_code)]
    pub fn from_file_or_stdin_as_array<F>(
        path: Option<String>,
        filter: F,
    ) -> Result<Self, JSONError>
    where
        F: Fn(&Value) -> bool,
    {
        // Read the JSON input from file or stdin
        let input = match path {
            Some(ref file_path) => {
                // Use `ref` to avoid moving `file_path`
                let mut file = File::open(file_path)
                    .map_err(|_| JSONError::FileOpenError(file_path.clone()))?;
                let mut buffer = String::new();
                file.read_to_string(&mut buffer)
                    .map_err(|_| JSONError::FileOpenError(file_path.clone()))?;
                buffer
            }
            None => {
                if io::stdin().is_terminal() {
                    return Err(JSONError::StdinReadError);
                }
                let mut buffer = String::new();
                io::stdin()
                    .read_to_string(&mut buffer)
                    .map_err(|_| JSONError::StdinReadError)?;
                buffer
            }
        };

        // Parse the input as JSON
        let parsed_json: Value =
            serde_json::from_str(&input).map_err(|e| JSONError::JSONParseError(e.to_string()))?;

        // Ensure the input is an array
        let array = parsed_json
            .as_array()
            .ok_or_else(|| JSONError::JSONParseError("Input JSON is not an array".to_string()))?;

        // Filter and collect the array elements
        let values = array
            .iter()
            .filter(|value| filter(value))
            .cloned()
            .collect();

        Ok(JSON { values })
    }

    /// Returns a reference to the parsed JSON values.
    pub fn values(&self) -> &Vec<Value> {
        &self.values
    }
}
