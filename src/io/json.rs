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

use std::io::{self, Read, BufRead, BufReader, IsTerminal, Write};
use std::fs::File;
use serde_json::{Value, Deserializer};
use std::fmt;

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
            JSONError::JSONToStringError(err) => write!(f, "error converting json value to string: {}", err),
            JSONError::FileWriteError(path) => write!(f, "failed to write to file: {}", path),
        }
    }
}

pub struct JSON {
    values: Vec<Value>,
}

impl JSON {
    /// Constructs a `JSON` instance from a file path.
    #[allow(dead_code)]
    pub fn from_file(path: &str) -> Result<Self, JSONError> {
        let file = File::open(path).map_err(|_| JSONError::FileOpenError(path.to_string()))?;
        let reader = BufReader::new(file);
        Self::deserialize(reader)
    }

    /// Constructs a `JSON` instance from standard input.
    #[allow(dead_code)]
    pub fn from_stdin() -> Result<Self, JSONError> {
        if io::stdin().is_terminal() {
            return Err(JSONError::StdinReadError);
        }

        let reader = BufReader::new(io::stdin());
        Self::deserialize(reader)
    }

    /// Constructs a `JSON` instance from a file path or standard input.
    /// If the file path is `None`, reads from standard input.
    #[allow(dead_code)]
    pub fn from_file_or_stdin(path: Option<String>) -> Result<Self, JSONError> {
        match path {
            Some(file_path) => Self::from_file(&file_path),
            None => Self::from_stdin(),
        }
    }

    /// Private method to deserialize JSON from a given reader.
    #[allow(dead_code)]
    fn deserialize<R: BufRead>(reader: R) -> Result<Self, JSONError> {
        let values: Vec<Value> = Deserializer::from_reader(reader)
            .into_iter::<Value>()
            .map(|value| value.map_err(|e| JSONError::JSONParseError(e.to_string())))
            .collect::<Result<_, _>>()?;

        Ok(JSON { values })
    }

    /// Private method to deserialize JSON with filtering and in-place modification.
    #[allow(dead_code)]
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

    /// Constructs a `JSON` instance from a file path with filtering and in-place modification.
    #[allow(dead_code)]
    pub fn from_file_with_filter<F>(path: &str, filter: F) -> Result<Self, JSONError>
    where
        F: Fn(&mut Value) -> bool,
    {
        let file = File::open(path).map_err(|_| JSONError::FileOpenError(path.to_string()))?;
        let reader = BufReader::new(file);
        Self::deserialize_with_filter(reader, filter)
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

    /// Constructs a `JSON` instance from a file path or standard input with filtering and in-place modification.
    #[allow(dead_code)]
    pub fn from_file_or_stdin_with_filter<F>(path: Option<String>, filter: F) -> Result<Self, JSONError>
    where
        F: Fn(&mut Value) -> bool,
    {
        match path {
            Some(file_path) => Self::from_file_with_filter(&file_path, filter),
            None => Self::from_stdin_with_filter(filter),
        }
    }

    #[allow(dead_code)]
    pub fn from_file_or_stdin_as_array<F>(path: Option<String>, filter: F) -> Result<Self, JSONError>
    where
        F: Fn(&Value) -> bool,
    {
        // Read the JSON input from file or stdin
        let input = match path {
            Some(ref file_path) => { // Use `ref` to avoid moving `file_path`
                let mut file = File::open(file_path).map_err(|_| JSONError::FileOpenError(file_path.clone()))?;
                let mut buffer = String::new();
                file.read_to_string(&mut buffer).map_err(|_| JSONError::FileOpenError(file_path.clone()))?;
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
        let parsed_json: Value = serde_json::from_str(&input).map_err(|e| JSONError::JSONParseError(e.to_string()))?;

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
    #[allow(dead_code)]
    pub fn values(&self) -> &Vec<Value> {
        &self.values
    }

    /// Converts a `serde_json::Value` to a `String`.
    #[allow(dead_code)]
    pub fn value_to_string(value: &Value) -> Result<String, JSONError> {
        serde_json::to_string(value).map_err(|e| JSONError::JSONToStringError(e.to_string()))
    }

    /// Converts all `serde_json::Value`s into a `Vec<String>`.
    #[allow(dead_code)]
    pub fn values_as_strings(&self) -> Vec<String> {
        self.values
            .iter()
            .filter_map(|value| Self::value_to_string(value).ok())
            .collect()
    }

    /// Writes all JSON values as single-line strings to a file.
    #[allow(dead_code)]
    pub fn write_to_file(&self, file_path: &str) -> Result<(), JSONError> {
        let strings = self.values_as_strings();

        let mut file = File::create(file_path).map_err(|_| JSONError::FileWriteError(file_path.to_string()))?;

        for line in strings {
            writeln!(file, "{}", line).map_err(|_| JSONError::FileWriteError(file_path.to_string()))?;
        }

        Ok(())
    }
}
