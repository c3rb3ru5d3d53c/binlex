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

use super::analysis::validate_targets;
use super::mir::{MirFunction, MirModule};
use std::collections::HashSet;
use std::io::{Error, ErrorKind};

pub fn verify_mir_function(mir: &MirFunction) -> Result<(), Error> {
    let mut names = HashSet::new();
    for block in &mir.blocks {
        if block.name.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "mir block name is empty",
            ));
        }
        if !names.insert(block.name.clone()) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("duplicate mir block name {}", block.name),
            ));
        }
        if block.terminator.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("mir block {} is missing a terminator", block.name),
            ));
        }
    }
    validate_targets(mir).map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
    Ok(())
}

pub fn verify_mir_module(module: &MirModule) -> Result<(), Error> {
    for function in &module.functions {
        verify_mir_function(function)?;
    }
    Ok(())
}
