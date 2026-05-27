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

use super::block::HirBlock;
use super::hir::{HirFunction, HirModule};
use super::statement::HirStatement;
use super::target::HirTarget;
use std::collections::HashSet;
use std::io::{Error, ErrorKind};

pub fn verify_hir_function(hir: &HirFunction) -> Result<(), Error> {
    let mut labels = HashSet::new();
    for block in &hir.blocks {
        collect_labels(block, &mut labels)?;
    }
    for block in &hir.blocks {
        verify_block(block, &labels)?;
    }
    Ok(())
}

pub fn verify_hir_module(module: &HirModule) -> Result<(), Error> {
    for function in &module.functions {
        verify_hir_function(function)?;
    }
    Ok(())
}

fn collect_labels(block: &HirBlock, labels: &mut HashSet<String>) -> Result<(), Error> {
    for statement in &block.statements {
        match statement {
            HirStatement::Label(name) => {
                if name.is_empty() {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "hir label name is empty",
                    ));
                }
                if !labels.insert(name.clone()) {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("duplicate hir label {}", name),
                    ));
                }
            }
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                collect_labels(then_body, labels)?;
                if let Some(else_body) = else_body {
                    collect_labels(else_body, labels)?;
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                collect_labels(body, labels)?;
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    collect_labels(&case.body, labels)?;
                }
                if let Some(default) = default {
                    collect_labels(default, labels)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn verify_block(block: &HirBlock, labels: &HashSet<String>) -> Result<(), Error> {
    for statement in &block.statements {
        verify_statement(statement, labels)?;
    }
    Ok(())
}

fn verify_statement(statement: &HirStatement, labels: &HashSet<String>) -> Result<(), Error> {
    let check = |target: &HirTarget| match target {
        HirTarget::Direct(name) if !labels.contains(name) => Err(Error::new(
            ErrorKind::InvalidData,
            format!("unknown hir label {}", name),
        )),
        _ => Ok(()),
    };

    match statement {
        HirStatement::Goto(target) => check(target),
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            verify_block(then_body, labels)?;
            if let Some(else_body) = else_body {
                verify_block(else_body, labels)?;
            }
            Ok(())
        }
        HirStatement::While { body, .. } | HirStatement::Loop { body } => {
            verify_block(body, labels)
        }
        HirStatement::Switch { cases, default, .. } => {
            for case in cases {
                verify_block(&case.body, labels)?;
            }
            if let Some(default) = default {
                verify_block(default, labels)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
