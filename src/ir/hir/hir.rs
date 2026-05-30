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
use super::kind::HirType;
use super::lower::{HirLowerError, lower_mir_function_to_hir, lower_mir_module_to_hir};
use super::optimizers::{
    optimize, optimize_algebraic, optimize_boolean, optimize_call_arguments, optimize_cfg,
    optimize_condition_idioms, optimize_inline_temps, optimize_load_hoisting, optimize_locals,
    optimize_memory_forms, optimize_pointer_reads, optimize_undefs,
};
use super::print::{format_hir_function, format_hir_module};
use super::statement::{HirLocal, HirParameter};
use crate::ir::lir::{LirAbi, LirFunction, LirModule};
use crate::ir::mir::{MirFunction, MirModule};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct HirFunction {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abi: Option<LirAbi>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<HirParameter>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub returns: Vec<HirType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locals: Vec<HirLocal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocks: Vec<HirBlock>,
}

impl HirFunction {
    pub fn from_mir(name: Option<String>, mir: &MirFunction) -> Result<Self, HirLowerError> {
        let mut mir = mir.clone();
        mir.optimize();
        lower_mir_function_to_hir(name.or_else(|| mir.name.clone()), &mir)
    }

    pub fn from_lir(name: Option<String>, lir: &LirFunction) -> Result<Self, HirLowerError> {
        let mir = MirFunction::from_lir(name.or_else(|| lir.name.clone()), lir)
            .map_err(|error| HirLowerError::new(error.to_string()))?;
        Self::from_mir(mir.name.clone(), &mir)
    }

    pub fn new(name: Option<String>) -> Self {
        Self {
            name,
            abi: None,
            parameters: Vec::new(),
            returns: Vec::new(),
            locals: Vec::new(),
            blocks: Vec::new(),
        }
    }

    pub fn blocks(&self) -> &[HirBlock] {
        &self.blocks
    }

    pub fn blocks_mut(&mut self) -> &mut Vec<HirBlock> {
        &mut self.blocks
    }

    pub fn append_block(&mut self, block: HirBlock) {
        self.blocks.push(block);
    }

    pub fn optimize_inline_temps(&mut self) {
        optimize_inline_temps(self);
    }

    pub fn optimize_algebraic(&mut self) {
        optimize_algebraic(self);
    }

    pub fn optimize_condition_idioms(&mut self) {
        optimize_condition_idioms(self);
    }

    pub fn optimize_boolean(&mut self) {
        optimize_boolean(self);
    }

    pub fn optimize_load_hoisting(&mut self) {
        optimize_load_hoisting(self);
    }

    pub fn optimize_call_arguments(&mut self) {
        optimize_call_arguments(self);
    }

    pub fn optimize_memory_forms(&mut self) {
        optimize_memory_forms(self);
    }

    pub fn optimize_pointer_reads(&mut self) {
        optimize_pointer_reads(self);
    }

    pub fn optimize_cfg(&mut self) {
        optimize_cfg(self);
    }

    pub fn optimize_locals(&mut self) {
        optimize_locals(self);
    }

    pub fn optimize_undefs(&mut self) {
        optimize_undefs(self);
    }

    pub fn optimize(&mut self) {
        optimize(self);
    }

    pub fn text(&self) -> String {
        format_hir_function(self)
    }

    pub fn print(&self) {
        println!("{}", self.text());
    }

    pub fn ast(&self) -> crate::ir::ast::AstFunction {
        crate::ir::ast::AstFunction::from_hir(self)
    }

    pub fn c(&self) -> String {
        self.ast().c()
    }

    pub fn print_c(&self) {
        println!("{}", self.c());
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct HirModule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<HirFunction>,
}

impl HirModule {
    pub fn from_mir(name: Option<String>, mir: &MirModule) -> Result<Self, HirLowerError> {
        let mut mir = mir.clone();
        mir.optimize();
        lower_mir_module_to_hir(name.or_else(|| mir.name.clone()), &mir)
    }

    pub fn from_lir(name: Option<String>, lir: &LirModule) -> Result<Self, HirLowerError> {
        let mir = MirModule::from_lir(name.or_else(|| lir.name.clone()), lir)
            .map_err(|error| HirLowerError::new(error.to_string()))?;
        Self::from_mir(mir.name.clone(), &mir)
    }

    pub fn new(name: Option<String>) -> Self {
        Self {
            name,
            functions: Vec::new(),
        }
    }

    pub fn functions(&self) -> &[HirFunction] {
        &self.functions
    }

    pub fn functions_mut(&mut self) -> &mut Vec<HirFunction> {
        &mut self.functions
    }

    pub fn append_function(&mut self, function: HirFunction) {
        self.functions.push(function);
    }

    pub fn optimize_inline_temps(&mut self) {
        for function in &mut self.functions {
            function.optimize_inline_temps();
        }
    }

    pub fn optimize_algebraic(&mut self) {
        for function in &mut self.functions {
            function.optimize_algebraic();
        }
    }

    pub fn optimize_condition_idioms(&mut self) {
        for function in &mut self.functions {
            function.optimize_condition_idioms();
        }
    }

    pub fn optimize_boolean(&mut self) {
        for function in &mut self.functions {
            function.optimize_boolean();
        }
    }

    pub fn optimize_load_hoisting(&mut self) {
        for function in &mut self.functions {
            function.optimize_load_hoisting();
        }
    }

    pub fn optimize_call_arguments(&mut self) {
        for function in &mut self.functions {
            function.optimize_call_arguments();
        }
    }

    pub fn optimize_memory_forms(&mut self) {
        for function in &mut self.functions {
            function.optimize_memory_forms();
        }
    }

    pub fn optimize_pointer_reads(&mut self) {
        for function in &mut self.functions {
            function.optimize_pointer_reads();
        }
    }

    pub fn optimize_cfg(&mut self) {
        for function in &mut self.functions {
            function.optimize_cfg();
        }
    }

    pub fn optimize_locals(&mut self) {
        for function in &mut self.functions {
            function.optimize_locals();
        }
    }

    pub fn optimize_undefs(&mut self) {
        for function in &mut self.functions {
            function.optimize_undefs();
        }
    }

    pub fn optimize(&mut self) {
        for function in &mut self.functions {
            function.optimize();
        }
    }

    pub fn text(&self) -> String {
        format_hir_module(self)
    }

    pub fn print(&self) {
        println!("{}", self.text());
    }

    pub fn ast(&self) -> crate::ir::ast::AstModule {
        crate::ir::ast::AstModule::from_hir(self)
    }

    pub fn c(&self) -> String {
        self.ast().c()
    }

    pub fn print_c(&self) {
        println!("{}", self.c());
    }
}
