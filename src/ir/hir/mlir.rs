use super::hir::HirModule;
use super::print::hir_module_operation;
use crate::ir::mlir::{
    MlirDocument, MlirOperationRecord, canonical_value, named_value_name,
    rewrite_string_operation_attr, string_operation_attr,
};
use mlir::Operation;
use std::collections::BTreeMap;

pub struct HirMlirModule {
    document: MlirDocument,
}

impl HirMlirModule {
    pub fn from_hir(module: &HirModule) -> mlir::Result<Self> {
        let context = crate::ir::mlir::context();
        let op = hir_module_operation(&context, module)?;
        Ok(Self {
            document: MlirDocument::from_context_and_ops(context, vec![op])?,
        })
    }

    pub fn from_text(text: &str) -> mlir::Result<Self> {
        Ok(Self {
            document: MlirDocument::from_text(text)?,
        })
    }

    pub fn from_bytecode(bytecode: &[u8]) -> mlir::Result<Self> {
        Ok(Self {
            document: MlirDocument::from_bytecode(bytecode)?,
        })
    }

    pub fn optimize_assignments(&self) {
        optimize_assignments_operation(&self.document.operation(), self.document.context());
    }

    pub fn optimize(&self) {
        self.optimize_assignments();
    }

    pub fn text(&self) -> String {
        self.document
            .text()
            .unwrap_or_else(|error| format!("// mlir print failed: {error}"))
    }

    pub fn bytecode(&self) -> Vec<u8> {
        self.document.bytecode()
    }

    pub fn operation_names(&self) -> Vec<String> {
        self.document.operation_names()
    }

    pub fn operation_count(&self) -> usize {
        self.document.operation_count()
    }

    pub fn operation_records(&self) -> Vec<MlirOperationRecord> {
        self.document.operation_records()
    }
}

fn optimize_assignments_operation(operation: &Operation, context: &mlir::Context) {
    for index in 0..operation.num_regions() {
        let Some(region) = operation.region(index) else {
            continue;
        };
        let mut block = region.first_block();
        while let Some(current_block) = block {
            optimize_assignments_block(&current_block, context);
            block = current_block.next_in_region();
        }
    }
}

fn optimize_assignments_block(block: &mlir::Block, context: &mlir::Context) {
    let mut values = BTreeMap::<String, String>::new();
    let mut operation = block.first_operation();
    while let Some(current_operation) = operation {
        operation = current_operation.next_in_block();
        optimize_nested_assignments(&current_operation, context);
        rewrite_operation_attrs(&current_operation, context, &values);

        let name = current_operation.name().as_string();
        if name == "binlex.hir.assign" {
            if let (Some(target), Some(value)) = (
                string_operation_attr(&current_operation, "target"),
                string_operation_attr(&current_operation, "value"),
            ) {
                if let Some(target) = named_value_name(&target) {
                    values.insert(target.to_string(), canonical_value(&value, &values));
                }
            }
        }
    }
}

fn optimize_nested_assignments(operation: &Operation, context: &mlir::Context) {
    for index in 0..operation.num_regions() {
        let Some(region) = operation.region(index) else {
            continue;
        };
        let mut block = region.first_block();
        while let Some(current_block) = block {
            optimize_assignments_block(&current_block, context);
            block = current_block.next_in_region();
        }
    }
}

fn rewrite_operation_attrs(
    operation: &Operation,
    context: &mlir::Context,
    values: &BTreeMap<String, String>,
) {
    for name in ["value", "values", "condition"] {
        rewrite_string_operation_attr(operation, context, name, values);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::hir::{
        HirBlock, HirExpression, HirFunction, HirPlace, HirStatement, HirType, HirValue,
    };

    #[test]
    fn assignments_rewrite_mlir_value_attributes() {
        let ty = HirType::integer(32);
        let mut block = HirBlock::new();
        block.append_statement(HirStatement::Assign {
            target: HirPlace::Named {
                name: "v0".to_string(),
                ty: ty.clone(),
            },
            value: HirExpression::Value(HirValue::Integer { value: 7, bits: 32 }),
        });
        block.append_statement(HirStatement::Return {
            values: vec![HirExpression::Value(HirValue::Named {
                name: "v0".to_string(),
                ty,
            })],
        });

        let mut function = HirFunction::new(Some("f".to_string()));
        function.append_block(block);
        let mut module = HirModule::new(Some("m".to_string()));
        module.append_function(function);

        let mlir = module.mlir().expect("HIR should lower to MLIR");
        mlir.optimize_assignments();
        let text = mlir.text();

        assert!(text.contains("values = \"7:i32\""));
    }
}
