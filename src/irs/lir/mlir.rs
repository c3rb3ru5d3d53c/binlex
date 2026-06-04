use super::ir::LirModule;
use super::print::lir_module_operation;
use crate::irs::mlir::{
    MlirDocument, MlirOperationRecord, set_string_operation_attr, string_operation_attr,
    walk_operations,
};
use mlir::Operation;

pub struct LirMlirModule {
    document: MlirDocument,
}

impl LirMlirModule {
    pub fn from_lir(module: &LirModule) -> mlir::Result<Self> {
        let context = crate::irs::mlir::context();
        let op = lir_module_operation(&context, module)?;
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

    pub fn normalize_status(&self) {
        normalize_status_operation(&self.document.operation(), self.document.context());
    }

    pub fn optimize(&self) {
        self.normalize_status();
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

fn normalize_status_operation(operation: &Operation, context: &mlir::Context) {
    walk_operations(operation, &mut |operation| {
        if operation.name().as_string() == "binlex.lir.instruction" {
            if let Some(status) = string_operation_attr(operation, "status") {
                let normalized = status.to_ascii_lowercase();
                if normalized != status {
                    set_string_operation_attr(operation, context, "status", &normalized);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use crate::irs::lir::{Lir, LirMetadata, LirModule, LirStatus, LirTerminator};

    #[test]
    fn normalize_status_rewrites_lir_instruction_status_attrs() {
        let module = LirModule::from_instructions(vec![Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: LirMetadata::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: LirTerminator::FallThrough,
            diagnostics: Vec::new(),
        }]);

        let mlir = module.mlir().expect("LIR should lower to MLIR");
        mlir.normalize_status();
        let text = mlir.text();

        assert!(text.contains("status = \"complete\""));
    }
}
