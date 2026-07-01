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
    use crate::irs::lir::{
        LirBlock, LirFunction, LirInstruction, LirMlirModule, LirModule, LirStatus, LirTerminator,
    };

    #[test]
    fn normalize_status_rewrites_lir_instruction_status_attrs() {
        let module = LirModule::from_instructions(vec![LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: Vec::new(),
            terminator: LirTerminator::FallThrough,
        }]);

        let mlir = module.mlir().expect("LIR should lower to MLIR");
        mlir.normalize_status();
        let text = mlir.text();

        assert!(text.contains("status = \"complete\""));
    }

    #[test]
    fn scoped_lir_bytecode_accessors_emit_parseable_mlir_modules() {
        let instruction = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: Vec::new(),
            terminator: LirTerminator::FallThrough,
        };

        let mut block = LirBlock::new(Some("block_0".to_string()));
        block.append_instruction(instruction.clone());

        let mut function = LirFunction::new(Some("function_0".to_string()));
        function.append_block(block.clone());

        let instruction_bytecode = instruction.bytecode().expect("instruction bytecode");
        let block_bytecode = block.bytecode().expect("block bytecode");
        let function_bytecode = function.bytecode().expect("function bytecode");
        let module = LirModule::from_instructions(vec![instruction.clone()]);
        let module_bytecode = module.bytecode().expect("module bytecode");

        assert!(!instruction_bytecode.is_empty());
        assert!(!block_bytecode.is_empty());
        assert!(!function_bytecode.is_empty());
        assert!(!module_bytecode.is_empty());
        assert!(LirMlirModule::from_bytecode(&instruction_bytecode).is_ok());
        assert!(LirMlirModule::from_bytecode(&block_bytecode).is_ok());
        assert!(LirMlirModule::from_bytecode(&function_bytecode).is_ok());
        assert!(LirMlirModule::from_bytecode(&module_bytecode).is_ok());
    }

    #[test]
    fn scoped_lir_ssa_then_bytecode_emits_parseable_mlir_modules() {
        let instruction = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: Vec::new(),
            terminator: LirTerminator::FallThrough,
        };

        let mut block = LirBlock::new(Some("block_0".to_string()));
        block.append_instruction(instruction.clone());

        let mut function = LirFunction::new(Some("function_0".to_string()));
        function.append_block(block.clone());

        let module = LirModule::from_instructions(vec![instruction.clone()]);
        let instruction_bytecode = instruction.ssa().bytecode().expect("instruction bytecode");
        let block_bytecode = block.ssa().bytecode().expect("block bytecode");
        let function_bytecode = function.ssa().bytecode().expect("function bytecode");
        let module_bytecode = module.ssa().bytecode().expect("module bytecode");

        assert!(!instruction_bytecode.is_empty());
        assert!(!block_bytecode.is_empty());
        assert!(!function_bytecode.is_empty());
        assert!(!module_bytecode.is_empty());
        assert!(LirMlirModule::from_bytecode(&instruction_bytecode).is_ok());
        assert!(LirMlirModule::from_bytecode(&block_bytecode).is_ok());
        assert!(LirMlirModule::from_bytecode(&function_bytecode).is_ok());
        assert!(LirMlirModule::from_bytecode(&module_bytecode).is_ok());
    }
}
