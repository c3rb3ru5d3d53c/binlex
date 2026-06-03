use super::mir::MirModule;
use super::print::mir_module_operation;
use crate::ir::mlir::{
    MlirDocument, MlirOperationRecord, canonical_value, rewrite_string_operation_attr,
    string_operation_attr,
};
use mlir::Operation;
use std::collections::BTreeMap;

pub struct MirMlirModule {
    document: MlirDocument,
}

impl MirMlirModule {
    pub fn from_mir(module: &MirModule) -> mlir::Result<Self> {
        let context = crate::ir::mlir::context();
        let op = mir_module_operation(&context, module)?;
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

    pub fn optimize_copy_propagation(&self) {
        optimize_copy_propagation_operation(&self.document.operation(), self.document.context());
    }

    pub fn optimize_constants(&self) {
        optimize_constants_operation(&self.document.operation(), self.document.context());
    }

    pub fn optimize(&self) {
        self.optimize_copy_propagation();
        self.optimize_constants();
        self.optimize_copy_propagation();
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

fn optimize_copy_propagation_operation(operation: &Operation, context: &mlir::Context) {
    for index in 0..operation.num_regions() {
        let Some(region) = operation.region(index) else {
            continue;
        };
        let mut block = region.first_block();
        while let Some(current_block) = block {
            optimize_copy_propagation_block(&current_block, context);
            block = current_block.next_in_region();
        }
    }
}

fn optimize_constants_operation(operation: &Operation, context: &mlir::Context) {
    for index in 0..operation.num_regions() {
        let Some(region) = operation.region(index) else {
            continue;
        };
        let mut block = region.first_block();
        while let Some(current_block) = block {
            optimize_constants_block(&current_block, context);
            block = current_block.next_in_region();
        }
    }
}

fn optimize_constants_block(block: &mlir::Block, context: &mlir::Context) {
    let mut constants = BTreeMap::<String, String>::new();
    let mut operation = block.first_operation();
    while let Some(current_operation) = operation {
        operation = current_operation.next_in_block();
        optimize_nested_constants(&current_operation, context);
        rewrite_operation_value_attrs(&current_operation, context, &constants);

        let result = string_attr(&current_operation, "result");
        if let Some(result) = result {
            if let Some(value) = fold_constant_operation(&current_operation) {
                constants.insert(result, value);
            } else {
                constants.remove(&result);
            }
        }
    }
}

fn optimize_nested_constants(operation: &Operation, context: &mlir::Context) {
    for index in 0..operation.num_regions() {
        let Some(region) = operation.region(index) else {
            continue;
        };
        let mut block = region.first_block();
        while let Some(current_block) = block {
            optimize_constants_block(&current_block, context);
            block = current_block.next_in_region();
        }
    }
}

fn fold_constant_operation(operation: &Operation) -> Option<String> {
    let name = operation.name().as_string();
    if name == "binlex.mir.copy" {
        return integer_value_attr(operation, "value").map(format_integer_value);
    }

    let lhs = integer_value_attr(operation, "lhs")?;
    let rhs = integer_value_attr(operation, "rhs")?;
    let bits = lhs.bits.max(rhs.bits);
    let value = match name.as_str() {
        "binlex.mir.add" => lhs.value.wrapping_add(rhs.value),
        "binlex.mir.sub" => lhs.value.wrapping_sub(rhs.value),
        "binlex.mir.mul" => lhs.value.wrapping_mul(rhs.value),
        "binlex.mir.and" => lhs.value & rhs.value,
        "binlex.mir.or" => lhs.value | rhs.value,
        "binlex.mir.xor" => lhs.value ^ rhs.value,
        "binlex.mir.shl" => lhs.value.wrapping_shl(rhs.value as u32),
        "binlex.mir.ashr" => lhs.value >> (rhs.value as u32),
        "binlex.mir.lshr" => ((lhs.value as u128) >> (rhs.value as u32)) as i128,
        _ => return None,
    };
    Some(format_integer_value(IntegerValue { value, bits }))
}

fn optimize_copy_propagation_block(block: &mlir::Block, context: &mlir::Context) {
    let mut aliases = BTreeMap::<String, String>::new();
    let mut operation = block.first_operation();
    while let Some(current_operation) = operation {
        operation = current_operation.next_in_block();
        optimize_nested_copy_propagation(&current_operation, context);
        rewrite_operation_value_attrs(&current_operation, context, &aliases);

        let result = string_attr(&current_operation, "result");
        if let Some(result) = result {
            if current_operation.name().as_string() == "binlex.mir.copy" {
                if let Some(value) = string_attr(&current_operation, "value") {
                    aliases.insert(result, canonical_value(&value, &aliases));
                    continue;
                }
            }
            aliases.remove(&result);
        }
    }
}

fn optimize_nested_copy_propagation(operation: &Operation, context: &mlir::Context) {
    for index in 0..operation.num_regions() {
        let Some(region) = operation.region(index) else {
            continue;
        };
        let mut block = region.first_block();
        while let Some(current_block) = block {
            optimize_copy_propagation_block(&current_block, context);
            block = current_block.next_in_region();
        }
    }
}

fn rewrite_operation_value_attrs(
    operation: &Operation,
    context: &mlir::Context,
    aliases: &BTreeMap<String, String>,
) {
    for name in [
        "value",
        "lhs",
        "rhs",
        "condition",
        "true",
        "false",
        "address",
        "src_address",
        "dst_address",
        "count",
        "decrement",
        "arguments",
        "then_arguments",
        "else_arguments",
        "values",
    ] {
        rewrite_string_operation_attr(operation, context, name, aliases);
    }
}

fn string_attr(operation: &Operation, name: &str) -> Option<String> {
    string_operation_attr(operation, name)
}

#[derive(Clone, Copy)]
struct IntegerValue {
    value: i128,
    bits: u16,
}

fn integer_value_attr(operation: &Operation, name: &str) -> Option<IntegerValue> {
    parse_integer_value(&string_attr(operation, name)?)
}

fn parse_integer_value(value: &str) -> Option<IntegerValue> {
    let (value, bits) = value.rsplit_once(":i")?;
    Some(IntegerValue {
        value: value.parse().ok()?,
        bits: bits.parse().ok()?,
    })
}

fn format_integer_value(value: IntegerValue) -> String {
    format!("{}:i{}", value.value, value.bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::mir::{
        MirBlock, MirFunction, MirOperation, MirOperationKind, MirTerminator, MirType, MirValue,
    };

    #[test]
    fn copy_propagation_rewrites_mlir_value_attributes() {
        let ty = MirType::integer(32);
        let mut block = MirBlock::new("entry".to_string());
        block.append_operation(MirOperation::new(
            Some("v0".to_string()),
            MirOperationKind::Copy {
                value: MirValue::integer(1, 32),
                ty: ty.clone(),
            },
        ));
        block.append_operation(MirOperation::new(
            Some("v1".to_string()),
            MirOperationKind::Copy {
                value: MirValue::named("v0".to_string(), ty.clone()),
                ty: ty.clone(),
            },
        ));
        block.append_operation(MirOperation::new(
            Some("v2".to_string()),
            MirOperationKind::Add {
                lhs: MirValue::named("v1".to_string(), ty.clone()),
                rhs: MirValue::integer(2, 32),
                ty: ty.clone(),
            },
        ));
        block.set_terminator(MirTerminator::Return {
            values: vec![MirValue::named("v2".to_string(), ty)],
        });

        let mut function = MirFunction::new(Some("f".to_string()));
        function.append_block(block);
        let mut module = MirModule::new(Some("m".to_string()));
        module.append_function(function);

        let mlir = module.mlir().expect("MIR should lower to MLIR");
        mlir.optimize_copy_propagation();
        let text = mlir.text();

        assert!(text.contains("lhs = \"1:i32\""));
        assert!(text.contains("result = \"v1\""));
        assert!(text.contains("value = \"1:i32\""));
        assert!(!text.contains("%v1"));
    }

    #[test]
    fn constants_rewrites_mlir_value_attributes() {
        let ty = MirType::integer(32);
        let mut block = MirBlock::new("entry".to_string());
        block.append_operation(MirOperation::new(
            Some("v0".to_string()),
            MirOperationKind::Add {
                lhs: MirValue::integer(1, 32),
                rhs: MirValue::integer(2, 32),
                ty: ty.clone(),
            },
        ));
        block.append_operation(MirOperation::new(
            Some("v1".to_string()),
            MirOperationKind::Mul {
                lhs: MirValue::named("v0".to_string(), ty.clone()),
                rhs: MirValue::integer(4, 32),
                ty: ty.clone(),
            },
        ));
        block.set_terminator(MirTerminator::Return {
            values: vec![MirValue::named("v1".to_string(), ty)],
        });

        let mut function = MirFunction::new(Some("f".to_string()));
        function.append_block(block);
        let mut module = MirModule::new(Some("m".to_string()));
        module.append_function(function);

        let mlir = module.mlir().expect("MIR should lower to MLIR");
        mlir.optimize_constants();
        let text = mlir.text();

        assert!(text.contains("lhs = \"3:i32\""));
        assert!(text.contains("values = \"12:i32\""));
        assert!(!text.contains("%v0"));
        assert!(!text.contains("%v1"));
    }

    #[test]
    fn operation_records_include_operation_attributes() {
        let ty = MirType::integer(32);
        let mut block = MirBlock::new("entry".to_string());
        block.append_operation(MirOperation::new(
            Some("v0".to_string()),
            MirOperationKind::Copy {
                value: MirValue::integer(7, 32),
                ty,
            },
        ));

        let mut function = MirFunction::new(Some("f".to_string()));
        function.append_block(block);
        let mut module = MirModule::new(Some("m".to_string()));
        module.append_function(function);

        let mlir = module.mlir().expect("MIR should lower to MLIR");
        let records = mlir.operation_records();
        let copy = records
            .iter()
            .find(|record| record.name == "binlex.mir.copy")
            .expect("copy operation should be present");

        assert_eq!(
            copy.attributes.get("result").map(String::as_str),
            Some("v0")
        );
        assert_eq!(
            copy.attributes.get("value").map(String::as_str),
            Some("7:i32")
        );
    }

    #[test]
    fn from_text_parses_mlir_module() {
        let ty = MirType::integer(32);
        let mut block = MirBlock::new("entry".to_string());
        block.append_operation(MirOperation::new(
            Some("v0".to_string()),
            MirOperationKind::Copy {
                value: MirValue::integer(7, 32),
                ty,
            },
        ));

        let mut function = MirFunction::new(Some("f".to_string()));
        function.append_block(block);
        let mut module = MirModule::new(Some("m".to_string()));
        module.append_function(function);

        let text = module.mlir().expect("MIR should lower to MLIR").text();
        let parsed = MirMlirModule::from_text(&text).expect("MIR MLIR text should parse");

        assert!(
            parsed
                .operation_names()
                .contains(&"binlex.mir.copy".to_string())
        );
    }

    #[test]
    fn bytecode_roundtrip_preserves_mlir_module() {
        let ty = MirType::integer(32);
        let mut block = MirBlock::new("entry".to_string());
        block.append_operation(MirOperation::new(
            Some("v0".to_string()),
            MirOperationKind::Copy {
                value: MirValue::integer(7, 32),
                ty,
            },
        ));

        let mut function = MirFunction::new(Some("f".to_string()));
        function.append_block(block);
        let mut module = MirModule::new(Some("m".to_string()));
        module.append_function(function);

        let mlir = module.mlir().expect("MIR should lower to MLIR");
        let bytecode = mlir.bytecode();
        assert!(!bytecode.is_empty());

        let parsed = MirMlirModule::from_bytecode(&bytecode).expect("MIR bytecode should parse");
        let records = parsed.operation_records();
        assert!(records.iter().any(|record| {
            record.name == "binlex.mir.copy"
                && record.attributes.get("value").map(String::as_str) == Some("7:i32")
        }));
    }
}
