use mlir::{
    Attribute, Block, Context, Identifier, Location, Module, NamedAttribute, Operation,
    OperationState, Region, Type,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MlirOperationRecord {
    pub name: String,
    pub attributes: BTreeMap<String, String>,
}

pub(crate) struct MlirDocument {
    module: Module,
    _context: Context,
}

impl MlirDocument {
    pub(crate) fn from_context_and_ops(
        context: Context,
        ops: Vec<Operation>,
    ) -> mlir::Result<Self> {
        let module = module_with_ops(&context, ops)?;
        Ok(Self {
            module,
            _context: context,
        })
    }

    pub(crate) fn from_text(text: &str) -> mlir::Result<Self> {
        let context = context();
        let module = Module::parse(&context, text)?;
        Ok(Self {
            module,
            _context: context,
        })
    }

    pub(crate) fn from_bytecode(bytecode: &[u8]) -> mlir::Result<Self> {
        let context = context();
        let module = Module::parse_bytes(&context, bytecode)?;
        Ok(Self {
            module,
            _context: context,
        })
    }

    pub(crate) fn text(&self) -> mlir::Result<String> {
        self.module.to_string()
    }

    pub(crate) fn bytecode(&self) -> Vec<u8> {
        self.module.bytecode()
    }

    pub(crate) fn operation(&self) -> mlir::Operation {
        self.module.operation()
    }

    pub(crate) fn context(&self) -> &Context {
        &self._context
    }

    pub(crate) fn operation_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        walk_operations(&self.operation(), &mut |operation| {
            names.push(operation.name().as_string());
        });
        names
    }

    pub(crate) fn operation_count(&self) -> usize {
        let mut count = 0;
        walk_operations(&self.operation(), &mut |_| {
            count += 1;
        });
        count
    }

    pub(crate) fn operation_records(&self) -> Vec<MlirOperationRecord> {
        let mut records = Vec::new();
        walk_operations(&self.operation(), &mut |operation| {
            records.push(operation_record(operation));
        });
        records
    }
}

pub(crate) fn context() -> Context {
    let context = Context::new_with_all_dialects();
    context.set_allow_unregistered_dialects(true);
    context
}

pub(crate) fn string_attr(context: &Context, name: &str, value: &str) -> NamedAttribute {
    NamedAttribute::new(
        Identifier::new(context, name),
        Attribute::string(context, value),
    )
}

pub(crate) fn integer_attr(context: &Context, name: &str, value: i64) -> NamedAttribute {
    NamedAttribute::new(
        Identifier::new(context, name),
        Attribute::integer(Type::integer(context, 64), value),
    )
}

pub(crate) fn operation(
    context: &Context,
    name: &str,
    attrs: Vec<NamedAttribute>,
    regions: Vec<Region>,
) -> mlir::Result<Operation> {
    let mut state = OperationState::new(name, Location::unknown(context));
    state.add_attributes(&attrs);
    state.add_owned_regions(regions);
    Operation::create(&mut state)
}

pub(crate) fn region_with_ops(ops: Vec<Operation>) -> Region {
    let region = Region::new();
    let block = Block::new(&[]);
    for op in ops {
        block.append_owned_operation(op);
    }
    region.append_owned_block(block);
    region
}

pub(crate) fn module_with_ops(context: &Context, ops: Vec<Operation>) -> mlir::Result<Module> {
    let module = Module::new(Location::unknown(context))?;
    let body = module
        .body()
        .expect("new MLIR module should always have a body block");
    for op in ops {
        body.append_owned_operation(op);
    }
    Ok(module)
}

pub(crate) fn walk_operations(operation: &Operation, visitor: &mut impl FnMut(&Operation)) {
    visitor(operation);
    for index in 0..operation.num_regions() {
        let Some(region) = operation.region(index) else {
            continue;
        };
        let mut block = region.first_block();
        while let Some(current_block) = block {
            let mut child = current_block.first_operation();
            while let Some(current_child) = child {
                child = current_child.next_in_block();
                walk_operations(&current_child, visitor);
            }
            block = current_block.next_in_region();
        }
    }
}

pub(crate) fn string_operation_attr(operation: &Operation, name: &str) -> Option<String> {
    operation.attribute(name).and_then(|attr| attr.as_string())
}

pub(crate) fn set_string_operation_attr(
    operation: &Operation,
    context: &Context,
    name: &str,
    value: &str,
) {
    operation.set_attribute(name, Attribute::string(context, value));
}

pub(crate) fn named_value_name(value: &str) -> Option<&str> {
    value.strip_prefix('%').and_then(|rest| {
        rest.split(|ch: char| {
            ch == ':' || ch == ',' || ch == ')' || ch == '(' || ch.is_whitespace()
        })
        .next()
        .filter(|name| !name.is_empty())
    })
}

pub(crate) fn canonical_value(value: &str, aliases: &BTreeMap<String, String>) -> String {
    let mut current = value.to_string();
    for _ in 0..aliases.len() {
        let Some(name) = named_value_name(&current) else {
            break;
        };
        let Some(next) = aliases.get(name) else {
            break;
        };
        if next == &current {
            break;
        }
        current = next.clone();
    }
    current
}

pub(crate) fn rewrite_string_operation_attr(
    operation: &Operation,
    context: &Context,
    name: &str,
    aliases: &BTreeMap<String, String>,
) {
    let Some(value) = string_operation_attr(operation, name) else {
        return;
    };
    let rewritten = value
        .lines()
        .map(|line| canonical_value(line, aliases))
        .collect::<Vec<_>>()
        .join("\n");
    if rewritten != value {
        set_string_operation_attr(operation, context, name, &rewritten);
    }
}

pub(crate) fn operation_record(operation: &Operation) -> MlirOperationRecord {
    let mut attributes = BTreeMap::new();
    for index in 0..operation.num_attributes() {
        let attribute = operation.attribute_at(index);
        attributes.insert(
            attribute.name().as_string(),
            format_attribute_value(&attribute.attribute()),
        );
    }
    MlirOperationRecord {
        name: operation.name().as_string(),
        attributes,
    }
}

fn format_attribute_value(attribute: &Attribute) -> String {
    if let Some(value) = attribute.as_string() {
        return value;
    }
    if let Some(value) = attribute.as_bool() {
        return value.to_string();
    }
    if let Some(value) = attribute.as_signed_integer() {
        return value.to_string();
    }
    attribute
        .to_string()
        .unwrap_or_else(|error| format!("<mlir attribute print failed: {error}>"))
}
