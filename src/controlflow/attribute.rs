use serde_json::json;
use crate::formats::file::FileJson;
use crate::controlflow::SymbolJson;
use crate::controlflow::TagJson;
use serde_json::Value;
use std::io::Error;

#[derive(Clone)]
pub enum Attribute {
    File(FileJson),
    Symbol(SymbolJson),
    Tag(TagJson),
}

impl Attribute {
    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            Attribute::File(file_json) => serde_json::to_value(file_json)
                .unwrap_or(json!({})),
            Attribute::Symbol(symbol_json) => serde_json::to_value(symbol_json)
            .unwrap_or(json!({})),
            Attribute::Tag(tag_json) => serde_json::to_value(tag_json)
            .unwrap_or(json!({})),
        }
    }
}

#[derive(Clone)]
pub struct Attributes {
    values: Vec<Attribute>,
}

impl Attributes {
    pub fn new() -> Self {
        Self {
            values: Vec::<Attribute>::new(),
        }
    }

    pub fn push(&mut self, attribute: Attribute) {
        self.values.push(attribute);
    }

    pub fn pop(&mut self) -> Option<Attribute> {
        self.values.pop()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn process(&self) -> Value {
        let json_list: Vec<Value> = self
            .values
            .iter()
            .map(|attribute| attribute.to_json_value())
            .collect();
        json!(json_list)
    }

    pub fn json(&self) -> Result<String, Error> {
        let raw = self.process();
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }

    #[allow(dead_code)]
    pub fn print(&self) {
        if let Ok(json) = self.json() {
            println!("{}", json);
        }
    }

}
