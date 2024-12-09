use std::io::Error;
use serde::{Deserialize, Serialize};
use crate::controlflow::Attribute;

/// Represents a JSON-serializable structure containing metadata about a tag.
#[derive(Serialize, Deserialize, Clone)]
pub struct TagJson {
    /// The type of this entity, always `"tag"`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The tag value
    pub value: String,
}

#[derive(Clone)]
pub struct Tag {
    tag: String,
}

impl Tag {
    #[allow(dead_code)]
    pub fn new(tag: String) -> Self{
        Self {
            tag: tag,
        }
    }

    /// Processes the function signature into its JSON-serializable representation.
    ///
    /// # Returns
    ///
    /// Returns a `FunctionSymbolJson` struct containing metadata about the function symbol.
    pub fn process(&self) -> TagJson {
        TagJson {
            type_: "tag".to_string(),
            value: self.tag.clone(),
        }
    }

    /// Processes the tag into an `Attribute`.
    ///
    /// # Returns
    ///
    /// Returns a `Attribute` struct containing the tag.
    pub fn attribute(&self) -> Attribute {
        Attribute::Tag(self.process())
    }

     /// Prints the JSON representation of the function symbol to standard output.
     #[allow(dead_code)]
     pub fn print(&self) {
         if let Ok(json) = self.json() {
             println!("{}", json);
         }
     }

     /// Converts the function symbol metadata into a JSON string representation.
     ///
     /// # Returns
     ///
     /// Returns `Ok(String)` containing the JSON representation, or an `Err` if serialization fails.
     pub fn json(&self) -> Result<String, Error> {
         let raw = self.process();
         let result = serde_json::to_string(&raw)?;
         Ok(result)
     }

}
