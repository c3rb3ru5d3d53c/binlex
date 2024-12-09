use std::io::Error;
use serde::{Deserialize, Serialize};
use serde_json;
use crate::controlflow::Attribute;

/// Represents a JSON-serializable structure containing metadata about a function symbol.
#[derive(Serialize, Deserialize)]
pub struct SymbolIoJson {
    /// The type of this entity.
    #[serde(rename = "type")]
    pub type_: String,
    /// The type of symbol
    pub symbol_type: String,
    /// Names associated with the function symbol.
    pub name: String,
    /// The offset of the function symbol, if available.
    pub file_offset: Option<u64>,
    /// The relative virtual address of the function symbol, if available.
    pub relative_virtual_address: Option<u64>,
    /// The virtual address of the function symbol, if available.
    pub virtual_address: Option<u64>,
    /// The slice associated with the function symbol, MachO format only
    pub slice: Option<usize>,
}

/// Represents a JSON-serializable structure containing metadata about a function symbol.
#[derive(Serialize, Deserialize, Clone)]
pub struct SymbolJson {
    #[serde(rename = "type")]
    /// The type always `symbol`.
    pub type_: String,
    /// The type of symbol.
    pub symbol_type: String,
    /// Names associated with the function symbol.
    pub name: String,
    /// The virtual address of the function symbol.
    #[serde(skip)]
    pub address: u64,
}

/// Represents a structure containing metadata about a function symbol.
#[derive(Clone, Debug)]
pub struct Symbol {
    /// Names associated with the function symbol.
    pub name: String,
     /// The virtual address of the function symbol.
    pub address: u64,
    /// The type of symbol
    pub symbol_type: String,
}

impl Symbol {
    #[allow(dead_code)]
    pub fn new(address: u64, symbol_type: String, name: String) -> Self{
        Self {
            name: name,
            address: address,
            symbol_type: symbol_type,
        }
    }

    /// Processes the function signature into its JSON-serializable representation.
    ///
    /// # Returns
    ///
    /// Returns a `FunctionSymbolJson` struct containing metadata about the function symbol.
    pub fn process(&self) -> SymbolJson {
        SymbolJson {
            type_: "symbol".to_string(),
            symbol_type: self.symbol_type.clone(),
            name: self.name.clone(),
            address: self.address,
        }
    }

    /// Processes the tag into an `Attribute`.
    ///
    /// # Returns
    ///
    /// Returns a `Attribute` struct containing the tag.
    pub fn attribute(&self) -> Attribute {
        Attribute::Symbol(self.process())
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

    /// Demangles a Microsoft Visual C++ (MSVC) mangled symbol name.
    ///
    /// # Arguments
    ///
    /// * `mangled_name` - A string slice representing the mangled symbol name to demangle.
    ///
    /// # Returns
    ///
    /// A `String` containing the demangled symbol name in the form `namespace::...::function_name`.
    /// If the input string does not start with the MSVC mangling prefix `?`, the original string
    /// is returned unchanged.
    #[allow(dead_code)]
    pub fn demangle_msvc_name(mangled_name: &str) -> String {
        if !mangled_name.starts_with('?') {
            return mangled_name.to_string();
        }
        let parts: Vec<&str> = mangled_name.trim_start_matches('?').split('@').collect();
        let function_name = parts.get(0).unwrap_or(&mangled_name);
        let mut namespaces: Vec<&str> = parts.iter().skip(1).take_while(|&&s| s != "").map(|&s| s).collect();
        namespaces.reverse();
        format!(
            "{}::{}",
            namespaces.join("::"),
            function_name
        )
    }
}
