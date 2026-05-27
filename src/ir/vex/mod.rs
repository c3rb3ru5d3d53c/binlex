pub mod lifter;
pub mod lower;

use serde::{Deserialize, Serialize};

pub use lifter::Lifter;
pub use lower::{from_lir_block, from_lir_function, from_lir_module};

#[derive(Serialize, Deserialize, Clone)]
pub struct VexJson {
    pub text: String,
}
