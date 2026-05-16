pub mod lifter;

use serde::{Deserialize, Serialize};

pub use lifter::Lifter;

#[derive(Serialize, Deserialize, Clone)]
pub struct VexJson {
    pub text: String,
}
