pub mod lifter;
pub mod optimizers;

use serde::{Deserialize, Serialize};

pub use lifter::Lifter;
pub use optimizers::Optimizers;
#[cfg(not(target_os = "windows"))]
use super::vex::VexJson;

#[derive(Serialize, Deserialize, Clone)]
pub struct LlvmNormalizedJson {
    pub text: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LlvmJson {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized: Option<LlvmNormalizedJson>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LiftersJson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llvm: Option<LlvmJson>,
    #[cfg(not(target_os = "windows"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vex: Option<VexJson>,
}
