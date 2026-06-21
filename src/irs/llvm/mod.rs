pub mod lower;
pub mod module;
pub mod optimizers;
pub mod prepare;
pub mod verify;

use serde::{Deserialize, Serialize};

pub use lower::{LlvmFromLir, from_lir};
pub use module::LlvmModule;
pub use optimizers::Optimizers;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Reconstruct,
    Intrinsic,
    Lir,
}
