pub mod child;
pub mod dispatch;
pub mod error;
pub mod modes;

pub use dispatch::{Processor, ProcessorDispatch};
pub use error::ProcessorError;
pub use modes::ipc::ProcessorPool;
