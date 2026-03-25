pub mod child;
pub mod dispatch;
pub mod error;
pub mod execute;
pub mod transports;

pub use child::ProcessorEntryError;
pub use dispatch::{
    HostRuntime, HostRuntimeError, Processor, ProcessorDispatch, WorkerLaunch, host_runtime,
    register_host_runtime,
};
pub use error::ProcessorError;
pub use execute::{JsonProcessorRequest, JsonProcessorResponse};
pub use transports::ipc::ProcessorPool;
