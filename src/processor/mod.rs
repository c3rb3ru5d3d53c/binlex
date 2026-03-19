pub mod api;
pub mod graph;
pub mod registry;
pub mod selection;

pub use api::{JsonProcessor, ProcessorContext};
pub use graph::{GraphProcessor, ProcessorOutputs, apply_output};
pub use registry::{
    ProcessorRegistration, RegisteredProcessor, RegisteredProcessorDispatch,
    default_processor_config, default_processor_configs, dispatch_by_name,
    enabled_processors_for_target, processor_registration_by_name, processor_registration_by_type,
    registered_processor_registrations,
};
pub use selection::{
    ProcessorArchitecture, ProcessorMode, ProcessorOs, ProcessorSelection, ProcessorTarget,
};
