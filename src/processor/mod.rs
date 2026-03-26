pub mod api;
pub mod graph;
pub mod registry;
pub mod selection;

pub use api::{JsonProcessor, ProcessorContext};
pub use graph::{
    GraphProcessor, GraphProcessorFanout, OnGraphOptions, ProcessorOutputs, apply_output,
};
pub use registry::{
    ProcessorRegistration, RegisteredProcessor, default_processor_config,
    default_processor_configs, enabled_processors_for_target, external_processor_registration,
    processor_registration_by_name, processor_registration_by_name_for_config,
    registered_processor_registrations, registered_processor_registrations_for_config,
};
pub use selection::{ProcessorArchitecture, ProcessorOs, ProcessorTarget, ProcessorTransport};
