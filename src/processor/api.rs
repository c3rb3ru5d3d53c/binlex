use crate::Config;
use crate::config::{ConfigProcessor, ConfigProcessors};
use crate::runtime::{Processor, ProcessorError};
use serde_json::Value;

pub trait ProcessorContext {
    fn processors(&self) -> &ConfigProcessors;

    fn processor(&self, name: &str) -> Option<&ConfigProcessor> {
        self.processors().processor(name)
    }
}

impl ProcessorContext for Config {
    fn processors(&self) -> &ConfigProcessors {
        &self.processors
    }
}

pub trait JsonProcessor: Processor {
    fn request<C: ProcessorContext>(
        context: &C,
        data: Value,
    ) -> Result<Self::Request, ProcessorError>;

    fn response(response: Self::Response) -> Result<Value, ProcessorError>;

    fn execute_ipc_value<C: ProcessorContext>(
        context: &C,
        data: Value,
    ) -> Result<Value, ProcessorError>
    where
        Self: Sized,
    {
        if let Some(registration) = crate::processor::processor_registration_by_name_for_config(
            context.processors(),
            Self::NAME,
        ) {
            crate::processor::registry::ensure_payload_architecture_supported(
                &registration.registration,
                &data,
            )?;
        }
        crate::runtime::transports::ipc::execute_external(Self::NAME, context.processors(), data)
    }
}

impl<T> JsonProcessor for T
where
    T: crate::processor::GraphProcessor,
{
    fn request<C: ProcessorContext>(
        context: &C,
        data: Value,
    ) -> Result<Self::Request, ProcessorError> {
        <T as crate::processor::GraphProcessor>::request_message(context, data)
    }

    fn response(response: Self::Response) -> Result<Value, ProcessorError> {
        <T as crate::processor::GraphProcessor>::response_message(response)
    }
}
