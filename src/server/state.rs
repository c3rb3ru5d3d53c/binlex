use std::collections::BTreeMap;
use std::sync::Arc;

use crate::Config;
use crate::config::ConfigProcessors;
use crate::runtime::ProcessorPool;
use tracing::{debug, info};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub processor_pools: BTreeMap<String, Arc<ProcessorPool>>,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, crate::runtime::error::ProcessorError> {
        let mut processor_pools = BTreeMap::new();
        if !config.processors.enabled {
            return Ok(Self {
                config,
                processor_pools,
            });
        }

        let processors = ConfigProcessors {
            enabled: true,
            ..config.processors.clone()
        };
        for registration in
            crate::processor::registered_processor_registrations_for_config(&processors)
        {
            if !config
                .processors
                .processor(&registration.name)
                .is_some_and(|processor| processor.enabled)
            {
                continue;
            }
            if config
                .processors
                .processor(&registration.name)
                .and_then(|processor| {
                    crate::server::processors::configured_server_transport(
                        processor,
                        &registration.transports,
                    )
                    .ok()
                })
                != Some(crate::processor::ProcessorTransport::Ipc)
            {
                continue;
            }
            let pool = crate::runtime::transports::ipc::ProcessorPool::for_external(
                &processors,
                &registration.name,
            )?;
            processor_pools.insert(registration.name.clone(), pool);
        }
        Ok(Self {
            config,
            processor_pools,
        })
    }

    pub fn debug_enabled(&self) -> bool {
        self.config.server.debug
    }

    pub fn debug_log<T: std::fmt::Display>(&self, line: T) {
        if self.debug_enabled() {
            debug!("{}", line);
        }
    }

    pub fn log<T: std::fmt::Display>(&self, line: T) {
        info!("{}", line);
    }

    pub fn processor_pool(&self, name: &str) -> Option<Arc<ProcessorPool>> {
        self.processor_pools.get(name).cloned()
    }

    pub fn processor_enabled(&self, name: &str) -> bool {
        self.config.processors.enabled
            && self
                .config
                .processors
                .processor(name)
                .is_some_and(|processor| processor.enabled)
    }
}
