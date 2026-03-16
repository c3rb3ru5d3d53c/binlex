use std::collections::BTreeMap;
use std::sync::Arc;

use crate::ConfigProcessors;
use crate::processing::pool::ProcessorPool;
use crate::server::config::ServerConfig;

#[derive(Clone)]
pub struct AppState {
    pub config: ServerConfig,
    pub processor_pools: BTreeMap<String, Arc<ProcessorPool>>,
}

impl AppState {
    pub fn new(config: ServerConfig) -> Result<Self, crate::processing::error::ProcessorError> {
        let processors = ConfigProcessors {
            enabled: true,
            ..config.processors.clone()
        };
        let mut processor_pools = BTreeMap::new();
        for registration in crate::processors::registered_processor_registrations() {
            if !registration.supported_on_current_os() {
                continue;
            }
            let pool = (registration.make_pool)(&processors)?;
            processor_pools.insert(registration.name.to_string(), pool);
        }
        Ok(Self {
            config,
            processor_pools,
        })
    }

    pub fn processor_pool(&self, name: &str) -> Option<Arc<ProcessorPool>> {
        self.processor_pools.get(name).cloned()
    }
}
