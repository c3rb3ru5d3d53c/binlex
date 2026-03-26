// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use super::{ConfigProcessor, ConfigProcessorTransport, ConfigProcessorValue, ConfigProcessors};
use std::collections::BTreeMap;

impl Default for ConfigProcessors {
    fn default() -> Self {
        Self {
            enabled: true,
            path: Some(crate::Config::default_processor_directory()),
            processes: 2,
            compression: true,
            restart_on_crash: true,
            max_payload_bytes: 64 * 1024 * 1024,
            idle_timeout_ms: 30_000,
            max_queue_depth: 2 * 64,
            processors: crate::processor::default_processor_configs(),
        }
    }
}

impl ConfigProcessors {
    pub fn processor(&self, name: &str) -> Option<&ConfigProcessor> {
        self.processors.get(name)
    }

    pub fn processor_mut(&mut self, name: &str) -> Option<&mut ConfigProcessor> {
        self.processors.get_mut(name)
    }

    pub fn ensure_processor(&mut self, name: &str) -> Option<&mut ConfigProcessor> {
        if !self.processors.contains_key(name) {
            let default = crate::processor::processor_registration_by_name_for_config(self, name)
                .map(|registration| registration.registration.default_config)
                .or_else(|| crate::processor::default_processor_config(name))?;
            self.processors.insert(name.to_string(), default);
        }
        self.processors.get_mut(name)
    }
}

impl ConfigProcessorValue {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value.as_str()),
            _ => None,
        }
    }

    pub fn as_table(&self) -> Option<&BTreeMap<String, ConfigProcessorValue>> {
        match self {
            Self::Table(value) => Some(value),
            _ => None,
        }
    }
}

impl ConfigProcessor {
    pub fn option_string(&self, key: &str) -> Option<&str> {
        self.options.get(key)?.as_string()
    }

    pub fn option_integer(&self, key: &str) -> Option<i64> {
        self.options.get(key)?.as_integer()
    }

    pub fn option_bool(&self, key: &str) -> Option<bool> {
        self.options.get(key)?.as_bool()
    }

    pub fn transport(
        &self,
        transport: crate::processor::ProcessorTransport,
    ) -> &ConfigProcessorTransport {
        match transport {
            crate::processor::ProcessorTransport::Ipc => &self.transport.ipc,
            crate::processor::ProcessorTransport::Http => &self.transport.http,
        }
    }

    pub fn transport_string(
        &self,
        transport: crate::processor::ProcessorTransport,
        key: &str,
    ) -> Option<&str> {
        self.transport(transport).options.get(key)?.as_string()
    }

    pub fn transport_bool(
        &self,
        transport: crate::processor::ProcessorTransport,
        key: &str,
    ) -> Option<bool> {
        self.transport(transport).options.get(key)?.as_bool()
    }
}

impl From<bool> for ConfigProcessorValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for ConfigProcessorValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<i32> for ConfigProcessorValue {
    fn from(value: i32) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<u64> for ConfigProcessorValue {
    fn from(value: u64) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<u32> for ConfigProcessorValue {
    fn from(value: u32) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<usize> for ConfigProcessorValue {
    fn from(value: usize) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<f64> for ConfigProcessorValue {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl From<&str> for ConfigProcessorValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

impl From<String> for ConfigProcessorValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<Vec<ConfigProcessorValue>> for ConfigProcessorValue {
    fn from(value: Vec<ConfigProcessorValue>) -> Self {
        Self::Array(value)
    }
}

impl From<BTreeMap<String, ConfigProcessorValue>> for ConfigProcessorValue {
    fn from(value: BTreeMap<String, ConfigProcessorValue>) -> Self {
        Self::Table(value)
    }
}
