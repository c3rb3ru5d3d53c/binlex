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

mod backend;
mod error;

use crate::{Architecture, Configuration};
pub use backend::AssemblerBackend;
use backend::ResolvedAssemblerBackend;
pub use error::AssemblerError;

pub struct Assembler {
    _config: Configuration,
    inner: ResolvedAssemblerBackend,
}

impl Assembler {
    pub fn new(
        architecture: Architecture,
        config: Configuration,
        backend: AssemblerBackend,
    ) -> Result<Self, AssemblerError> {
        Ok(Self {
            _config: config,
            inner: ResolvedAssemblerBackend::new(architecture, backend)?,
        })
    }

    pub fn assemble(&self, address: u64, text: &str) -> Result<Vec<u8>, AssemblerError> {
        self.inner.assemble(address, text)
    }
}

#[cfg(test)]
mod tests {
    use super::{Assembler, AssemblerBackend};
    use crate::{Architecture, Configuration};

    #[test]
    fn default_backend_assembles_amd64() {
        let assembler = Assembler::new(
            Architecture::AMD64,
            Configuration::default(),
            AssemblerBackend::Default,
        )
        .expect("assembler");
        let bytes = assembler
            .assemble(0, "xor eax, eax; ret")
            .expect("assemble");
        assert_eq!(bytes, vec![0x31, 0xc0, 0xc3]);
    }
}
