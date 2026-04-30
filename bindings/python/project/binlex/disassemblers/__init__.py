# MIT License
#
# Copyright (c) [2025] [c3rb3ru5d3d53c]
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""Disassembler implementations exposed by the Python bindings."""

from enum import Enum

from binlex.core import Architecture
from binlex.core.architecture import _coerce_architecture

from .capstone import Disassembler as _CapstoneDisassembler
from .cil import Disassembler as _CilDisassembler


class DisassemblerBackend(str, Enum):
    Default = "default"
    Capstone = "capstone"
    Native = "native"


class Disassembler:
    def __init__(
        self,
        architecture,
        image,
        executable_address_ranges,
        config,
        backend=DisassemblerBackend.Default,
    ):
        binding_architecture = _coerce_architecture(architecture)
        self.architecture = Architecture.from_binding(binding_architecture)
        self.backend = (
            backend
            if isinstance(backend, DisassemblerBackend)
            else DisassemblerBackend(backend)
        )

        resolved_backend = self.backend
        if resolved_backend == DisassemblerBackend.Default:
            resolved_backend = (
                DisassemblerBackend.Native
                if self.architecture == Architecture.CIL
                else DisassemblerBackend.Capstone
            )

        if self.architecture == Architecture.CIL:
            if resolved_backend != DisassemblerBackend.Native:
                raise ValueError("CIL only supports the Native backend")
            self._inner = _CilDisassembler(
                binding_architecture,
                image,
                executable_address_ranges,
                config,
            )
        else:
            if resolved_backend != DisassemblerBackend.Capstone:
                raise ValueError(
                    f"{self.architecture} only supports the Capstone backend"
                )
            self._inner = _CapstoneDisassembler(
                binding_architecture,
                image,
                executable_address_ranges,
                config,
            )

    def disassemble_instruction(self, address, cfg, metadata_token_addresses=None):
        if self.architecture == Architecture.CIL:
            return self._inner.disassemble_instruction(
                address,
                cfg,
                metadata_token_addresses,
            )
        return self._inner.disassemble_instruction(address, cfg)

    def disassemble_function(self, address, cfg, metadata_token_addresses=None):
        if self.architecture == Architecture.CIL:
            return self._inner.disassemble_function(
                address,
                cfg,
                metadata_token_addresses,
            )
        return self._inner.disassemble_function(address, cfg)

    def disassemble_block(self, address, cfg, metadata_token_addresses=None):
        if self.architecture == Architecture.CIL:
            return self._inner.disassemble_block(
                address,
                cfg,
                metadata_token_addresses,
            )
        return self._inner.disassemble_block(address, cfg)

    def disassemble(self, addresses, cfg, metadata_token_addresses=None):
        if self.architecture == Architecture.CIL:
            return self._inner.disassemble(
                addresses,
                cfg,
                metadata_token_addresses,
            )
        return self._inner.disassemble(addresses, cfg)

    def disassemble_sweep(self):
        return self._inner.disassemble_sweep()

    def __getattr__(self, name):
        return getattr(self._inner, name)


__all__ = ["Disassembler", "DisassemblerBackend"]
