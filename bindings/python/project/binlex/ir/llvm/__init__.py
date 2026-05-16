"""LLVM IR wrappers backed by the Rust core implementation."""

import ctypes

from binlex_bindings.binlex.ir.llvm import JittedFunction as _JittedFunctionBinding
from binlex_bindings.binlex.ir.llvm import Lifter as _LifterBinding
from binlex_bindings.binlex.ir.llvm import LiftedFunction as _LiftedFunctionBinding

from binlex.ir.lir import LirBlock, LirCpu, LirFunction, LirModule
from binlex.ir.lir import _cpu_kind_from_architecture


def _call_or_value(value, name):
    attr = getattr(value, name, None)
    if attr is None:
        return None
    return attr() if callable(attr) else attr


def _infer_cpu_from_lir_function(function):
    abi = function.abi()
    if abi is not None:
        cpu = _call_or_value(abi, "cpu")
        if cpu is not None:
            return LirCpu._from_inner(getattr(cpu, "_inner", cpu))
    for block in function.blocks():
        for instruction in block.instructions():
            abi = instruction.abi()
            if abi is not None:
                cpu = _call_or_value(abi, "cpu")
                if cpu is not None:
                    return LirCpu._from_inner(getattr(cpu, "_inner", cpu))
            encoding = _call_or_value(instruction, "encoding")
            if encoding is not None:
                architecture = _call_or_value(encoding, "architecture")
                if architecture is not None:
                    return LirCpu.from_kind(_cpu_kind_from_architecture(architecture))
    raise ValueError("unable to infer LIR CPU for LLVM lowering")


def _module_for_block(block, name=None):
    function_name = name or _call_or_value(block, "name") or "function_0"
    function = LirFunction(name=function_name, blocks=[block])
    return LirModule(name=name, functions=[function])


def _module_for_function(function, name=None):
    if name is not None:
        function = LirFunction(name=name, abi=function.abi(), blocks=function.blocks())
    return LirModule(name=name or _call_or_value(function, "name"), functions=[function])


class LlvmModule:
    def __init__(self, cpu, config, triple=None, _inner=None):
        self._cpu = cpu
        self._config = config
        if _inner is None:
            cpu = getattr(cpu, "_inner", cpu)
            self._inner = _LifterBinding(cpu, config, triple)
        else:
            self._inner = _inner

    @classmethod
    def from_lir(cls, lir_module, name=None, triple=None, config=None):
        lir_module = getattr(lir_module, "_inner", lir_module)
        module = LirModule._from_inner(lir_module)
        if not module.functions():
            raise ValueError("cannot lower empty LIR module to LLVM")
        cpu = _infer_cpu_from_lir_function(module.functions()[0])
        if config is None:
            from binlex.config import Configuration

            config = Configuration()
        llvm = cls(cpu, config, triple=triple)
        for function in module.functions():
            function_name = (
                name if len(module.functions()) == 1 and name is not None else _call_or_value(function, "name")
            )
            function_module = _module_for_function(function, name=function_name)
            abi = function.abi()
            if llvm.lift_function_semantics(function_module, abi=abi, name=function_name) is None:
                raise RuntimeError("LLVM lowering from LIR failed")
        return llvm

    def lift_instruction(self, instruction):
        if self._inner.lift_instruction(instruction._inner):
            return self
        return None

    def lift_block(self, block, abi=None):
        if self._inner.lift_block(block._inner, abi):
            return self
        return None

    def lift_function(self, function, abi=None):
        if self._inner.lift_function(function._inner, abi):
            return self
        return None

    def lift_block_semantics(self, semantics, abi=None):
        semantics = getattr(semantics, "_inner", semantics)
        if not self._inner.lift_block_semantics(semantics, abi):
            return None
        return self

    def lift_function_semantics(self, semantics, abi=None, name=None):
        semantics = getattr(semantics, "_inner", semantics)
        if not self._inner.lift_function_semantics(semantics, abi, name):
            return None
        return self

    def create_function(self, name, abi=None):
        inner = self._inner.create_function(name, abi)
        return LlvmFunction(self, inner)

    def functions(self):
        return [LlvmFunction(self, inner) for inner in self._inner.functions()]

    def clear(self):
        if self._inner.clear():
            return self
        return None

    def optimize(self):
        for step in (
            self.optimize_mem2reg,
            self.optimize_sroa,
            self.optimize_instcombine,
            self.optimize_cfg,
            self.optimize_gvn,
            self.optimize_dce,
        ):
            step()
        return self

    def ir(self):
        return self._inner.ir()

    def text(self):
        return self.ir()

    def set_ir(self, ir):
        if self._inner.set_ir(ir):
            return self
        return None

    def set_bitcode(self, bitcode):
        if self._inner.set_bitcode(bitcode):
            return self
        return None

    def print(self):
        return self._inner.print()

    def bitcode(self):
        return bytes(self._inner.bitcode())

    def object(self):
        return bytes(self._inner.object())

    def optimize_mem2reg(self):
        if self._inner.optimize_mem2reg():
            return self
        return None

    def optimize_instcombine(self):
        if self._inner.optimize_instcombine():
            return self
        return None

    def optimize_cfg(self):
        if self._inner.optimize_cfg():
            return self
        return None

    def optimize_gvn(self):
        if self._inner.optimize_gvn():
            return self
        return None

    def optimize_sroa(self):
        if self._inner.optimize_sroa():
            return self
        return None

    def optimize_dce(self):
        if self._inner.optimize_dce():
            return self
        return None

    def verify(self):
        return self._inner.verify()

    def __str__(self):
        return self.ir()


class LlvmFunction:
    def __init__(self, module, inner):
        self._module = module
        self._inner = inner

    @classmethod
    def from_lir(cls, lir_function, name=None, triple=None, config=None):
        lir_function = getattr(lir_function, "_inner", lir_function)
        function = LirFunction._from_inner(lir_function)
        module = LlvmModule.from_lir(
            _module_for_function(function, name=name),
            triple=triple,
            config=config,
        )
        return module.functions()[0]

    def name(self):
        return self._inner.name()

    def set_name(self, name):
        if self._inner.set_name(name):
            return self
        return None

    def blocks(self):
        return [LlvmBlock(self, inner) for inner in self._inner.blocks()]

    def lift_block(self, block, name=None):
        if self._inner.lift_block(block._inner, name):
            return self
        return None

    def lift_block_semantics(self, semantics, name=None):
        semantics = getattr(semantics, "_inner", semantics)
        if self._inner.lift_block_semantics(semantics, name):
            return self
        return None

    def lift_function_semantics(self, semantics):
        semantics = getattr(semantics, "_inner", semantics)
        if self._inner.lift_function_semantics(semantics):
            return self
        return None

    def optimize_mem2reg(self):
        if self._inner.optimize_mem2reg():
            return self
        return None

    def optimize_instcombine(self):
        if self._inner.optimize_instcombine():
            return self
        return None

    def optimize_cfg(self):
        if self._inner.optimize_cfg():
            return self
        return None

    def optimize_gvn(self):
        if self._inner.optimize_gvn():
            return self
        return None

    def optimize_sroa(self):
        if self._inner.optimize_sroa():
            return self
        return None

    def optimize_dce(self):
        if self._inner.optimize_dce():
            return self
        return None

    def ir(self):
        return self._inner.ir()

    def text(self):
        return self.ir()

    def set_ir(self, ir):
        if self._inner.set_ir(ir):
            return self
        return None

    def set_bitcode(self, bitcode):
        if self._inner.set_bitcode(bitcode):
            return self
        return None

    def print(self):
        return self._inner.print()

    def bitcode(self):
        data = self._inner.bitcode()
        return None if data is None else bytes(data)

    def object(self):
        data = self._inner.object()
        return None if data is None else bytes(data)

    def jit(self, return_type=None, parameter_types=None, links=None):
        resolved_links = _resolve_jit_links(links or {})
        handle = self._inner.jit(resolved_links)
        if handle is None:
            return None
        return NativeFunction(
            handle,
            return_type=return_type,
            parameter_types=parameter_types,
        )


class LlvmBlock:
    def __init__(self, function, inner):
        self._function = function
        self._inner = inner

    @classmethod
    def from_lir(cls, lir_block, name=None, triple=None, config=None):
        lir_block = getattr(lir_block, "_inner", lir_block)
        block = LirBlock._from_inner(lir_block)
        module = LlvmModule.from_lir(_module_for_block(block, name=name), triple=triple, config=config)
        return module.functions()[0].blocks()[0]

    def name(self):
        return self._inner.name()

    def ir(self):
        return self._inner.ir()

    def text(self):
        return self.ir()

    def print(self):
        return self._inner.print()


class NativeFunction:
    def __init__(self, handle, return_type=None, parameter_types=None):
        if not isinstance(handle, _JittedFunctionBinding):
            raise TypeError("handle must be a binlex llvm jitted function")
        self._handle = handle
        self._return_type = ctypes.c_int if return_type is None else return_type
        self._parameter_types = list(parameter_types or [])
        self._functype = ctypes.CFUNCTYPE(self._return_type, *self._parameter_types)
        self._callable = self._functype(handle.address())

    def name(self):
        return self._handle.name()

    def address(self):
        return self._handle.address()

    def __call__(self, *args):
        return self._callable(*args)


def _resolve_jit_links(links):
    resolved = {}
    for name, value in links.items():
        resolved[str(name)] = _resolve_jit_link_target(str(name), value)
    return resolved


def _resolve_jit_link_target(name, value):
    if isinstance(value, NativeFunction):
        return int(value.address())
    if isinstance(value, _JittedFunctionBinding):
        return int(value.address())
    if isinstance(value, int):
        return int(value)

    target = value
    if _looks_like_ctypes_library(value):
        try:
            target = getattr(value, name)
        except AttributeError as exc:
            raise ValueError(f"jit link target {name!r} not found on module {value!r}") from exc

    try:
        pointer = ctypes.cast(target, ctypes.c_void_p).value
    except Exception as exc:
        raise TypeError(
            f"unsupported jit link target for {name!r}: expected ctypes module, ctypes function, raw address, or jitted function"
        ) from exc
    if pointer is None:
        raise ValueError(f"jit link target for {name!r} does not have an address")
    return int(pointer)


def _looks_like_ctypes_library(value):
    return hasattr(value, "_handle") and not hasattr(value, "address")


__all__ = ["LlvmBlock", "LlvmFunction", "LlvmModule", "NativeFunction"]
