"""LLVM IR wrappers backed by the Rust core implementation."""

import ctypes

from binlex_bindings.binlex.irs.llvm import JittedFunction as _JittedFunctionBinding
from binlex_bindings.binlex.irs.llvm import LiftedFunction as _LiftedFunctionBinding
from binlex_bindings.binlex.irs.llvm import LlvmModule as _LlvmModuleBinding

from binlex.irs.lir import LirBlock, LirFunction, LirModule


def _call_or_value(value, name):
    attr = getattr(value, name, None)
    if attr is None:
        return None
    return attr() if callable(attr) else attr


def _module_for_block(block, name=None):
    function_name = name or _call_or_value(block, "name") or "function_0"
    function = LirFunction(name=function_name)
    function.append_block(block)
    module = LirModule(name=name)
    module.append_function(function)
    return module


def _module_for_function(function, name=None):
    if name is not None:
        replacement = LirFunction(name=name, abi=function.abi())
        for block in function.blocks():
            replacement.append_block(block)
        function = replacement
    module = LirModule(name=name or _call_or_value(function, "name"))
    module.append_function(function)
    return module


class LlvmModule:
    def __init__(self, name, cpu, triple=None, _inner=None, _config=None):
        self._name = name
        self._cpu = cpu
        self._config = _config
        if _inner is None:
            cpu = getattr(cpu, "_inner", cpu)
            self._inner = _LlvmModuleBinding(name, cpu, triple)
        else:
            self._inner = _inner

    @classmethod
    def _with_config(cls, name, cpu, config, triple=None):
        result = cls.__new__(cls)
        result._name = name
        result._cpu = cpu
        result._config = config
        result._inner = _LlvmModuleBinding.with_config(
            name,
            getattr(cpu, "_inner", cpu),
            config,
            triple,
        )
        return result

    @classmethod
    def _with_inner(cls, name, cpu, config, inner):
        result = cls.__new__(cls)
        result._name = name
        result._cpu = cpu
        result._config = config
        result._inner = inner
        return result

    def from_lir(self, lir_module, config):
        lir_module = getattr(lir_module, "_inner", lir_module)
        module = LirModule._from_inner(lir_module)
        if not module.functions():
            raise ValueError("cannot lower empty LIR module to LLVM")
        if self._inner.from_lir(module._inner, config):
            self._name = module.name()
            self._config = config
            return self
        return None

    def set_abi(self, abi=None):
        if self._inner.set_abi(abi):
            return self
        return None

    def append_block_lir(self, semantics, abi=None):
        semantics = getattr(semantics, "_inner", semantics)
        if not self._inner.append_block_lir(semantics, abi):
            return None
        return self

    def append_function_lir(self, semantics, abi=None, name=None):
        semantics = getattr(semantics, "_inner", semantics)
        if not self._inner.append_function_lir(semantics, abi, name):
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

    def text(self):
        return self._inner.text()

    def set_text(self, text):
        if self._inner.set_text(text):
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
        return self.text()


class LlvmFunction:
    def __init__(self, module, inner):
        self._module = module
        self._inner = inner

    @classmethod
    def from_lir(cls, lir_function, cpu, config, triple=None):
        lir_function = getattr(lir_function, "_inner", lir_function)
        function = LirFunction._from_inner(lir_function)
        lir_module = _module_for_function(function)
        module = LlvmModule(lir_module.name(), cpu, triple=triple)
        module.from_lir(lir_module, config)
        return module.functions()[0]

    def name(self):
        return self._inner.name()

    def set_name(self, name):
        if self._inner.set_name(name):
            return self
        return None

    def blocks(self):
        return [LlvmBlock(self, inner) for inner in self._inner.blocks()]

    def append_block(self, block, name=None):
        if self._inner.append_block(block._inner, name):
            return self
        return None

    def append_block_lir(self, semantics, name=None):
        semantics = getattr(semantics, "_inner", semantics)
        if self._inner.append_block_lir(semantics, name):
            return self
        return None

    def set_lir(self, semantics):
        semantics = getattr(semantics, "_inner", semantics)
        if self._inner.set_lir(semantics):
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

    def text(self):
        return self._inner.text()

    def set_text(self, text):
        if self._inner.set_text(text):
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
    def from_lir(cls, lir_block, cpu, config, triple=None):
        lir_block = getattr(lir_block, "_inner", lir_block)
        block = LirBlock._from_inner(lir_block)
        lir_module = _module_for_block(block)
        module = LlvmModule(lir_module.name(), cpu, triple=triple)
        module.from_lir(lir_module, config)
        return module.functions()[0].blocks()[0]

    def name(self):
        return self._inner.name()

    def text(self):
        return self._inner.text()

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
