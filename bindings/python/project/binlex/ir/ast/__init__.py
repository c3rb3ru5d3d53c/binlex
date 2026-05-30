"""Rust-backed AST bindings."""

from importlib import import_module

_ast = import_module("binlex_bindings.binlex.ir.ast")

_AstFunctionBinding = _ast.AstFunction
_AstModuleBinding = _ast.AstModule


class AstFunction:
    """Wrapper around a Rust AST function object."""

    def __init__(self):
        self._inner = _AstFunctionBinding()

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_AstFunctionBinding.from_dict(data))

    @classmethod
    def from_hir(cls, hir_function):
        hir_function = getattr(hir_function, "_inner", hir_function)
        return cls._from_inner(_AstFunctionBinding.from_hir(hir_function))

    def optimize(self):
        self._inner.optimize()

    def c(self, image=None):
        if image is not None:
            image = getattr(image, "_inner", image)
            return self._inner.c_with_image(image)
        return self._inner.c()

    def print_c(self):
        self._inner.print_c()

    def text(self):
        return self._inner.text()

    def print(self):
        self._inner.print()

    def json(self):
        return self._inner.json()

    def to_dict(self):
        return self._inner.to_dict()

    def __str__(self):
        return self.text()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class AstModule:
    """Wrapper around a Rust AST module object."""

    def __init__(self):
        self._inner = _AstModuleBinding()

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_AstModuleBinding.from_dict(data))

    @classmethod
    def from_hir(cls, hir_module):
        hir_module = getattr(hir_module, "_inner", hir_module)
        return cls._from_inner(_AstModuleBinding.from_hir(hir_module))

    def optimize(self):
        self._inner.optimize()

    def c(self):
        return self._inner.c()

    def print_c(self):
        self._inner.print_c()

    def text(self):
        return self._inner.text()

    def print(self):
        self._inner.print()

    def json(self):
        return self._inner.json()

    def to_dict(self):
        return self._inner.to_dict()

    def __str__(self):
        return self.text()

    def __getattr__(self, name):
        return getattr(self._inner, name)


__all__ = ["AstFunction", "AstModule"]
