"""Rust-backed HIR bindings."""

from importlib import import_module

_hir = import_module("binlex_bindings.binlex.ir.hir")

_HirBlockBinding = _hir.HirBlock
_HirExpressionBinding = _hir.HirExpression
_HirPlaceBinding = _hir.HirPlace
_HirTargetBinding = _hir.HirTarget
_HirStatementBinding = _hir.HirStatement
_HirParameterBinding = _hir.HirParameter
_HirLocalBinding = _hir.HirLocal
_HirValueBinding = _hir.HirValue
_HirFunctionBinding = _hir.HirFunction
_HirModuleBinding = _hir.HirModule
_HirMlirModuleBinding = _hir.HirMlirModule


def _unwrap(value):
    return getattr(value, "_inner", value)


class _Wrapper:
    _binding = None

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(cls._binding.from_dict(data))

    def json(self):
        return self._inner.json()

    def to_dict(self):
        return self._inner.to_dict()

    def __str__(self):
        return str(self._inner)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class HirValue(_Wrapper):
    _binding = _HirValueBinding

    named = classmethod(lambda cls, name, ty: cls._from_inner(cls._binding.named(name, getattr(ty, "_inner", ty))))
    integer = classmethod(lambda cls, value, bits: cls._from_inner(cls._binding.integer(value, bits)))
    boolean = classmethod(lambda cls, value: cls._from_inner(cls._binding.boolean(value)))
    null = classmethod(lambda cls, ty: cls._from_inner(cls._binding.null(getattr(ty, "_inner", ty))))
    undef = classmethod(lambda cls, ty: cls._from_inner(cls._binding.undef(getattr(ty, "_inner", ty))))


class HirNamedValue(HirValue):
    def __init__(self, name, ty):
        self._inner = _HirValueBinding.named(name, _unwrap(ty))


class HirIntegerValue(HirValue):
    def __init__(self, value, bits):
        self._inner = _HirValueBinding.integer(value, bits)


class HirBooleanValue(HirValue):
    def __init__(self, value):
        self._inner = _HirValueBinding.boolean(value)


class HirNullValue(HirValue):
    def __init__(self, ty):
        self._inner = _HirValueBinding.null(_unwrap(ty))


class HirUndefValue(HirValue):
    def __init__(self, ty):
        self._inner = _HirValueBinding.undef(_unwrap(ty))


class HirExpression(_Wrapper):
    _binding = _HirExpressionBinding

    @classmethod
    def value(cls, value):
        return cls._from_inner(cls._binding.value(getattr(value, "_inner", value)))

    @classmethod
    def call(cls, target, arguments=None, return_types=None):
        arguments = [getattr(item, "_inner", item) for item in list(arguments or [])]
        return_types = [getattr(item, "_inner", item) for item in list(return_types or [])]
        return cls._from_inner(cls._binding.call(getattr(target, "_inner", target), arguments, return_types))

    @classmethod
    def intrinsic(cls, name, arguments=None, return_types=None):
        arguments = [getattr(item, "_inner", item) for item in list(arguments or [])]
        return_types = [getattr(item, "_inner", item) for item in list(return_types or [])]
        return cls._from_inner(cls._binding.intrinsic(name, arguments, return_types))


class HirValueExpression(HirExpression):
    def __init__(self, value):
        self._inner = _HirExpressionBinding.value(_unwrap(value))


class HirCallExpression(HirExpression):
    def __init__(self, target, arguments=None, return_types=None):
        self._inner = _HirExpressionBinding.call(
            _unwrap(target),
            [_unwrap(item) for item in list(arguments or [])],
            [_unwrap(item) for item in list(return_types or [])],
        )


class HirIntrinsicExpression(HirExpression):
    def __init__(self, name, arguments=None, return_types=None):
        self._inner = _HirExpressionBinding.intrinsic(
            name,
            [_unwrap(item) for item in list(arguments or [])],
            [_unwrap(item) for item in list(return_types or [])],
        )


class HirPlace(_Wrapper):
    _binding = _HirPlaceBinding

    @classmethod
    def named(cls, name, ty):
        return cls._from_inner(cls._binding.named(name, getattr(ty, "_inner", ty)))


class HirNamedPlace(HirPlace):
    def __init__(self, name, ty):
        self._inner = _HirPlaceBinding.named(name, _unwrap(ty))


class HirTarget(_Wrapper):
    _binding = _HirTargetBinding

    direct = classmethod(lambda cls, name: cls._from_inner(cls._binding.direct(name)))

    @classmethod
    def indirect(cls, expression):
        return cls._from_inner(cls._binding.indirect(getattr(expression, "_inner", expression)))


class HirDirectTarget(HirTarget):
    def __init__(self, name):
        self._inner = _HirTargetBinding.direct(name)


class HirIndirectTarget(HirTarget):
    def __init__(self, expression):
        self._inner = _HirTargetBinding.indirect(_unwrap(expression))


class HirStatement(_Wrapper):
    _binding = _HirStatementBinding

    @classmethod
    def assign(cls, target, value):
        return cls._from_inner(cls._binding.assign(getattr(target, "_inner", target), getattr(value, "_inner", value)))

    @classmethod
    def expr(cls, value):
        return cls._from_inner(cls._binding.expr(getattr(value, "_inner", value)))

    @classmethod
    def return_(cls, values=None):
        values = [getattr(item, "_inner", item) for item in list(values or [])]
        return cls._from_inner(cls._binding.return_(values))

    label = classmethod(lambda cls, name: cls._from_inner(cls._binding.label(name)))
    goto = classmethod(lambda cls, target: cls._from_inner(cls._binding.goto(getattr(target, "_inner", target))))
    break_ = classmethod(lambda cls: cls._from_inner(cls._binding.break_()))
    continue_ = classmethod(lambda cls: cls._from_inner(cls._binding.continue_()))
    trap = classmethod(lambda cls: cls._from_inner(cls._binding.trap()))
    unreachable = classmethod(lambda cls: cls._from_inner(cls._binding.unreachable()))


class HirAssignStatement(HirStatement):
    def __init__(self, target, value):
        self._inner = _HirStatementBinding.assign(_unwrap(target), _unwrap(value))


class HirExpressionStatement(HirStatement):
    def __init__(self, value):
        self._inner = _HirStatementBinding.expr(_unwrap(value))


class HirReturnStatement(HirStatement):
    def __init__(self, values=None):
        self._inner = _HirStatementBinding.return_([_unwrap(item) for item in list(values or [])])


class HirLabelStatement(HirStatement):
    def __init__(self, name):
        self._inner = _HirStatementBinding.label(name)


class HirGotoStatement(HirStatement):
    def __init__(self, target):
        self._inner = _HirStatementBinding.goto(_unwrap(target))


class HirBreakStatement(HirStatement):
    def __init__(self):
        self._inner = _HirStatementBinding.break_()


class HirContinueStatement(HirStatement):
    def __init__(self):
        self._inner = _HirStatementBinding.continue_()


class HirTrapStatement(HirStatement):
    def __init__(self):
        self._inner = _HirStatementBinding.trap()


class HirUnreachableStatement(HirStatement):
    def __init__(self):
        self._inner = _HirStatementBinding.unreachable()


class HirParameter(_Wrapper):
    _binding = _HirParameterBinding

    def __init__(self, name, ty):
        self._inner = self._binding(name, _unwrap(ty))


class HirLocal(_Wrapper):
    _binding = _HirLocalBinding

    def __init__(self, name, ty, init=None):
        self._inner = self._binding(name, _unwrap(ty), _unwrap(init))


class HirBlock(_Wrapper):
    _binding = _HirBlockBinding

    def __init__(self, statements=None):
        self._inner = self._binding()
        for statement in list(statements or []):
            self.append_statement(statement)

    def statements(self):
        return [HirStatement._from_inner(item) for item in self._inner.statements()]

    def append_statement(self, statement):
        self._inner.append_statement(getattr(statement, "_inner", statement))


class HirFunction:
    """Wrapper around a Rust HIR function object."""

    def __init__(self, name=None):
        self._inner = _HirFunctionBinding(name=name)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_HirFunctionBinding.from_dict(data))

    @classmethod
    def from_mir(cls, mir_function, name=None):
        mir_function = getattr(mir_function, "_inner", mir_function)
        return cls._from_inner(_HirFunctionBinding.from_mir(mir_function, name=name))

    @classmethod
    def from_lir(cls, lir_function, name=None):
        lir_function = getattr(lir_function, "_inner", lir_function)
        return cls._from_inner(_HirFunctionBinding.from_lir(lir_function, name=name))

    def append_block(self, block):
        block = getattr(block, "_inner", block)
        self._inner.append_block(block)

    def append_parameter(self, parameter):
        parameter = getattr(parameter, "_inner", parameter)
        self._inner.append_parameter(parameter)

    def append_local(self, local):
        local = getattr(local, "_inner", local)
        self._inner.append_local(local)

    def blocks(self):
        return [HirBlock._from_inner(item) for item in self._inner.blocks()]

    def verify(self):
        return self._inner.verify()

    def optimize_inline_temps(self):
        self._inner.optimize_inline_temps()

    def optimize_algebraic(self):
        self._inner.optimize_algebraic()

    def optimize_condition_idioms(self):
        self._inner.optimize_condition_idioms()

    def optimize_boolean(self):
        self._inner.optimize_boolean()

    def optimize_load_hoisting(self):
        self._inner.optimize_load_hoisting()

    def optimize_call_arguments(self):
        self._inner.optimize_call_arguments()

    def optimize_memory_forms(self):
        self._inner.optimize_memory_forms()

    def optimize_pointer_reads(self):
        self._inner.optimize_pointer_reads()

    def optimize_cfg(self):
        self._inner.optimize_cfg()

    def optimize_locals(self):
        self._inner.optimize_locals()

    def optimize(self):
        self._inner.optimize()

    def ast(self):
        from binlex.ir.ast import AstFunction

        return AstFunction._from_inner(self._inner.ast())

    def c(self):
        return self._inner.c()

    def print_c(self):
        self._inner.print_c()

    def text(self):
        return self._inner.text()

    def mlir(self):
        return HirMlirModule._from_inner(self._inner.mlir())

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


class HirModule:
    """Wrapper around a Rust HIR module object."""

    def __init__(self, name=None):
        self._inner = _HirModuleBinding(name=name)
        self._mlir = False

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        instance._mlir = False
        return instance

    @classmethod
    def _from_mlir_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        instance._mlir = True
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_HirModuleBinding.from_dict(data))

    @classmethod
    def from_mir(cls, mir_module, name=None):
        mir_module = getattr(mir_module, "_inner", mir_module)
        return cls._from_inner(_HirModuleBinding.from_mir(mir_module, name=name))

    @classmethod
    def from_lir(cls, lir_module, name=None):
        lir_module = getattr(lir_module, "_inner", lir_module)
        return cls._from_inner(_HirModuleBinding.from_lir(lir_module, name=name))

    @classmethod
    def from_text(cls, text):
        return cls._from_mlir_inner(_HirModuleBinding.from_text(text))

    @classmethod
    def from_bytecode(cls, bytecode):
        return cls._from_mlir_inner(_HirModuleBinding.from_bytecode(bytecode))

    def append_function(self, function):
        function = getattr(function, "_inner", function)
        self._inner.append_function(function)

    def functions(self):
        return [HirFunction._from_inner(item) for item in self._inner.functions()]

    def verify(self):
        return self._inner.verify()

    def optimize_inline_temps(self):
        self._inner.optimize_inline_temps()

    def optimize_algebraic(self):
        self._inner.optimize_algebraic()

    def optimize_condition_idioms(self):
        self._inner.optimize_condition_idioms()

    def optimize_boolean(self):
        self._inner.optimize_boolean()

    def optimize_load_hoisting(self):
        self._inner.optimize_load_hoisting()

    def optimize_call_arguments(self):
        self._inner.optimize_call_arguments()

    def optimize_memory_forms(self):
        self._inner.optimize_memory_forms()

    def optimize_pointer_reads(self):
        self._inner.optimize_pointer_reads()

    def optimize_cfg(self):
        self._inner.optimize_cfg()

    def optimize_locals(self):
        self._inner.optimize_locals()

    def optimize(self):
        if self._mlir:
            self._inner.optimize()
            return
        self._inner.optimize()

    def ast(self):
        from binlex.ir.ast import AstModule

        return AstModule._from_inner(self._inner.ast())

    def c(self):
        return self._inner.c()

    def print_c(self):
        self._inner.print_c()

    def text(self):
        if self._mlir:
            return self._inner.text()
        return self._inner.text()

    def bytecode(self):
        return self._inner.bytecode()

    def mlir(self):
        if self._mlir:
            return HirMlirModule._from_inner(self._inner)
        return HirMlirModule._from_inner(self._inner.mlir())

    def operation_names(self):
        return self.mlir().operation_names()

    def operation_count(self):
        return self.mlir().operation_count()

    def operation_records(self):
        return self.mlir().operation_records()

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


class HirMlirModule:
    """Wrapper around an MLIR-backed Rust HIR module object."""

    def __init__(self, module):
        module = getattr(module, "_inner", module)
        self._inner = module.mlir()

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_text(cls, text):
        return cls._from_inner(_HirMlirModuleBinding.from_text(text))

    @classmethod
    def from_bytecode(cls, bytecode):
        return cls._from_inner(_HirMlirModuleBinding.from_bytecode(bytecode))

    def optimize_assignments(self):
        self._inner.optimize_assignments()

    def optimize(self):
        self._inner.optimize()

    def text(self):
        return self._inner.text()

    def bytecode(self):
        return self._inner.bytecode()

    def operation_names(self):
        return self._inner.operation_names()

    def operation_count(self):
        return self._inner.operation_count()

    def operation_records(self):
        return self._inner.operation_records()

    def print(self):
        self._inner.print()

    def __getattr__(self, name):
        return getattr(self._inner, name)


__all__ = [
    "HirFunction",
    "HirModule",
    "HirMlirModule",
    "HirBlock",
    "HirParameter",
    "HirLocal",
    "HirExpression",
    "HirPlace",
    "HirTarget",
    "HirStatement",
    "HirValue",
]
