"""Rust-backed AST bindings."""

from importlib import import_module

_ast = import_module("binlex_bindings.binlex.ir.ast")

_AstValueBinding = _ast.AstValue
_AstTypeBinding = _ast.AstType
_AstStructureMemberBinding = _ast.AstStructureMember
_AstUnionMemberBinding = _ast.AstUnionMember
_AstExpressionBinding = _ast.AstExpression
_AstPlaceBinding = _ast.AstPlace
_AstTargetBinding = _ast.AstTarget
_AstStatementBinding = _ast.AstStatement
_AstBlockBinding = _ast.AstBlock
_AstParameterBinding = _ast.AstParameter
_AstLocalBinding = _ast.AstLocal
_AstFunctionBinding = _ast.AstFunction
_AstModuleBinding = _ast.AstModule


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


def _unwrap(value):
    return getattr(value, "_inner", value)


def _to_dict(value):
    return value.to_dict() if hasattr(value, "to_dict") else value


class AstValue(_Wrapper):
    _binding = _AstValueBinding

    named = classmethod(lambda cls, name, ty: cls._from_inner(cls._binding.named(name, getattr(ty, "_inner", ty))))
    integer = classmethod(lambda cls, value, bits: cls._from_inner(cls._binding.integer(value, bits)))
    boolean = classmethod(lambda cls, value: cls._from_inner(cls._binding.boolean(value)))
    null = classmethod(lambda cls, ty: cls._from_inner(cls._binding.null(getattr(ty, "_inner", ty))))
    undef = classmethod(lambda cls, ty: cls._from_inner(cls._binding.undef(getattr(ty, "_inner", ty))))


class AstType(_Wrapper):
    _binding = _AstTypeBinding

    void = classmethod(lambda cls: cls._from_inner(cls._binding.void()))
    integer = classmethod(lambda cls, bits: cls._from_inner(cls._binding.integer(bits)))
    float = classmethod(lambda cls, bits: cls._from_inner(cls._binding.float(bits)))
    pointer = classmethod(lambda cls, pointee: cls._from_inner(cls._binding.pointer(getattr(pointee, "_inner", pointee))))

    @classmethod
    def function(cls, parameters=None, returns=None):
        parameters = [getattr(item, "_inner", item) for item in list(parameters or [])]
        returns = [getattr(item, "_inner", item) for item in list(returns or [])]
        return cls._from_inner(cls._binding.function(parameters, returns))

    memory = classmethod(lambda cls: cls._from_inner(cls._binding.memory()))
    type_definition = classmethod(lambda cls, name: cls._from_inner(cls._binding.type_definition(name)))

    @classmethod
    def structure(cls, name, members=None):
        members = [getattr(item, "_inner", item) for item in list(members or [])]
        return cls._from_inner(cls._binding.structure(name, members))

    @classmethod
    def union(cls, name, members=None):
        members = [getattr(item, "_inner", item) for item in list(members or [])]
        return cls._from_inner(cls._binding.union(name, members))


class AstStructureMember(_Wrapper):
    _binding = _AstStructureMemberBinding

    def __init__(self, name, ty):
        self._inner = self._binding(name, getattr(ty, "_inner", ty))

    def name(self):
        return self._inner.name()


class AstUnionMember(_Wrapper):
    _binding = _AstUnionMemberBinding

    def __init__(self, name, ty):
        self._inner = self._binding(name, getattr(ty, "_inner", ty))

    def name(self):
        return self._inner.name()


class AstVoid(AstType):
    def __init__(self):
        self._inner = _AstTypeBinding.void()


class AstInteger(AstType):
    def __init__(self, bits):
        self._inner = _AstTypeBinding.integer(bits)


class AstFloat(AstType):
    def __init__(self, bits):
        self._inner = _AstTypeBinding.float(bits)


class AstPointer(AstType):
    def __init__(self, pointee):
        self._inner = _AstTypeBinding.pointer(_unwrap(pointee))


class AstFunctionType(AstType):
    def __init__(self, parameters=None, returns=None):
        parameters = [_unwrap(item) for item in list(parameters or [])]
        returns = [_unwrap(item) for item in list(returns or [])]
        self._inner = _AstTypeBinding.function(parameters, returns)


class AstTypeDefinition(AstType):
    def __init__(self, name):
        self._inner = _AstTypeBinding.type_definition(name)


class AstStructure(AstType):
    def __init__(self, name, members=None):
        members = [_unwrap(item) for item in list(members or [])]
        self._inner = _AstTypeBinding.structure(name, members)


class AstUnion(AstType):
    def __init__(self, name, members=None):
        members = [_unwrap(item) for item in list(members or [])]
        self._inner = _AstTypeBinding.union(name, members)


class AstMemory(AstType):
    def __init__(self):
        self._inner = _AstTypeBinding.memory()


class AstNamedValue(AstValue):
    def __init__(self, name, ty):
        self._inner = _AstValueBinding.named(name, _unwrap(ty))


class AstIntegerValue(AstValue):
    def __init__(self, value, bits):
        self._inner = _AstValueBinding.integer(value, bits)


class AstBooleanValue(AstValue):
    def __init__(self, value):
        self._inner = _AstValueBinding.boolean(value)


class AstNullValue(AstValue):
    def __init__(self, ty):
        self._inner = _AstValueBinding.null(_unwrap(ty))


class AstUndefValue(AstValue):
    def __init__(self, ty):
        self._inner = _AstValueBinding.undef(_unwrap(ty))


class AstExpression(_Wrapper):
    _binding = _AstExpressionBinding

    @classmethod
    def value(cls, value):
        return cls._from_inner(cls._binding.value(getattr(value, "_inner", value)))

    @classmethod
    def call(cls, target, arguments=None, return_types=None):
        arguments = [getattr(item, "_inner", item) for item in list(arguments or [])]
        return_types = [getattr(item, "_inner", item) for item in list(return_types or [])]
        return cls._from_inner(cls._binding.call(getattr(target, "_inner", target), arguments, return_types))

    @classmethod
    def member(cls, base, name, ty):
        return cls._from_inner(
            cls._binding.member(
                getattr(base, "_inner", base),
                name,
                getattr(ty, "_inner", ty),
            )
        )


class AstPlace(_Wrapper):
    _binding = _AstPlaceBinding

    @classmethod
    def named(cls, name, ty):
        return cls._from_inner(cls._binding.named(name, getattr(ty, "_inner", ty)))


class AstValueExpression(AstExpression):
    def __init__(self, value):
        self._inner = _AstExpressionBinding.value(_unwrap(value))


class AstCallExpression(AstExpression):
    def __init__(self, target, arguments=None, return_types=None):
        arguments = [_unwrap(item) for item in list(arguments or [])]
        return_types = [_unwrap(item) for item in list(return_types or [])]
        self._inner = _AstExpressionBinding.call(_unwrap(target), arguments, return_types)


class AstMemberExpression(AstExpression):
    def __init__(self, base, name, ty):
        self._inner = _AstExpressionBinding.member(_unwrap(base), name, _unwrap(ty))


class AstUnaryExpression(AstExpression):
    def __init__(self, op, value, ty):
        self._inner = _AstExpressionBinding.from_dict({
            "Unary": {"op": op, "value": _to_dict(value), "ty": _to_dict(ty)}
        })


class AstBinaryExpression(AstExpression):
    def __init__(self, op, lhs, rhs, ty):
        self._inner = _AstExpressionBinding.from_dict({
            "Binary": {"op": op, "lhs": _to_dict(lhs), "rhs": _to_dict(rhs), "ty": _to_dict(ty)}
        })


class AstCastExpression(AstExpression):
    def __init__(self, op, value, ty):
        self._inner = _AstExpressionBinding.from_dict({
            "Cast": {"op": op, "value": _to_dict(value), "ty": _to_dict(ty)}
        })


class AstLoadExpression(AstExpression):
    def __init__(self, address_space, address, ty):
        self._inner = _AstExpressionBinding.from_dict({
            "Load": {"address_space": _to_dict(address_space), "address": _to_dict(address), "ty": _to_dict(ty)}
        })


class AstAddressOfExpression(AstExpression):
    def __init__(self, place, ty):
        self._inner = _AstExpressionBinding.from_dict({
            "AddressOf": {"place": _to_dict(place), "ty": _to_dict(ty)}
        })


class AstDereferenceExpression(AstExpression):
    def __init__(self, pointer, ty):
        self._inner = _AstExpressionBinding.from_dict({
            "Dereference": {"pointer": _to_dict(pointer), "ty": _to_dict(ty)}
        })


class AstIndexExpression(AstExpression):
    def __init__(self, base, index, ty):
        self._inner = _AstExpressionBinding.from_dict({
            "Index": {"base": _to_dict(base), "index": _to_dict(index), "ty": _to_dict(ty)}
        })


class AstCompareExpression(AstExpression):
    def __init__(self, op, lhs, rhs, ty):
        self._inner = _AstExpressionBinding.from_dict({
            "Compare": {"op": op, "lhs": _to_dict(lhs), "rhs": _to_dict(rhs), "ty": _to_dict(ty)}
        })


class AstSelectExpression(AstExpression):
    def __init__(self, condition, when_true, when_false, ty):
        self._inner = _AstExpressionBinding.from_dict({
            "Select": {
                "condition": _to_dict(condition),
                "when_true": _to_dict(when_true),
                "when_false": _to_dict(when_false),
                "ty": _to_dict(ty),
            }
        })


class AstNamedPlace(AstPlace):
    def __init__(self, name, ty):
        self._inner = _AstPlaceBinding.named(name, _unwrap(ty))


class AstDereferencePlace(AstPlace):
    def __init__(self, pointer, ty):
        self._inner = _AstPlaceBinding.from_dict({
            "Dereference": {"pointer": _to_dict(pointer), "ty": _to_dict(ty)}
        })


class AstIndexPlace(AstPlace):
    def __init__(self, base, index, ty):
        self._inner = _AstPlaceBinding.from_dict({
            "Index": {"base": _to_dict(base), "index": _to_dict(index), "ty": _to_dict(ty)}
        })


class AstTarget(_Wrapper):
    _binding = _AstTargetBinding

    direct = classmethod(lambda cls, name: cls._from_inner(cls._binding.direct(name)))

    @classmethod
    def indirect(cls, expression):
        return cls._from_inner(cls._binding.indirect(getattr(expression, "_inner", expression)))


class AstStatement(_Wrapper):
    _binding = _AstStatementBinding

    @classmethod
    def assign(cls, target, value):
        return cls._from_inner(cls._binding.assign(getattr(target, "_inner", target), getattr(value, "_inner", value)))

    @classmethod
    def expr(cls, value):
        return cls._from_inner(cls._binding.expr(getattr(value, "_inner", value)))

    comment = classmethod(lambda cls, comment: cls._from_inner(cls._binding.comment(comment)))

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


class AstBlock(_Wrapper):
    _binding = _AstBlockBinding

    def __init__(self, statements=None):
        self._inner = self._binding()
        for statement in list(statements or []):
            self.append_statement(statement)

    def statements(self):
        return [AstStatement._from_inner(item) for item in self._inner.statements()]

    def append_statement(self, statement):
        self._inner.append_statement(getattr(statement, "_inner", statement))

    def append_comment(self, comment):
        self._inner.append_comment(comment)


class AstAssignStatement(AstStatement):
    def __init__(self, target, value):
        self._inner = _AstStatementBinding.assign(_unwrap(target), _unwrap(value))


class AstReturnStatement(AstStatement):
    def __init__(self, values=None):
        values = [_unwrap(item) for item in list(values or [])]
        self._inner = _AstStatementBinding.return_(values)


class AstCommentStatement(AstStatement):
    def __init__(self, comment):
        self._inner = _AstStatementBinding.comment(comment)


class AstExpressionStatement(AstStatement):
    def __init__(self, value):
        self._inner = _AstStatementBinding.expr(_unwrap(value))


class AstLabelStatement(AstStatement):
    def __init__(self, name):
        self._inner = _AstStatementBinding.label(name)


class AstGotoStatement(AstStatement):
    def __init__(self, target):
        self._inner = _AstStatementBinding.goto(_unwrap(target))


class AstBreakStatement(AstStatement):
    def __init__(self):
        self._inner = _AstStatementBinding.break_()


class AstContinueStatement(AstStatement):
    def __init__(self):
        self._inner = _AstStatementBinding.continue_()


class AstParameter(_Wrapper):
    _binding = _AstParameterBinding

    def __init__(self, name, ty, comment=None):
        self._inner = self._binding(name, getattr(ty, "_inner", ty), comment)

    def name(self):
        return self._inner.name()

    def set_name(self, name):
        self._inner.set_name(name)

    def comment(self):
        return self._inner.comment()

    def set_comment(self, comment):
        self._inner.set_comment(comment)


class AstLocal(_Wrapper):
    _binding = _AstLocalBinding

    def __init__(self, name, ty, init=None, display_name=None, comment=None):
        self._inner = self._binding(
            name,
            getattr(ty, "_inner", ty),
            getattr(init, "_inner", init),
            display_name,
            comment,
        )

    def name(self):
        return self._inner.name()

    def set_name(self, name):
        self._inner.set_name(name)

    def display_name(self):
        return self._inner.display_name()

    def set_display_name(self, display_name):
        self._inner.set_display_name(display_name)

    def rename(self, display_name):
        self._inner.rename(display_name)

    def comment(self):
        return self._inner.comment()

    def set_comment(self, comment):
        self._inner.set_comment(comment)


class AstFunction:
    """Wrapper around a Rust AST function object."""

    def __init__(self, name=None):
        self._inner = _AstFunctionBinding(name=name)

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

    def comment(self):
        return self._inner.comment()

    def set_comment(self, comment):
        self._inner.set_comment(comment)

    def set_returns(self, returns):
        returns = [getattr(item, "_inner", item) for item in list(returns)]
        self._inner.set_returns(returns)

    def append_return(self, ty):
        self._inner.append_return(getattr(ty, "_inner", ty))

    def parameters(self):
        return [AstParameter._from_inner(item) for item in self._inner.parameters()]

    def locals(self):
        return [AstLocal._from_inner(item) for item in self._inner.locals()]

    def blocks(self):
        return [AstBlock._from_inner(item) for item in self._inner.blocks()]

    def append_parameter(self, parameter):
        self._inner.append_parameter(getattr(parameter, "_inner", parameter))

    def append_local(self, local):
        self._inner.append_local(getattr(local, "_inner", local))

    def append_block(self, block):
        self._inner.append_block(getattr(block, "_inner", block))

    def rename_local(self, name, display_name):
        return self._inner.rename_local(name, display_name)

    def set_local_comment(self, name, comment):
        return self._inner.set_local_comment(name, comment)

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

    def __init__(self, name=None):
        self._inner = _AstModuleBinding(name=name)

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

    def functions(self):
        return [AstFunction._from_inner(item) for item in self._inner.functions()]

    def append_function(self, function):
        self._inner.append_function(getattr(function, "_inner", function))

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


__all__ = [
    "AstVoid",
    "AstInteger",
    "AstFloat",
    "AstPointer",
    "AstFunctionType",
    "AstTypeDefinition",
    "AstStructure",
    "AstUnion",
    "AstMemory",
    "AstValue",
    "AstNamedValue",
    "AstIntegerValue",
    "AstBooleanValue",
    "AstNullValue",
    "AstUndefValue",
    "AstType",
    "AstStructureMember",
    "AstUnionMember",
    "AstExpression",
    "AstValueExpression",
    "AstCallExpression",
    "AstMemberExpression",
    "AstUnaryExpression",
    "AstBinaryExpression",
    "AstCastExpression",
    "AstLoadExpression",
    "AstAddressOfExpression",
    "AstDereferenceExpression",
    "AstIndexExpression",
    "AstCompareExpression",
    "AstSelectExpression",
    "AstPlace",
    "AstNamedPlace",
    "AstDereferencePlace",
    "AstIndexPlace",
    "AstTarget",
    "AstStatement",
    "AstAssignStatement",
    "AstReturnStatement",
    "AstCommentStatement",
    "AstExpressionStatement",
    "AstLabelStatement",
    "AstGotoStatement",
    "AstBreakStatement",
    "AstContinueStatement",
    "AstBlock",
    "AstParameter",
    "AstLocal",
    "AstFunction",
    "AstModule",
]
