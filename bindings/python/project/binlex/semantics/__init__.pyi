from __future__ import annotations

from typing import Any


class SemanticStatus:
    Partial: SemanticStatus
    Complete: SemanticStatus
    def __str__(self) -> str: ...


class SemanticLocationKind:
    Register: SemanticLocationKind
    Flag: SemanticLocationKind
    ProgramCounter: SemanticLocationKind
    Temporary: SemanticLocationKind
    Memory: SemanticLocationKind
    def __str__(self) -> str: ...


class SemanticEffectKind:
    Set: SemanticEffectKind
    Store: SemanticEffectKind
    Fence: SemanticEffectKind
    Trap: SemanticEffectKind
    Intrinsic: SemanticEffectKind
    Nop: SemanticEffectKind
    def __str__(self) -> str: ...


class SemanticExpressionKind:
    Const: SemanticExpressionKind
    Read: SemanticExpressionKind
    Load: SemanticExpressionKind
    Unary: SemanticExpressionKind
    Binary: SemanticExpressionKind
    Cast: SemanticExpressionKind
    Compare: SemanticExpressionKind
    Select: SemanticExpressionKind
    Extract: SemanticExpressionKind
    Concat: SemanticExpressionKind
    Undefined: SemanticExpressionKind
    Poison: SemanticExpressionKind
    Intrinsic: SemanticExpressionKind
    def __str__(self) -> str: ...


class SemanticTerminatorKind:
    FallThrough: SemanticTerminatorKind
    Jump: SemanticTerminatorKind
    Branch: SemanticTerminatorKind
    Call: SemanticTerminatorKind
    Return: SemanticTerminatorKind
    Unreachable: SemanticTerminatorKind
    Trap: SemanticTerminatorKind
    def __str__(self) -> str: ...


class SemanticOperationUnary:
    Not: SemanticOperationUnary
    Neg: SemanticOperationUnary
    BitReverse: SemanticOperationUnary
    ByteSwap: SemanticOperationUnary
    CountLeadingZeros: SemanticOperationUnary
    CountTrailingZeros: SemanticOperationUnary
    PopCount: SemanticOperationUnary
    Sqrt: SemanticOperationUnary
    Abs: SemanticOperationUnary
    def __str__(self) -> str: ...


class SemanticOperationBinary:
    Add: SemanticOperationBinary
    AddWithCarry: SemanticOperationBinary
    Sub: SemanticOperationBinary
    SubWithBorrow: SemanticOperationBinary
    Mul: SemanticOperationBinary
    UMulHigh: SemanticOperationBinary
    SMulHigh: SemanticOperationBinary
    UDiv: SemanticOperationBinary
    SDiv: SemanticOperationBinary
    URem: SemanticOperationBinary
    SRem: SemanticOperationBinary
    And: SemanticOperationBinary
    Or: SemanticOperationBinary
    Xor: SemanticOperationBinary
    Shl: SemanticOperationBinary
    LShr: SemanticOperationBinary
    AShr: SemanticOperationBinary
    RotateLeft: SemanticOperationBinary
    RotateRight: SemanticOperationBinary
    MinUnsigned: SemanticOperationBinary
    MinSigned: SemanticOperationBinary
    MaxUnsigned: SemanticOperationBinary
    MaxSigned: SemanticOperationBinary
    def __str__(self) -> str: ...


class SemanticOperationCast:
    ZeroExtend: SemanticOperationCast
    SignExtend: SemanticOperationCast
    Truncate: SemanticOperationCast
    Bitcast: SemanticOperationCast
    IntToFloat: SemanticOperationCast
    FloatToInt: SemanticOperationCast
    FloatExtend: SemanticOperationCast
    FloatTruncate: SemanticOperationCast
    def __str__(self) -> str: ...


class SemanticOperationCompare:
    Eq: SemanticOperationCompare
    Ne: SemanticOperationCompare
    Ult: SemanticOperationCompare
    Ule: SemanticOperationCompare
    Ugt: SemanticOperationCompare
    Uge: SemanticOperationCompare
    Slt: SemanticOperationCompare
    Sle: SemanticOperationCompare
    Sgt: SemanticOperationCompare
    Sge: SemanticOperationCompare
    Ordered: SemanticOperationCompare
    Unordered: SemanticOperationCompare
    Oeq: SemanticOperationCompare
    One: SemanticOperationCompare
    Olt: SemanticOperationCompare
    Ole: SemanticOperationCompare
    Ogt: SemanticOperationCompare
    Oge: SemanticOperationCompare
    Ueq: SemanticOperationCompare
    Une: SemanticOperationCompare
    UltFp: SemanticOperationCompare
    UleFp: SemanticOperationCompare
    UgtFp: SemanticOperationCompare
    UgeFp: SemanticOperationCompare
    def __str__(self) -> str: ...


class SemanticAddressSpace:
    Default: SemanticAddressSpace
    Stack: SemanticAddressSpace
    Heap: SemanticAddressSpace
    Global: SemanticAddressSpace
    Io: SemanticAddressSpace
    @staticmethod
    def segment(name: str) -> SemanticAddressSpace: ...
    @staticmethod
    def arch_specific(name: str) -> SemanticAddressSpace: ...
    def __str__(self) -> str: ...


class SemanticFenceKind:
    Acquire: SemanticFenceKind
    Release: SemanticFenceKind
    AcquireRelease: SemanticFenceKind
    SequentiallyConsistent: SemanticFenceKind
    @staticmethod
    def arch_specific(name: str) -> SemanticFenceKind: ...
    def __str__(self) -> str: ...


class SemanticTrapKind:
    Breakpoint: SemanticTrapKind
    DivideError: SemanticTrapKind
    Overflow: SemanticTrapKind
    InvalidOpcode: SemanticTrapKind
    GeneralProtection: SemanticTrapKind
    PageFault: SemanticTrapKind
    AlignmentFault: SemanticTrapKind
    Syscall: SemanticTrapKind
    Interrupt: SemanticTrapKind
    @staticmethod
    def arch_specific(name: str) -> SemanticTrapKind: ...
    def __str__(self) -> str: ...


class SemanticDiagnosticKind:
    UnsupportedInstruction: SemanticDiagnosticKind
    UnsupportedOperandForm: SemanticDiagnosticKind
    UnsupportedRegisterClass: SemanticDiagnosticKind
    UnsupportedVectorForm: SemanticDiagnosticKind
    UnsupportedFloatingPointForm: SemanticDiagnosticKind
    UnsupportedAtomicForm: SemanticDiagnosticKind
    PartialFlags: SemanticDiagnosticKind
    PartialMemoryModel: SemanticDiagnosticKind
    PartialExceptionModel: SemanticDiagnosticKind
    @staticmethod
    def arch_specific(name: str) -> SemanticDiagnosticKind: ...
    def __str__(self) -> str: ...


class SemanticTemporary:
    def __init__(self, id: int, bits: int, name: str | None = None) -> None: ...
    @classmethod
    def from_dict(cls, data: Any) -> SemanticTemporary: ...
    def id(self) -> int: ...
    def bits(self) -> int: ...
    def name(self) -> str | None: ...
    def to_dict(self) -> Any: ...
    def json(self) -> str: ...
    def print(self) -> None: ...


class SemanticDiagnostic:
    def __init__(self, kind: SemanticDiagnosticKind, message: str) -> None: ...
    @classmethod
    def from_dict(cls, data: Any) -> SemanticDiagnostic: ...
    def kind(self) -> SemanticDiagnosticKind: ...
    def message(self) -> str: ...
    def to_dict(self) -> Any: ...
    def json(self) -> str: ...
    def print(self) -> None: ...


class SemanticLocation:
    @classmethod
    def from_dict(cls, data: Any) -> SemanticLocation: ...
    @classmethod
    def register(cls, name: str, bits: int) -> SemanticLocation: ...
    @classmethod
    def flag(cls, name: str, bits: int) -> SemanticLocation: ...
    @classmethod
    def program_counter(cls, bits: int) -> SemanticLocation: ...
    @classmethod
    def temporary(cls, id: int, bits: int) -> SemanticLocation: ...
    @classmethod
    def memory(
        cls,
        address_space: SemanticAddressSpace,
        bits: int,
        base: SemanticExpression | None = None,
        index: SemanticExpression | None = None,
        scale: int | None = None,
        displacement: int | None = None,
    ) -> SemanticLocation: ...
    def kind(self) -> SemanticLocationKind: ...
    def bits(self) -> int: ...
    def name(self) -> str | None: ...
    def to_dict(self) -> Any: ...
    def json(self) -> str: ...
    def print(self) -> None: ...


class SemanticExpression:
    @classmethod
    def from_dict(cls, data: Any) -> SemanticExpression: ...
    @classmethod
    def const_value(cls, value: int, bits: int) -> SemanticExpression: ...
    @classmethod
    def read(cls, location: SemanticLocation) -> SemanticExpression: ...
    @classmethod
    def load(
        cls, address_space: SemanticAddressSpace, bits: int, address: SemanticExpression
    ) -> SemanticExpression: ...
    @classmethod
    def unary(
        cls, operation: SemanticOperationUnary, operand: SemanticExpression, bits: int
    ) -> SemanticExpression: ...
    @classmethod
    def binary(
        cls,
        operation: SemanticOperationBinary,
        lhs: SemanticExpression,
        rhs: SemanticExpression,
        bits: int,
    ) -> SemanticExpression: ...
    @classmethod
    def cast(
        cls, operation: SemanticOperationCast, operand: SemanticExpression, bits: int
    ) -> SemanticExpression: ...
    @classmethod
    def compare(
        cls,
        operation: SemanticOperationCompare,
        lhs: SemanticExpression,
        rhs: SemanticExpression,
    ) -> SemanticExpression: ...
    @classmethod
    def select(
        cls,
        condition: SemanticExpression,
        when_true: SemanticExpression,
        when_false: SemanticExpression,
        bits: int,
    ) -> SemanticExpression: ...
    @classmethod
    def extract(
        cls, operand: SemanticExpression, offset: int, bits: int
    ) -> SemanticExpression: ...
    @classmethod
    def concat(cls, parts: list[SemanticExpression], bits: int) -> SemanticExpression: ...
    @classmethod
    def undefined(cls, bits: int) -> SemanticExpression: ...
    @classmethod
    def poison(cls, bits: int) -> SemanticExpression: ...
    @classmethod
    def intrinsic(
        cls, name: str, operands: list[SemanticExpression], bits: int
    ) -> SemanticExpression: ...
    def kind(self) -> SemanticExpressionKind: ...
    def operation(
        self,
    ) -> (
        SemanticOperationBinary
        | SemanticOperationUnary
        | SemanticOperationCast
        | SemanticOperationCompare
        | None
    ): ...
    def bits(self) -> int: ...
    def left(self) -> SemanticExpression | None: ...
    def right(self) -> SemanticExpression | None: ...
    def argument(self) -> SemanticExpression | None: ...
    def condition(self) -> SemanticExpression | None: ...
    def when_true(self) -> SemanticExpression | None: ...
    def when_false(self) -> SemanticExpression | None: ...
    def address(self) -> SemanticExpression | None: ...
    def address_space(self) -> SemanticAddressSpace | None: ...
    def location(self) -> SemanticLocation | None: ...
    def offset(self) -> int | None: ...
    def parts(self) -> list[SemanticExpression] | None: ...
    def name(self) -> str | None: ...
    def arguments(self) -> list[SemanticExpression] | None: ...
    def value(self) -> int | None: ...
    def to_dict(self) -> Any: ...
    def json(self) -> str: ...
    def print(self) -> None: ...


class SemanticEffect:
    @classmethod
    def from_dict(cls, data: Any) -> SemanticEffect: ...
    @classmethod
    def set(
        cls, location: SemanticLocation, expression: SemanticExpression
    ) -> SemanticEffect: ...
    @classmethod
    def store(
        cls,
        address_space: SemanticAddressSpace,
        address: SemanticExpression,
        value: SemanticExpression,
    ) -> SemanticEffect: ...
    @classmethod
    def fence(cls, kind: SemanticFenceKind) -> SemanticEffect: ...
    @classmethod
    def trap(cls, kind: SemanticTrapKind) -> SemanticEffect: ...
    @classmethod
    def intrinsic(cls, name: str, operands: list[SemanticExpression]) -> SemanticEffect: ...
    @classmethod
    def nop(cls) -> SemanticEffect: ...
    def kind(self) -> SemanticEffectKind: ...
    def expression(self) -> SemanticExpression | None: ...
    def location(self) -> SemanticLocation | None: ...
    def to_dict(self) -> Any: ...
    def json(self) -> str: ...
    def print(self) -> None: ...


class SemanticTerminator:
    @classmethod
    def from_dict(cls, data: Any) -> SemanticTerminator: ...
    @classmethod
    def fallthrough(cls) -> SemanticTerminator: ...
    @classmethod
    def jump(cls, target: SemanticExpression) -> SemanticTerminator: ...
    @classmethod
    def branch(
        cls,
        condition: SemanticExpression,
        true_target: SemanticExpression,
        false_target: SemanticExpression,
    ) -> SemanticTerminator: ...
    @classmethod
    def call(
        cls,
        target: SemanticExpression,
        return_target: SemanticExpression | None = None,
        does_return: bool | None = None,
    ) -> SemanticTerminator: ...
    @classmethod
    def return_(cls, expression: SemanticExpression | None = None) -> SemanticTerminator: ...
    @classmethod
    def unreachable(cls) -> SemanticTerminator: ...
    @classmethod
    def trap(cls) -> SemanticTerminator: ...
    def kind(self) -> SemanticTerminatorKind: ...
    def to_dict(self) -> Any: ...
    def json(self) -> str: ...
    def print(self) -> None: ...


class InstructionSemantics:
    def __init__(
        self,
        version: int,
        status: SemanticStatus,
        temporaries: list[SemanticTemporary] | None = None,
        effects: list[SemanticEffect] | None = None,
        terminator: SemanticTerminator | None = None,
        diagnostics: list[SemanticDiagnostic] | None = None,
    ) -> None: ...
    @classmethod
    def from_dict(cls, data: Any) -> InstructionSemantics: ...
    def version(self) -> int: ...
    def status(self) -> SemanticStatus: ...
    def temporaries(self) -> list[SemanticTemporary]: ...
    def effects(self) -> list[SemanticEffect]: ...
    def terminator(self) -> SemanticTerminator: ...
    def diagnostics(self) -> list[SemanticDiagnostic]: ...
    def to_dict(self) -> Any: ...
    def json(self) -> str: ...
    def print(self) -> None: ...
    def __str__(self) -> str: ...


__all__: list[str]
