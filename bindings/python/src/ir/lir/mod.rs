pub mod abis;

use crate::ir::lir::abis::{extract_abi, register_abi_classes, LirAbi as PyLirAbi};
use binlex::ir::lir::{
    LirAddressSpace as InnerAddressSpace, LirBlock as InnerLirBlock, LirCpu as InnerLirCpu,
    LirCpuAlias as InnerLirCpuAlias, LirCpuAliasWritePolicy as InnerLirCpuAliasWritePolicy,
    LirCpuEndian as InnerLirCpuEndian, LirCpuKind as InnerLirCpuKind,
    LirCpuProgramCounter as InnerLirCpuProgramCounter, LirCpuRegister as InnerLirCpuRegister,
    LirData as InnerLirData, LirDiagnostic as InnerLirDiagnostic,
    LirDiagnosticKind as InnerLirDiagnosticKind, LirEffect as InnerLirEffect,
    LirEffectKind as InnerLirEffectKind, LirEncoding as InnerLirEncoding,
    LirExpression as InnerLirExpr, LirExpressionKind as InnerLirExprKind,
    LirFenceKind as InnerFenceKind, LirFunction as InnerLirFunction, LirInstruction as InnerLir,
    LirLocation as InnerLirLocation, LirLocationKind as InnerLirLocationKind,
    LirMemory as InnerLirMemory, LirMemoryAddressed as InnerLirMemoryAddressed,
    LirMemoryIndexed as InnerLirMemoryIndexed, LirMemoryStack as InnerLirMemoryStack,
    LirModule as InnerLirModule, LirOperation as InnerLirOperation,
    LirOperationBinary as InnerLirBinaryOp, LirOperationCast as InnerLirCastOp,
    LirOperationCompare as InnerLirCompareOp, LirOperationUnary as InnerLirUnaryOp,
    LirStatus as InnerLirStatus, LirTemporary as InnerLirTemporary,
    LirTerminator as InnerLirTerminator, LirTerminatorKind as InnerLirTerminatorKind,
    LirTrapKind as InnerTrapKind,
};
use pyo3::class::basic::CompareOp;
use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyModule, PyType};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

fn json_value_to_py(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
    let json_str =
        serde_json::to_string(value).map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    let json_module = py.import("json")?;
    Ok(json_module.call_method1("loads", (json_str,))?.into())
}

fn py_to_json_value(py: Python<'_>, value: Py<PyAny>) -> PyResult<serde_json::Value> {
    let json_module = py.import("json")?;
    let json_str = json_module
        .call_method1("dumps", (value,))?
        .extract::<String>()?;
    serde_json::from_str(&json_str).map_err(|error| PyValueError::new_err(error.to_string()))
}

fn hash_value<T: Hash>(value: &T) -> isize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() as isize
}

macro_rules! simple_enum_binding {
    ($name:ident, $inner:ty, { $($variant:ident),+ $(,)? }) => {
        #[pyclass(skip_from_py_object)]
        #[derive(Clone)]
        pub struct $name {
            pub inner: $inner,
        }

        impl $name {
            pub fn from_inner(inner: $inner) -> Self {
                Self { inner }
            }
        }

        #[pymethods]
        impl $name {
            $(
                #[allow(non_upper_case_globals)]
                #[classattr]
                pub const $variant: Self = Self { inner: <$inner>::$variant };
            )+

            pub fn __str__(&self) -> String {
                format!("{:?}", self.inner)
            }

            pub fn __hash__(&self) -> isize {
                hash_value(&self.inner)
            }

            pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
                match op {
                    CompareOp::Eq => self.inner == other.inner,
                    CompareOp::Ne => self.inner != other.inner,
                    CompareOp::Lt => self.inner < other.inner,
                    CompareOp::Le => self.inner <= other.inner,
                    CompareOp::Gt => self.inner > other.inner,
                    CompareOp::Ge => self.inner >= other.inner,
                }
            }
        }
    };
}

simple_enum_binding!(LirStatus, InnerLirStatus, { Partial, Complete });
simple_enum_binding!(
    LirLocationKind,
    InnerLirLocationKind,
    { Register, Flag, ProgramCounter, Temporary, Memory }
);
simple_enum_binding!(
    LirEffectKind,
    InnerLirEffectKind,
    {
        Set,
        Store,
        MemorySet,
        MemoryCopy,
        AtomicCmpXchg,
        WriteProperty,
        WriteElement,
        Push,
        Pop,
        Fence,
        Trap,
        Intrinsic,
        Nop
    }
);
simple_enum_binding!(
    LirExpressionKind,
    InnerLirExprKind,
    {
        Const,
        Function,
        DataAddress,
        AddressOf,
        Read,
        Load,
        Unary,
        Binary,
        Cast,
        Compare,
        Select,
        Extract,
        Concat,
        Undefined,
        Poison,
        Intrinsic,
        Null,
        Allocate,
        ReadProperty,
        ReadElement
    }
);
simple_enum_binding!(
    LirTerminatorKind,
    InnerLirTerminatorKind,
    { FallThrough, Jump, Branch, Call, Return, Unreachable, Trap }
);
simple_enum_binding!(
    LirOperationUnary,
    InnerLirUnaryOp,
    {
        Not,
        Neg,
        BitReverse,
        ByteSwap,
        CountLeadingZeros,
        CountTrailingZeros,
        PopCount,
        Sqrt,
        Abs
    }
);
simple_enum_binding!(
    LirOperationBinary,
    InnerLirBinaryOp,
    {
        Add,
        AddWithCarry,
        Sub,
        SubWithBorrow,
        Mul,
        UMulHigh,
        SMulHigh,
        UDiv,
        SDiv,
        URem,
        SRem,
        And,
        Or,
        Xor,
        Shl,
        LShr,
        AShr,
        RotateLeft,
        RotateRight,
        MinUnsigned,
        MinSigned,
        MaxUnsigned,
        MaxSigned
    }
);
simple_enum_binding!(
    LirOperationCast,
    InnerLirCastOp,
    {
        ZeroExtend,
        SignExtend,
        Truncate,
        Bitcast,
        IntToFloat,
        FloatToInt,
        FloatExtend,
        FloatTruncate
    }
);
simple_enum_binding!(
    LirOperationCompare,
    InnerLirCompareOp,
    {
        Eq,
        Ne,
        Ult,
        Ule,
        Ugt,
        Uge,
        Slt,
        Sle,
        Sgt,
        Sge,
        Ordered,
        Unordered,
        Oeq,
        One,
        Olt,
        Ole,
        Ogt,
        Oge,
        Ueq,
        Une,
        UltFp,
        UleFp,
        UgtFp,
        UgeFp
    }
);

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct LirAddressSpace {
    pub inner: InnerAddressSpace,
}

impl LirAddressSpace {
    pub fn from_inner(inner: InnerAddressSpace) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl LirAddressSpace {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Default: Self = Self {
        inner: InnerAddressSpace::Default,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const State: Self = Self {
        inner: InnerAddressSpace::State,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Stack: Self = Self {
        inner: InnerAddressSpace::Stack,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Heap: Self = Self {
        inner: InnerAddressSpace::Heap,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Global: Self = Self {
        inner: InnerAddressSpace::Global,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Io: Self = Self {
        inner: InnerAddressSpace::Io,
    };

    #[staticmethod]
    pub fn cpu_memory(name: String) -> Self {
        Self {
            inner: InnerAddressSpace::CpuMemory { name },
        }
    }

    #[staticmethod]
    pub fn segment(name: String) -> Self {
        Self {
            inner: InnerAddressSpace::Segment { name },
        }
    }

    #[staticmethod]
    pub fn named(name: String) -> Self {
        Self {
            inner: InnerAddressSpace::Named { name },
        }
    }

    pub fn __str__(&self) -> String {
        match &self.inner {
            InnerAddressSpace::Default => "Default".to_string(),
            InnerAddressSpace::State => "State".to_string(),
            InnerAddressSpace::Stack => "Stack".to_string(),
            InnerAddressSpace::Heap => "Heap".to_string(),
            InnerAddressSpace::Global => "Global".to_string(),
            InnerAddressSpace::Io => "Io".to_string(),
            InnerAddressSpace::CpuMemory { name } => format!("CpuMemory({})", name),
            InnerAddressSpace::Segment { name } => format!("Segment({})", name),
            InnerAddressSpace::Named { name } => format!("Named({})", name),
        }
    }

    pub fn __hash__(&self) -> isize {
        hash_value(&self.inner)
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct LirFenceKind {
    pub inner: InnerFenceKind,
}

impl LirFenceKind {
    pub fn from_inner(inner: InnerFenceKind) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl LirFenceKind {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Acquire: Self = Self {
        inner: InnerFenceKind::Acquire,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Release: Self = Self {
        inner: InnerFenceKind::Release,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const AcquireRelease: Self = Self {
        inner: InnerFenceKind::AcquireRelease,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const SequentiallyConsistent: Self = Self {
        inner: InnerFenceKind::SequentiallyConsistent,
    };

    #[staticmethod]
    pub fn named(name: String) -> Self {
        Self {
            inner: InnerFenceKind::Named { name },
        }
    }

    pub fn __str__(&self) -> String {
        match &self.inner {
            InnerFenceKind::Acquire => "Acquire".to_string(),
            InnerFenceKind::Release => "Release".to_string(),
            InnerFenceKind::AcquireRelease => "AcquireRelease".to_string(),
            InnerFenceKind::SequentiallyConsistent => "SequentiallyConsistent".to_string(),
            InnerFenceKind::Named { name } => format!("Named({})", name),
        }
    }

    pub fn __hash__(&self) -> isize {
        hash_value(&self.inner)
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct LirTrapKind {
    pub inner: InnerTrapKind,
}

impl LirTrapKind {
    pub fn from_inner(inner: InnerTrapKind) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl LirTrapKind {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Breakpoint: Self = Self {
        inner: InnerTrapKind::Breakpoint,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const DivideError: Self = Self {
        inner: InnerTrapKind::DivideError,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Overflow: Self = Self {
        inner: InnerTrapKind::Overflow,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const InvalidOpcode: Self = Self {
        inner: InnerTrapKind::InvalidOpcode,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const GeneralProtection: Self = Self {
        inner: InnerTrapKind::GeneralProtection,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const PageFault: Self = Self {
        inner: InnerTrapKind::PageFault,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const AlignmentFault: Self = Self {
        inner: InnerTrapKind::AlignmentFault,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Syscall: Self = Self {
        inner: InnerTrapKind::Syscall,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Interrupt: Self = Self {
        inner: InnerTrapKind::Interrupt,
    };

    #[staticmethod]
    pub fn named(name: String) -> Self {
        Self {
            inner: InnerTrapKind::Named { name },
        }
    }

    pub fn __str__(&self) -> String {
        match &self.inner {
            InnerTrapKind::Breakpoint => "Breakpoint".to_string(),
            InnerTrapKind::DivideError => "DivideError".to_string(),
            InnerTrapKind::Overflow => "Overflow".to_string(),
            InnerTrapKind::InvalidOpcode => "InvalidOpcode".to_string(),
            InnerTrapKind::GeneralProtection => "GeneralProtection".to_string(),
            InnerTrapKind::PageFault => "PageFault".to_string(),
            InnerTrapKind::AlignmentFault => "AlignmentFault".to_string(),
            InnerTrapKind::Syscall => "Syscall".to_string(),
            InnerTrapKind::Interrupt => "Interrupt".to_string(),
            InnerTrapKind::Named { name } => format!("Named({})", name),
        }
    }

    pub fn __hash__(&self) -> isize {
        hash_value(&self.inner)
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct LirDiagnosticKind {
    pub inner: InnerLirDiagnosticKind,
}

impl LirDiagnosticKind {
    pub fn from_inner(inner: InnerLirDiagnosticKind) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl LirDiagnosticKind {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const UnsupportedInstruction: Self = Self {
        inner: InnerLirDiagnosticKind::UnsupportedInstruction,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const UnsupportedOperandForm: Self = Self {
        inner: InnerLirDiagnosticKind::UnsupportedOperandForm,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const UnsupportedRegisterClass: Self = Self {
        inner: InnerLirDiagnosticKind::UnsupportedRegisterClass,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const UnsupportedVectorForm: Self = Self {
        inner: InnerLirDiagnosticKind::UnsupportedVectorForm,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const UnsupportedFloatingPointForm: Self = Self {
        inner: InnerLirDiagnosticKind::UnsupportedFloatingPointForm,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const UnsupportedAtomicForm: Self = Self {
        inner: InnerLirDiagnosticKind::UnsupportedAtomicForm,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const PartialFlags: Self = Self {
        inner: InnerLirDiagnosticKind::PartialFlags,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const PartialMemoryModel: Self = Self {
        inner: InnerLirDiagnosticKind::PartialMemoryModel,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const PartialExceptionModel: Self = Self {
        inner: InnerLirDiagnosticKind::PartialExceptionModel,
    };

    #[staticmethod]
    pub fn named(name: String) -> Self {
        Self {
            inner: InnerLirDiagnosticKind::Named { name },
        }
    }

    pub fn __str__(&self) -> String {
        match &self.inner {
            InnerLirDiagnosticKind::UnsupportedInstruction => "UnsupportedInstruction".to_string(),
            InnerLirDiagnosticKind::UnsupportedOperandForm => "UnsupportedOperandForm".to_string(),
            InnerLirDiagnosticKind::UnsupportedRegisterClass => {
                "UnsupportedRegisterClass".to_string()
            }
            InnerLirDiagnosticKind::UnsupportedVectorForm => "UnsupportedVectorForm".to_string(),
            InnerLirDiagnosticKind::UnsupportedFloatingPointForm => {
                "UnsupportedFloatingPointForm".to_string()
            }
            InnerLirDiagnosticKind::UnsupportedAtomicForm => "UnsupportedAtomicForm".to_string(),
            InnerLirDiagnosticKind::PartialFlags => "PartialFlags".to_string(),
            InnerLirDiagnosticKind::PartialMemoryModel => "PartialMemoryModel".to_string(),
            InnerLirDiagnosticKind::PartialExceptionModel => "PartialExceptionModel".to_string(),
            InnerLirDiagnosticKind::Named { name } => format!("Named({})", name),
        }
    }

    pub fn __hash__(&self) -> isize {
        hash_value(&self.inner)
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct LirCpu {
    pub inner: InnerLirCpu,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct LirCpuRegister {
    pub inner: InnerLirCpuRegister,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct LirCpuAlias {
    pub inner: InnerLirCpuAlias,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct LirCpuProgramCounter {
    pub inner: InnerLirCpuProgramCounter,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct LirMemoryIndexed {
    pub inner: InnerLirMemoryIndexed,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct LirMemoryStack {
    pub inner: InnerLirMemoryStack,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct LirMemoryAddressed {
    pub inner: InnerLirMemoryAddressed,
}

#[pyclass(eq, eq_int, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LirCpuEndian {
    Little,
    Big,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone, Copy)]
pub struct LirCpuKind {
    pub inner: InnerLirCpuKind,
}

#[pymethods]
impl LirCpuKind {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const I386: Self = Self {
        inner: InnerLirCpuKind::I386,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Amd64: Self = Self {
        inner: InnerLirCpuKind::Amd64,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Arm64: Self = Self {
        inner: InnerLirCpuKind::Arm64,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Cil: Self = Self {
        inner: InnerLirCpuKind::Cil,
    };

    pub fn __str__(&self) -> String {
        match self.inner {
            InnerLirCpuKind::I386 => "I386".to_string(),
            InnerLirCpuKind::Amd64 => "Amd64".to_string(),
            InnerLirCpuKind::Arm64 => "Arm64".to_string(),
            InnerLirCpuKind::Cil => "Cil".to_string(),
        }
    }
}

impl From<LirCpuEndian> for InnerLirCpuEndian {
    fn from(value: LirCpuEndian) -> Self {
        match value {
            LirCpuEndian::Little => Self::Little,
            LirCpuEndian::Big => Self::Big,
        }
    }
}

#[pymethods]
impl LirCpuRegister {
    #[new]
    #[pyo3(text_signature = "(name, bits)")]
    pub fn new(name: String, bits: u16) -> Self {
        Self {
            inner: InnerLirCpuRegister::new(name, bits),
        }
    }

    pub fn name(&self) -> String {
        self.inner.name.clone()
    }

    pub fn bits(&self) -> u16 {
        self.inner.bits
    }
}

#[pymethods]
impl LirCpuAlias {
    #[new]
    #[pyo3(signature = (name, parent, offset, bits, write_policy=None), text_signature = "(name, parent, offset, bits, write_policy=None)")]
    pub fn new(
        name: String,
        parent: String,
        offset: u16,
        bits: u16,
        write_policy: Option<String>,
    ) -> PyResult<Self> {
        let inner = match write_policy.as_deref().unwrap_or("preserve") {
            "preserve" => InnerLirCpuAlias::new(name, parent, offset, bits),
            "zero_extend" => InnerLirCpuAlias::zero_extend(name, parent, offset, bits),
            value => {
                return Err(PyValueError::new_err(format!(
                    "invalid semantic CPU alias write policy: {value}"
                )));
            }
        };
        Ok(Self { inner })
    }

    pub fn name(&self) -> String {
        self.inner.name.clone()
    }

    pub fn parent(&self) -> String {
        self.inner.parent.clone()
    }

    pub fn offset(&self) -> u16 {
        self.inner.offset
    }

    pub fn bits(&self) -> u16 {
        self.inner.bits
    }

    pub fn write_policy(&self) -> String {
        match self.inner.write_policy {
            InnerLirCpuAliasWritePolicy::Preserve => "preserve",
            InnerLirCpuAliasWritePolicy::ZeroExtend => "zero_extend",
        }
        .to_string()
    }
}

#[pymethods]
impl LirCpuProgramCounter {
    #[new]
    #[pyo3(text_signature = "(name, bits)")]
    pub fn new(name: String, bits: u16) -> Self {
        Self {
            inner: InnerLirCpuProgramCounter::new(name, bits),
        }
    }

    pub fn name(&self) -> String {
        self.inner.name.clone()
    }

    pub fn bits(&self) -> u16 {
        self.inner.bits
    }
}

#[pymethods]
impl LirMemoryIndexed {
    #[new]
    #[pyo3(text_signature = "(name)")]
    pub fn new(name: String) -> Self {
        Self {
            inner: InnerLirMemoryIndexed::new(name),
        }
    }

    pub fn name(&self) -> String {
        self.inner.name.clone()
    }
}

#[pymethods]
impl LirMemoryStack {
    #[new]
    #[pyo3(text_signature = "(name)")]
    pub fn new(name: String) -> Self {
        Self {
            inner: InnerLirMemoryStack::new(name),
        }
    }

    pub fn name(&self) -> String {
        self.inner.name.clone()
    }
}

#[pymethods]
impl LirMemoryAddressed {
    #[new]
    #[pyo3(text_signature = "(name, address_bits, endian)")]
    pub fn new(name: String, address_bits: u16, endian: LirCpuEndian) -> Self {
        Self {
            inner: InnerLirMemoryAddressed::new(name, address_bits, endian.into()),
        }
    }

    pub fn name(&self) -> String {
        self.inner.name.clone()
    }

    pub fn address_bits(&self) -> u16 {
        self.inner.address_bits
    }

    pub fn endian(&self) -> LirCpuEndian {
        match self.inner.endian {
            InnerLirCpuEndian::Little => LirCpuEndian::Little,
            InnerLirCpuEndian::Big => LirCpuEndian::Big,
        }
    }
}

#[pymethods]
impl LirCpu {
    #[new]
    #[pyo3(signature = (*, name, address_bits, endian, registers=None, aliases=None, program_counter=None, memory=None))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        py: Python<'_>,
        name: String,
        address_bits: u16,
        endian: LirCpuEndian,
        registers: Option<Vec<Py<LirCpuRegister>>>,
        aliases: Option<Vec<Py<LirCpuAlias>>>,
        program_counter: Option<Py<LirCpuProgramCounter>>,
        memory: Option<Vec<Py<PyAny>>>,
    ) -> PyResult<Self> {
        let endian = endian.into();
        let registers = registers
            .unwrap_or_default()
            .into_iter()
            .map(|register| register.borrow(py).inner.clone())
            .collect::<Vec<_>>();
        let aliases = aliases
            .unwrap_or_default()
            .into_iter()
            .map(|alias| alias.borrow(py).inner.clone())
            .collect::<Vec<_>>();
        let program_counter = program_counter.map(|value| value.borrow(py).inner.clone());
        let memory = memory
            .unwrap_or_default()
            .into_iter()
            .map(|item| {
                let bound = item.bind(py);
                if let Ok(memory) = bound.extract::<PyRef<'_, LirMemoryIndexed>>() {
                    return Ok(InnerLirMemory::Indexed(memory.inner.clone()));
                }
                if let Ok(memory) = bound.extract::<PyRef<'_, LirMemoryStack>>() {
                    return Ok(InnerLirMemory::Stack(memory.inner.clone()));
                }
                if let Ok(memory) = bound.extract::<PyRef<'_, LirMemoryAddressed>>() {
                    return Ok(InnerLirMemory::Addressed(memory.inner.clone()));
                }
                Err(PyTypeError::new_err(
                    "memory items must be LirMemoryIndexed, LirMemoryStack, or LirMemoryAddressed",
                ))
            })
            .collect::<PyResult<Vec<_>>>()?;
        let inner = InnerLirCpu::new(
            name,
            address_bits,
            endian,
            registers,
            aliases,
            program_counter,
            memory,
        )
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn from_kind(_cls: &Bound<'_, PyType>, kind: PyRef<'_, LirCpuKind>) -> PyResult<Self> {
        let inner = InnerLirCpu::from_kind(kind.inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn i386(_cls: &Bound<'_, PyType>) -> PyResult<Self> {
        let inner =
            InnerLirCpu::i386().map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn amd64(_cls: &Bound<'_, PyType>) -> PyResult<Self> {
        let inner =
            InnerLirCpu::amd64().map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn arm64(_cls: &Bound<'_, PyType>) -> PyResult<Self> {
        let inner =
            InnerLirCpu::arm64().map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn cil(_cls: &Bound<'_, PyType>) -> PyResult<Self> {
        let inner =
            InnerLirCpu::cil().map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    pub fn kind(&self) -> Option<LirCpuKind> {
        self.inner.kind().map(|inner| LirCpuKind { inner })
    }

    pub fn name(&self) -> String {
        self.inner.name().to_string()
    }

    pub fn address_bits(&self) -> u16 {
        self.inner.address_bits()
    }

    pub fn endian(&self) -> LirCpuEndian {
        match self.inner.endian() {
            InnerLirCpuEndian::Little => LirCpuEndian::Little,
            InnerLirCpuEndian::Big => LirCpuEndian::Big,
        }
    }
}

macro_rules! value_wrapper {
    ($name:ident, $inner:ty) => {
        #[pyclass]
        pub struct $name {
            pub inner: Arc<Mutex<$inner>>,
        }

        impl $name {
            pub fn from_inner(inner: $inner) -> Self {
                Self {
                    inner: Arc::new(Mutex::new(inner)),
                }
            }

            fn value_eq(&self, other: &Self) -> bool {
                *self.inner.lock().unwrap() == *other.inner.lock().unwrap()
            }

            fn value_hash(&self) -> isize {
                hash_value(&*self.inner.lock().unwrap())
            }
        }
    };
}

value_wrapper!(LirTemporary, InnerLirTemporary);
value_wrapper!(LirData, InnerLirData);
value_wrapper!(LirDiagnostic, InnerLirDiagnostic);
value_wrapper!(LirEncoding, InnerLirEncoding);
value_wrapper!(LirLocation, InnerLirLocation);
value_wrapper!(LirExpression, InnerLirExpr);
value_wrapper!(LirEffect, InnerLirEffect);
value_wrapper!(LirTerminator, InnerLirTerminator);
value_wrapper!(Lir, InnerLir);
value_wrapper!(LirBlock, InnerLirBlock);
value_wrapper!(LirFunction, InnerLirFunction);
value_wrapper!(LirModule, InnerLirModule);

#[pymethods]
impl LirTemporary {
    #[new]
    #[pyo3(signature = (id, bits, name=None))]
    pub fn new(id: u32, bits: u16, name: Option<String>) -> Self {
        Self::from_inner(InnerLirTemporary { id, bits, name })
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    pub fn id(&self) -> u32 {
        self.inner.lock().unwrap().id
    }
    pub fn bits(&self) -> u16 {
        self.inner.lock().unwrap().bits
    }
    pub fn name(&self) -> Option<String> {
        self.inner.lock().unwrap().name.clone()
    }
    pub fn set_id(&mut self, id: u32) {
        self.inner.lock().unwrap().set_id(id);
    }
    pub fn set_bits(&mut self, bits: u16) {
        self.inner.lock().unwrap().set_bits(bits);
    }
    pub fn set_name(&mut self, name: Option<String>) {
        self.inner.lock().unwrap().set_name(name);
    }
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
    pub fn print(&self) -> PyResult<()> {
        println!("{}", self.json()?);
        Ok(())
    }

    pub fn __hash__(&self) -> isize {
        self.value_hash()
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.value_eq(&other),
            CompareOp::Ne => !self.value_eq(&other),
            _ => false,
        }
    }
}

#[pymethods]
impl LirDiagnostic {
    #[new]
    pub fn new(py: Python<'_>, kind: Py<LirDiagnosticKind>, message: String) -> Self {
        Self::from_inner(InnerLirDiagnostic {
            kind: kind.borrow(py).inner.clone(),
            message,
        })
    }
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }
    pub fn kind(&self) -> LirDiagnosticKind {
        LirDiagnosticKind::from_inner(self.inner.lock().unwrap().kind.clone())
    }
    pub fn message(&self) -> String {
        self.inner.lock().unwrap().message.clone()
    }
    pub fn set_kind(&mut self, py: Python<'_>, kind: Py<LirDiagnosticKind>) {
        self.inner
            .lock()
            .unwrap()
            .set_kind(kind.borrow(py).inner.clone());
    }
    pub fn set_message(&mut self, message: String) {
        self.inner.lock().unwrap().set_message(message);
    }
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
    pub fn print(&self) -> PyResult<()> {
        println!("{}", self.json()?);
        Ok(())
    }

    pub fn __hash__(&self) -> isize {
        self.value_hash()
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.value_eq(&other),
            CompareOp::Ne => !self.value_eq(&other),
            _ => false,
        }
    }
}

#[pymethods]
impl LirEncoding {
    #[new]
    #[pyo3(signature = (architecture, mnemonic, disassembly, address, bytes=None))]
    pub fn new(
        architecture: String,
        mnemonic: String,
        disassembly: String,
        address: u64,
        bytes: Option<&Bound<'_, PyBytes>>,
    ) -> Self {
        Self::from_inner(InnerLirEncoding {
            architecture,
            mnemonic,
            disassembly,
            address,
            bytes: bytes
                .map(|bytes| bytes.as_bytes().to_vec())
                .unwrap_or_default(),
        })
    }
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }
    pub fn architecture(&self) -> String {
        self.inner.lock().unwrap().architecture.clone()
    }
    pub fn mnemonic(&self) -> String {
        self.inner.lock().unwrap().mnemonic.clone()
    }
    pub fn disassembly(&self) -> String {
        self.inner.lock().unwrap().disassembly.clone()
    }
    pub fn address(&self) -> u64 {
        self.inner.lock().unwrap().address
    }
    pub fn bytes(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.lock().unwrap().bytes).unbind()
    }
    pub fn set_architecture(&mut self, architecture: String) {
        self.inner.lock().unwrap().architecture = architecture;
    }
    pub fn set_mnemonic(&mut self, mnemonic: String) {
        self.inner.lock().unwrap().mnemonic = mnemonic;
    }
    pub fn set_disassembly(&mut self, disassembly: String) {
        self.inner.lock().unwrap().disassembly = disassembly;
    }
    pub fn set_address(&mut self, address: u64) {
        self.inner.lock().unwrap().address = address;
    }
    pub fn set_bytes(&mut self, bytes: &Bound<'_, PyBytes>) {
        self.inner.lock().unwrap().bytes = bytes.as_bytes().to_vec();
    }
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
    pub fn print(&self) -> PyResult<()> {
        println!("{}", self.json()?);
        Ok(())
    }

    pub fn __hash__(&self) -> isize {
        self.value_hash()
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.value_eq(&other),
            CompareOp::Ne => !self.value_eq(&other),
            _ => false,
        }
    }
}

#[pymethods]
impl LirLocation {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }
    #[classmethod]
    pub fn register(_cls: &Bound<'_, PyType>, name: String, bits: u16) -> Self {
        Self::from_inner(InnerLirLocation::Register { name, bits })
    }
    #[classmethod]
    pub fn flag(_cls: &Bound<'_, PyType>, name: String, bits: u16) -> Self {
        Self::from_inner(InnerLirLocation::Flag { name, bits })
    }
    #[classmethod]
    pub fn program_counter(_cls: &Bound<'_, PyType>, bits: u16) -> Self {
        Self::from_inner(InnerLirLocation::ProgramCounter { bits })
    }
    #[classmethod]
    pub fn temporary(_cls: &Bound<'_, PyType>, id: u32, bits: u16) -> Self {
        Self::from_inner(InnerLirLocation::Temporary { id, bits })
    }
    #[classmethod]
    pub fn memory(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        space: Py<LirAddressSpace>,
        addr: Py<LirExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirLocation::Memory {
            space: space.borrow(py).inner.clone(),
            addr: Box::new(addr.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn indexed_memory(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        name: String,
        index: Py<LirExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirLocation::IndexedMemory {
            name,
            index: Box::new(index.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn stack_memory(_cls: &Bound<'_, PyType>, name: String, offset: u32, bits: u16) -> Self {
        Self::from_inner(InnerLirLocation::StackMemory { name, offset, bits })
    }
    pub fn kind(&self) -> LirLocationKind {
        LirLocationKind::from_inner(self.inner.lock().unwrap().kind())
    }
    pub fn bits(&self) -> u16 {
        self.inner.lock().unwrap().bits()
    }
    pub fn name(&self) -> Option<String> {
        match &*self.inner.lock().unwrap() {
            InnerLirLocation::Register { name, .. }
            | InnerLirLocation::Flag { name, .. }
            | InnerLirLocation::IndexedMemory { name, .. }
            | InnerLirLocation::StackMemory { name, .. } => Some(name.clone()),
            _ => None,
        }
    }
    pub fn set_kind(&mut self, py: Python<'_>, kind: Py<LirLocationKind>) {
        self.inner.lock().unwrap().set_kind(kind.borrow(py).inner);
    }
    pub fn set_bits(&mut self, bits: u16) {
        self.inner.lock().unwrap().set_bits(bits);
    }
    pub fn set_name(&mut self, name: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_name(name)
            .map_err(PyValueError::new_err)
    }
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
    pub fn print(&self) -> PyResult<()> {
        println!("{}", self.json()?);
        Ok(())
    }

    pub fn __hash__(&self) -> isize {
        self.value_hash()
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.value_eq(&other),
            CompareOp::Ne => !self.value_eq(&other),
            _ => false,
        }
    }
}

#[pymethods]
impl LirExpression {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }
    #[classmethod]
    #[pyo3(name = "const")]
    pub fn const_value(_cls: &Bound<'_, PyType>, value: u128, bits: u16) -> Self {
        Self::from_inner(InnerLirExpr::Const { value, bits })
    }
    #[classmethod]
    pub fn function(_cls: &Bound<'_, PyType>, name: String, bits: u16) -> Self {
        Self::from_inner(InnerLirExpr::Function { name, bits })
    }
    #[classmethod]
    pub fn data_address(_cls: &Bound<'_, PyType>, name: String, bits: u16) -> Self {
        Self::from_inner(InnerLirExpr::DataAddress { name, bits })
    }
    #[classmethod]
    pub fn address_of(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        location: Py<LirLocation>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirExpr::AddressOf {
            location: Box::new(location.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn read(_cls: &Bound<'_, PyType>, py: Python<'_>, location: Py<LirLocation>) -> Self {
        Self::from_inner(InnerLirExpr::Read(Box::new(
            location.borrow(py).inner.lock().unwrap().clone(),
        )))
    }
    #[classmethod]
    pub fn load(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        space: Py<LirAddressSpace>,
        addr: Py<LirExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirExpr::Load {
            space: space.borrow(py).inner.clone(),
            addr: Box::new(addr.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn unary(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        op: Py<LirOperationUnary>,
        arg: Py<LirExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirExpr::Unary {
            op: op.borrow(py).inner,
            arg: Box::new(arg.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn binary(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        op: Py<LirOperationBinary>,
        left: Py<LirExpression>,
        right: Py<LirExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirExpr::Binary {
            op: op.borrow(py).inner,
            left: Box::new(left.borrow(py).inner.lock().unwrap().clone()),
            right: Box::new(right.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn cast(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        op: Py<LirOperationCast>,
        arg: Py<LirExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirExpr::Cast {
            op: op.borrow(py).inner,
            arg: Box::new(arg.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn compare(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        op: Py<LirOperationCompare>,
        left: Py<LirExpression>,
        right: Py<LirExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirExpr::Compare {
            op: op.borrow(py).inner,
            left: Box::new(left.borrow(py).inner.lock().unwrap().clone()),
            right: Box::new(right.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn select(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        condition: Py<LirExpression>,
        when_true: Py<LirExpression>,
        when_false: Py<LirExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirExpr::Select {
            condition: Box::new(condition.borrow(py).inner.lock().unwrap().clone()),
            when_true: Box::new(when_true.borrow(py).inner.lock().unwrap().clone()),
            when_false: Box::new(when_false.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn extract(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        arg: Py<LirExpression>,
        lsb: u16,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirExpr::Extract {
            arg: Box::new(arg.borrow(py).inner.lock().unwrap().clone()),
            lsb,
            bits,
        })
    }
    #[classmethod]
    pub fn concat(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        parts: Vec<Py<LirExpression>>,
        bits: u16,
    ) -> Self {
        let parts = parts
            .into_iter()
            .map(|part| part.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(InnerLirExpr::Concat { parts, bits })
    }
    #[classmethod]
    pub fn undefined(_cls: &Bound<'_, PyType>, bits: u16) -> Self {
        Self::from_inner(InnerLirExpr::Undefined { bits })
    }
    #[classmethod]
    pub fn poison(_cls: &Bound<'_, PyType>, bits: u16) -> Self {
        Self::from_inner(InnerLirExpr::Poison { bits })
    }
    #[classmethod]
    pub fn intrinsic(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        name: String,
        args: Vec<Py<LirExpression>>,
        bits: u16,
    ) -> Self {
        let args = args
            .into_iter()
            .map(|arg| arg.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(InnerLirExpr::Intrinsic { name, args, bits })
    }
    #[classmethod]
    pub fn null(_cls: &Bound<'_, PyType>, bits: u16) -> Self {
        Self::from_inner(InnerLirExpr::Null { bits })
    }
    #[classmethod]
    pub fn allocate(_cls: &Bound<'_, PyType>, kind: String, bits: u16) -> Self {
        Self::from_inner(InnerLirExpr::Allocate { kind, bits })
    }
    #[classmethod]
    pub fn read_property(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        reference: Py<LirExpression>,
        name: String,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirExpr::ReadProperty {
            reference: Box::new(reference.borrow(py).inner.lock().unwrap().clone()),
            name,
            bits,
        })
    }
    #[classmethod]
    pub fn read_element(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        reference: Py<LirExpression>,
        index: Py<LirExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirExpr::ReadElement {
            reference: Box::new(reference.borrow(py).inner.lock().unwrap().clone()),
            index: Box::new(index.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    pub fn kind(&self) -> LirExpressionKind {
        LirExpressionKind::from_inner(self.inner.lock().unwrap().kind())
    }

    pub fn bits(&self) -> u16 {
        self.inner.lock().unwrap().bits()
    }

    pub fn operation(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        match self.inner.lock().unwrap().operation() {
            Some(InnerLirOperation::Binary(op)) => Some(
                Py::new(py, LirOperationBinary::from_inner(op))
                    .expect("binary operation wrapper allocation should succeed")
                    .into_any(),
            ),
            Some(InnerLirOperation::Unary(op)) => Some(
                Py::new(py, LirOperationUnary::from_inner(op))
                    .expect("unary operation wrapper allocation should succeed")
                    .into_any(),
            ),
            Some(InnerLirOperation::Cast(op)) => Some(
                Py::new(py, LirOperationCast::from_inner(op))
                    .expect("cast operation wrapper allocation should succeed")
                    .into_any(),
            ),
            Some(InnerLirOperation::Compare(op)) => Some(
                Py::new(py, LirOperationCompare::from_inner(op))
                    .expect("compare operation wrapper allocation should succeed")
                    .into_any(),
            ),
            None => None,
        }
    }

    pub fn left(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().left().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }

    pub fn right(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().right().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }

    pub fn argument(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().argument().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }

    pub fn condition(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().condition().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }

    pub fn when_true(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().when_true().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }

    pub fn when_false(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().when_false().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }

    pub fn address(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().address().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }

    pub fn address_space(&self, py: Python<'_>) -> PyResult<Option<Py<LirAddressSpace>>> {
        let space = self.inner.lock().unwrap().address_space().cloned();
        space
            .map(|space| Py::new(py, LirAddressSpace::from_inner(space)))
            .transpose()
    }

    pub fn location(&self, py: Python<'_>) -> PyResult<Option<Py<LirLocation>>> {
        let location = self.inner.lock().unwrap().location().cloned();
        location
            .map(|location| Py::new(py, LirLocation::from_inner(location)))
            .transpose()
    }

    pub fn offset(&self) -> Option<u16> {
        self.inner.lock().unwrap().offset()
    }

    pub fn parts(&self, py: Python<'_>) -> PyResult<Option<Vec<Py<LirExpression>>>> {
        self.inner
            .lock()
            .unwrap()
            .parts()
            .map(|parts| {
                parts
                    .iter()
                    .cloned()
                    .map(|part| Py::new(py, LirExpression::from_inner(part)))
                    .collect()
            })
            .transpose()
    }

    pub fn name(&self) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .name()
            .map(std::borrow::ToOwned::to_owned)
    }

    pub fn arguments(&self, py: Python<'_>) -> PyResult<Option<Vec<Py<LirExpression>>>> {
        self.inner
            .lock()
            .unwrap()
            .arguments()
            .map(|arguments| {
                arguments
                    .iter()
                    .cloned()
                    .map(|argument| Py::new(py, LirExpression::from_inner(argument)))
                    .collect()
            })
            .transpose()
    }

    pub fn value(&self) -> Option<u128> {
        self.inner.lock().unwrap().value()
    }

    pub fn set_kind(&mut self, py: Python<'_>, kind: Py<LirExpressionKind>) {
        self.inner.lock().unwrap().set_kind(kind.borrow(py).inner);
    }

    pub fn set_operation(&mut self, py: Python<'_>, operation: Py<PyAny>) -> PyResult<()> {
        let operation = if let Ok(op) = operation.extract::<Py<LirOperationBinary>>(py) {
            InnerLirOperation::Binary(op.borrow(py).inner)
        } else if let Ok(op) = operation.extract::<Py<LirOperationUnary>>(py) {
            InnerLirOperation::Unary(op.borrow(py).inner)
        } else if let Ok(op) = operation.extract::<Py<LirOperationCast>>(py) {
            InnerLirOperation::Cast(op.borrow(py).inner)
        } else if let Ok(op) = operation.extract::<Py<LirOperationCompare>>(py) {
            InnerLirOperation::Compare(op.borrow(py).inner)
        } else {
            return Err(PyValueError::new_err(
                "operation must be a semantic binary, unary, cast, or compare operation",
            ));
        };
        self.inner
            .lock()
            .unwrap()
            .set_operation(operation)
            .map_err(PyValueError::new_err)
    }

    pub fn set_bits(&mut self, bits: u16) {
        self.inner.lock().unwrap().set_bits(bits);
    }

    pub fn set_left(&mut self, py: Python<'_>, expression: Py<LirExpression>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_left(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_right(&mut self, py: Python<'_>, expression: Py<LirExpression>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_right(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_argument(&mut self, py: Python<'_>, expression: Py<LirExpression>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_argument(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_condition(&mut self, py: Python<'_>, expression: Py<LirExpression>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_condition(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_when_true(&mut self, py: Python<'_>, expression: Py<LirExpression>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_when_true(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_when_false(
        &mut self,
        py: Python<'_>,
        expression: Py<LirExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_when_false(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_address(&mut self, py: Python<'_>, expression: Py<LirExpression>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_address(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_address_space(
        &mut self,
        py: Python<'_>,
        space: Py<LirAddressSpace>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_address_space(space.borrow(py).inner.clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_location(&mut self, py: Python<'_>, location: Py<LirLocation>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_location(location.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_offset(&mut self, offset: u16) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_offset(offset)
            .map_err(PyValueError::new_err)
    }

    pub fn set_parts(&mut self, py: Python<'_>, parts: Vec<Py<LirExpression>>) -> PyResult<()> {
        let parts = parts
            .into_iter()
            .map(|part| part.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner
            .lock()
            .unwrap()
            .set_parts(parts)
            .map_err(PyValueError::new_err)
    }

    pub fn set_name(&mut self, name: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_name(name)
            .map_err(PyValueError::new_err)
    }

    pub fn set_arguments(
        &mut self,
        py: Python<'_>,
        arguments: Vec<Py<LirExpression>>,
    ) -> PyResult<()> {
        let arguments = arguments
            .into_iter()
            .map(|argument| argument.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner
            .lock()
            .unwrap()
            .set_arguments(arguments)
            .map_err(PyValueError::new_err)
    }

    pub fn set_value(&mut self, value: u128) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_value(value)
            .map_err(PyValueError::new_err)
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
    pub fn print(&self) -> PyResult<()> {
        println!("{}", self.json()?);
        Ok(())
    }

    pub fn __hash__(&self) -> isize {
        self.value_hash()
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.value_eq(&other),
            CompareOp::Ne => !self.value_eq(&other),
            _ => false,
        }
    }
}

#[pymethods]
impl LirEffect {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }
    #[classmethod]
    pub fn set(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        dst: Py<LirLocation>,
        expression: Py<LirExpression>,
    ) -> Self {
        Self::from_inner(InnerLirEffect::Set {
            dst: dst.borrow(py).inner.lock().unwrap().clone(),
            expression: expression.borrow(py).inner.lock().unwrap().clone(),
        })
    }
    #[classmethod]
    pub fn store(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        space: Py<LirAddressSpace>,
        addr: Py<LirExpression>,
        expression: Py<LirExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirEffect::Store {
            space: space.borrow(py).inner.clone(),
            addr: addr.borrow(py).inner.lock().unwrap().clone(),
            expression: expression.borrow(py).inner.lock().unwrap().clone(),
            bits,
        })
    }
    #[classmethod]
    pub fn write_property(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        reference: Py<LirExpression>,
        name: String,
        expression: Py<LirExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirEffect::WriteProperty {
            reference: reference.borrow(py).inner.lock().unwrap().clone(),
            name,
            expression: expression.borrow(py).inner.lock().unwrap().clone(),
            bits,
        })
    }
    #[classmethod]
    pub fn write_element(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        reference: Py<LirExpression>,
        index: Py<LirExpression>,
        expression: Py<LirExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerLirEffect::WriteElement {
            reference: reference.borrow(py).inner.lock().unwrap().clone(),
            index: index.borrow(py).inner.lock().unwrap().clone(),
            expression: expression.borrow(py).inner.lock().unwrap().clone(),
            bits,
        })
    }
    #[classmethod]
    pub fn push(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        stack: String,
        expression: Py<LirExpression>,
    ) -> Self {
        Self::from_inner(InnerLirEffect::Push {
            stack,
            expression: expression.borrow(py).inner.lock().unwrap().clone(),
        })
    }
    #[classmethod]
    pub fn pop(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        stack: String,
        dst: Py<LirLocation>,
    ) -> Self {
        Self::from_inner(InnerLirEffect::Pop {
            stack,
            dst: dst.borrow(py).inner.lock().unwrap().clone(),
        })
    }
    #[classmethod]
    pub fn fence(_cls: &Bound<'_, PyType>, py: Python<'_>, kind: Py<LirFenceKind>) -> Self {
        Self::from_inner(InnerLirEffect::Fence {
            kind: kind.borrow(py).inner.clone(),
        })
    }
    #[classmethod]
    pub fn trap(_cls: &Bound<'_, PyType>, py: Python<'_>, kind: Py<LirTrapKind>) -> Self {
        Self::from_inner(InnerLirEffect::Trap {
            kind: kind.borrow(py).inner.clone(),
        })
    }
    #[classmethod]
    pub fn intrinsic(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        name: String,
        args: Vec<Py<LirExpression>>,
        outputs: Vec<Py<LirLocation>>,
    ) -> Self {
        let args = args
            .into_iter()
            .map(|arg| arg.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let outputs = outputs
            .into_iter()
            .map(|output| output.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(InnerLirEffect::Intrinsic {
            name,
            args,
            outputs,
        })
    }
    #[classmethod]
    pub fn nop(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(InnerLirEffect::Nop)
    }
    pub fn kind(&self) -> LirEffectKind {
        LirEffectKind::from_inner(self.inner.lock().unwrap().kind())
    }
    pub fn expression(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().expression().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }
    pub fn location(&self, py: Python<'_>) -> PyResult<Option<Py<LirLocation>>> {
        let location = match &*self.inner.lock().unwrap() {
            InnerLirEffect::Set { dst, .. } => Some(dst.clone()),
            InnerLirEffect::AtomicCmpXchg { observed, .. } => Some(observed.clone()),
            InnerLirEffect::Pop { dst, .. } => Some(dst.clone()),
            _ => None,
        };
        location
            .map(|location| Py::new(py, LirLocation::from_inner(location)))
            .transpose()
    }
    pub fn set_kind(&mut self, py: Python<'_>, kind: Py<LirEffectKind>) {
        self.inner.lock().unwrap().set_kind(kind.borrow(py).inner);
    }
    pub fn set_expression(
        &mut self,
        py: Python<'_>,
        expression: Py<LirExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_expression(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }
    pub fn set_location(&mut self, py: Python<'_>, location: Py<LirLocation>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_location(location.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
    pub fn print(&self) -> PyResult<()> {
        println!("{}", self.json()?);
        Ok(())
    }

    pub fn __hash__(&self) -> isize {
        self.value_hash()
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.value_eq(&other),
            CompareOp::Ne => !self.value_eq(&other),
            _ => false,
        }
    }
}

#[pymethods]
impl LirTerminator {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }
    #[classmethod]
    pub fn fallthrough(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(InnerLirTerminator::FallThrough)
    }
    #[classmethod]
    pub fn jump(_cls: &Bound<'_, PyType>, py: Python<'_>, target: Py<LirExpression>) -> Self {
        Self::from_inner(InnerLirTerminator::Jump {
            target: target.borrow(py).inner.lock().unwrap().clone(),
        })
    }
    #[classmethod]
    pub fn branch(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        condition: Py<LirExpression>,
        true_target: Py<LirExpression>,
        false_target: Py<LirExpression>,
    ) -> Self {
        Self::from_inner(InnerLirTerminator::Branch {
            condition: condition.borrow(py).inner.lock().unwrap().clone(),
            true_target: true_target.borrow(py).inner.lock().unwrap().clone(),
            false_target: false_target.borrow(py).inner.lock().unwrap().clone(),
        })
    }
    #[classmethod]
    #[pyo3(signature = (target, return_target=None, does_return=None))]
    pub fn call(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        target: Py<LirExpression>,
        return_target: Option<Py<LirExpression>>,
        does_return: Option<bool>,
    ) -> Self {
        Self::from_inner(InnerLirTerminator::Call {
            target: target.borrow(py).inner.lock().unwrap().clone(),
            return_target: return_target.map(|item| item.borrow(py).inner.lock().unwrap().clone()),
            does_return,
        })
    }
    #[classmethod]
    #[pyo3(signature = (expression=None))]
    pub fn return_(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        expression: Option<Py<LirExpression>>,
    ) -> Self {
        Self::from_inner(InnerLirTerminator::Return {
            expression: expression.map(|item| item.borrow(py).inner.lock().unwrap().clone()),
        })
    }
    #[classmethod]
    pub fn unreachable(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(InnerLirTerminator::Unreachable)
    }
    #[classmethod]
    pub fn trap(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(InnerLirTerminator::Trap)
    }
    pub fn kind(&self) -> LirTerminatorKind {
        LirTerminatorKind::from_inner(self.inner.lock().unwrap().kind())
    }
    pub fn condition(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().condition().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }
    pub fn true_target(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().true_target().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }
    pub fn false_target(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().false_target().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }
    pub fn target(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().target().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }
    pub fn return_target(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().return_target().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }
    pub fn does_return(&self) -> Option<bool> {
        self.inner.lock().unwrap().does_return()
    }
    pub fn return_expression(&self, py: Python<'_>) -> PyResult<Option<Py<LirExpression>>> {
        let expression = self.inner.lock().unwrap().return_expression().cloned();
        expression
            .map(|expression| Py::new(py, LirExpression::from_inner(expression)))
            .transpose()
    }
    pub fn set_kind(&mut self, py: Python<'_>, kind: Py<LirTerminatorKind>) {
        self.inner.lock().unwrap().set_kind(kind.borrow(py).inner);
    }
    pub fn set_condition(&mut self, py: Python<'_>, expression: Py<LirExpression>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_condition(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }
    pub fn set_true_target(
        &mut self,
        py: Python<'_>,
        expression: Py<LirExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_true_target(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }
    pub fn set_false_target(
        &mut self,
        py: Python<'_>,
        expression: Py<LirExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_false_target(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }
    pub fn set_target(&mut self, py: Python<'_>, expression: Py<LirExpression>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_target(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }
    pub fn set_return_target(
        &mut self,
        py: Python<'_>,
        expression: Option<Py<LirExpression>>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_return_target(expression.map(|item| item.borrow(py).inner.lock().unwrap().clone()))
            .map_err(PyValueError::new_err)
    }
    pub fn set_does_return(&mut self, does_return: Option<bool>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_does_return(does_return)
            .map_err(PyValueError::new_err)
    }
    pub fn set_return_expression(
        &mut self,
        py: Python<'_>,
        expression: Option<Py<LirExpression>>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_return_expression(
                expression.map(|item| item.borrow(py).inner.lock().unwrap().clone()),
            )
            .map_err(PyValueError::new_err)
    }
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
    pub fn print(&self) -> PyResult<()> {
        println!("{}", self.json()?);
        Ok(())
    }

    pub fn __hash__(&self) -> isize {
        self.value_hash()
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.value_eq(&other),
            CompareOp::Ne => !self.value_eq(&other),
            _ => false,
        }
    }
}

#[pymethods]
impl Lir {
    #[new]
    #[pyo3(signature = (version, status, abi=None, encoding=None, temporaries=None, effects=None, terminator=None, diagnostics=None))]
    pub fn new(
        py: Python<'_>,
        version: u32,
        status: Py<LirStatus>,
        abi: Option<Py<PyAny>>,
        encoding: Option<Py<LirEncoding>>,
        temporaries: Option<Vec<Py<LirTemporary>>>,
        effects: Option<Vec<Py<LirEffect>>>,
        terminator: Option<Py<LirTerminator>>,
        diagnostics: Option<Vec<Py<LirDiagnostic>>>,
    ) -> PyResult<Self> {
        let abi = abi
            .map(|item| extract_abi(item.bind(py).as_any()))
            .transpose()?;
        let encoding = encoding.map(|item| item.borrow(py).inner.lock().unwrap().clone());
        let temporaries = temporaries
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let effects = effects
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let terminator = terminator
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .unwrap_or(InnerLirTerminator::FallThrough);
        let diagnostics = diagnostics
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Ok(Self::from_inner(InnerLir {
            version,
            status: status.borrow(py).inner,
            abi,
            encoding,
            temporaries,
            effects,
            terminator,
            diagnostics,
        }))
    }
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }
    pub fn version(&self) -> u32 {
        self.inner.lock().unwrap().version
    }
    pub fn status(&self) -> LirStatus {
        LirStatus::from_inner(self.inner.lock().unwrap().status)
    }
    pub fn abi(&self) -> Option<PyLirAbi> {
        self.inner
            .lock()
            .unwrap()
            .abi
            .clone()
            .map(PyLirAbi::from_inner)
    }
    pub fn encoding(&self, py: Python<'_>) -> PyResult<Option<Py<LirEncoding>>> {
        self.inner
            .lock()
            .unwrap()
            .encoding
            .clone()
            .map(|item| Py::new(py, LirEncoding::from_inner(item)))
            .transpose()
    }
    pub fn temporaries(&self, py: Python<'_>) -> PyResult<Vec<Py<LirTemporary>>> {
        self.inner
            .lock()
            .unwrap()
            .temporaries
            .iter()
            .cloned()
            .map(|item| Py::new(py, LirTemporary::from_inner(item)))
            .collect()
    }
    pub fn effects(&self, py: Python<'_>) -> PyResult<Vec<Py<LirEffect>>> {
        self.inner
            .lock()
            .unwrap()
            .effects
            .iter()
            .cloned()
            .map(|item| Py::new(py, LirEffect::from_inner(item)))
            .collect()
    }
    pub fn terminator(&self, py: Python<'_>) -> PyResult<Py<LirTerminator>> {
        Py::new(
            py,
            LirTerminator::from_inner(self.inner.lock().unwrap().terminator.clone()),
        )
    }
    pub fn diagnostics(&self, py: Python<'_>) -> PyResult<Vec<Py<LirDiagnostic>>> {
        self.inner
            .lock()
            .unwrap()
            .diagnostics
            .iter()
            .cloned()
            .map(|item| Py::new(py, LirDiagnostic::from_inner(item)))
            .collect()
    }
    pub fn set_version(&mut self, version: u32) {
        self.inner.lock().unwrap().set_version(version);
    }
    pub fn set_status(&mut self, py: Python<'_>, status: Py<LirStatus>) {
        self.inner
            .lock()
            .unwrap()
            .set_status(status.borrow(py).inner);
    }
    pub fn set_abi(&mut self, py: Python<'_>, abi: Option<Py<PyAny>>) -> PyResult<()> {
        let abi = abi
            .map(|item| extract_abi(item.bind(py).as_any()))
            .transpose()?;
        self.inner.lock().unwrap().set_abi(abi);
        Ok(())
    }
    pub fn set_encoding(&mut self, py: Python<'_>, encoding: Option<Py<LirEncoding>>) {
        let encoding = encoding.map(|item| item.borrow(py).inner.lock().unwrap().clone());
        self.inner.lock().unwrap().set_encoding(encoding);
    }
    pub fn set_temporaries(&mut self, py: Python<'_>, temporaries: Vec<Py<LirTemporary>>) {
        let temporaries = temporaries
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner.lock().unwrap().set_temporaries(temporaries);
    }
    pub fn set_effects(&mut self, py: Python<'_>, effects: Vec<Py<LirEffect>>) {
        let effects = effects
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner.lock().unwrap().set_effects(effects);
    }
    pub fn set_terminator(&mut self, py: Python<'_>, terminator: Py<LirTerminator>) {
        self.inner
            .lock()
            .unwrap()
            .set_terminator(terminator.borrow(py).inner.lock().unwrap().clone());
    }
    pub fn set_diagnostics(&mut self, py: Python<'_>, diagnostics: Vec<Py<LirDiagnostic>>) {
        let diagnostics = diagnostics
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner.lock().unwrap().set_diagnostics(diagnostics);
    }
    pub fn optimize_constants(&mut self) {
        self.inner.lock().unwrap().optimize_constants();
    }
    pub fn optimize_identities(&mut self) {
        self.inner.lock().unwrap().optimize_identities();
    }
    pub fn optimize_casts(&mut self) {
        self.inner.lock().unwrap().optimize_casts();
    }
    pub fn optimize_noops(&mut self) {
        self.inner.lock().unwrap().optimize_noops();
    }
    pub fn optimize_branches(&mut self) {
        self.inner.lock().unwrap().optimize_branches();
    }
    pub fn optimize_intrinsics(&mut self) {
        self.inner.lock().unwrap().optimize_intrinsics();
    }
    pub fn optimize(&mut self) {
        self.inner.lock().unwrap().optimize();
    }
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
    pub fn text(&self) -> String {
        self.inner.lock().unwrap().text()
    }
    pub fn print(&self) -> PyResult<()> {
        println!("{}", self.text());
        Ok(())
    }
    pub fn __str__(&self) -> PyResult<String> {
        Ok(self.text())
    }

    pub fn __hash__(&self) -> isize {
        self.value_hash()
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.value_eq(&other),
            CompareOp::Ne => !self.value_eq(&other),
            _ => false,
        }
    }
}

#[pymethods]
impl LirData {
    #[new]
    pub fn new(name: String, bytes: Vec<u8>) -> Self {
        Self::from_inner(InnerLirData { name, bytes })
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    pub fn name(&self) -> String {
        self.inner.lock().unwrap().name.clone()
    }

    pub fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.lock().unwrap().bytes)
    }

    pub fn set_name(&mut self, name: String) {
        self.inner.lock().unwrap().name = name;
    }

    pub fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.inner.lock().unwrap().bytes = bytes;
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }

    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    pub fn print(&self) -> PyResult<()> {
        println!("{}", self.json()?);
        Ok(())
    }

    pub fn __hash__(&self) -> isize {
        self.value_hash()
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.value_eq(&other),
            CompareOp::Ne => !self.value_eq(&other),
            _ => false,
        }
    }
}

#[pymethods]
impl LirBlock {
    #[new]
    #[pyo3(signature = (name=None, instructions=None))]
    pub fn new(py: Python<'_>, name: Option<String>, instructions: Option<Vec<Py<Lir>>>) -> Self {
        let instructions = instructions
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(InnerLirBlock { name, instructions })
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    pub fn name(&self) -> Option<String> {
        self.inner.lock().unwrap().name.clone()
    }

    pub fn instructions(&self, py: Python<'_>) -> PyResult<Vec<Py<Lir>>> {
        self.inner
            .lock()
            .unwrap()
            .instructions
            .iter()
            .cloned()
            .map(|item| Py::new(py, Lir::from_inner(item)))
            .collect()
    }

    pub fn set_name(&mut self, name: Option<String>) {
        self.inner.lock().unwrap().name = name;
    }

    pub fn set_instructions(&mut self, py: Python<'_>, instructions: Vec<Py<Lir>>) {
        let instructions = instructions
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner.lock().unwrap().instructions = instructions;
    }

    pub fn append_instruction(&mut self, py: Python<'_>, instruction: Py<Lir>) {
        let instruction = instruction.borrow(py).inner.lock().unwrap().clone();
        self.inner.lock().unwrap().instructions.push(instruction);
    }

    pub fn optimize_constants(&mut self) {
        self.inner.lock().unwrap().optimize_constants();
    }
    pub fn optimize_identities(&mut self) {
        self.inner.lock().unwrap().optimize_identities();
    }
    pub fn optimize_casts(&mut self) {
        self.inner.lock().unwrap().optimize_casts();
    }
    pub fn optimize_noops(&mut self) {
        self.inner.lock().unwrap().optimize_noops();
    }
    pub fn optimize_branches(&mut self) {
        self.inner.lock().unwrap().optimize_branches();
    }
    pub fn optimize_intrinsics(&mut self) {
        self.inner.lock().unwrap().optimize_intrinsics();
    }
    pub fn optimize(&mut self) {
        self.inner.lock().unwrap().optimize();
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }

    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    pub fn text(&self) -> String {
        self.inner.lock().unwrap().text()
    }

    pub fn __hash__(&self) -> isize {
        self.value_hash()
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.value_eq(&other),
            CompareOp::Ne => !self.value_eq(&other),
            _ => false,
        }
    }
}

#[pymethods]
impl LirFunction {
    #[new]
    #[pyo3(signature = (name=None, abi=None, blocks=None))]
    pub fn new(
        py: Python<'_>,
        name: Option<String>,
        abi: Option<Py<PyAny>>,
        blocks: Option<Vec<Py<LirBlock>>>,
    ) -> PyResult<Self> {
        let abi = abi
            .map(|item| extract_abi(item.bind(py).as_any()))
            .transpose()?;
        let blocks = blocks
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Ok(Self::from_inner(InnerLirFunction { name, abi, blocks }))
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    pub fn name(&self) -> Option<String> {
        self.inner.lock().unwrap().name.clone()
    }

    pub fn abi(&self) -> Option<PyLirAbi> {
        self.inner
            .lock()
            .unwrap()
            .abi
            .clone()
            .map(PyLirAbi::from_inner)
    }

    pub fn blocks(&self, py: Python<'_>) -> PyResult<Vec<Py<LirBlock>>> {
        self.inner
            .lock()
            .unwrap()
            .blocks
            .iter()
            .cloned()
            .map(|item| Py::new(py, LirBlock::from_inner(item)))
            .collect()
    }

    pub fn set_name(&mut self, name: Option<String>) {
        self.inner.lock().unwrap().name = name;
    }

    pub fn set_abi(&mut self, py: Python<'_>, abi: Option<Py<PyAny>>) -> PyResult<()> {
        let abi = abi
            .map(|item| extract_abi(item.bind(py).as_any()))
            .transpose()?;
        self.inner.lock().unwrap().abi = abi;
        Ok(())
    }

    pub fn set_blocks(&mut self, py: Python<'_>, blocks: Vec<Py<LirBlock>>) {
        let blocks = blocks
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner.lock().unwrap().blocks = blocks;
    }

    pub fn append_block(&mut self, py: Python<'_>, block: Py<LirBlock>) {
        let block = block.borrow(py).inner.lock().unwrap().clone();
        self.inner.lock().unwrap().blocks.push(block);
    }

    pub fn optimize_constants(&mut self) {
        self.inner.lock().unwrap().optimize_constants();
    }
    pub fn optimize_identities(&mut self) {
        self.inner.lock().unwrap().optimize_identities();
    }
    pub fn optimize_casts(&mut self) {
        self.inner.lock().unwrap().optimize_casts();
    }
    pub fn optimize_noops(&mut self) {
        self.inner.lock().unwrap().optimize_noops();
    }
    pub fn optimize_branches(&mut self) {
        self.inner.lock().unwrap().optimize_branches();
    }
    pub fn optimize_intrinsics(&mut self) {
        self.inner.lock().unwrap().optimize_intrinsics();
    }
    pub fn optimize(&mut self) {
        self.inner.lock().unwrap().optimize();
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }

    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    pub fn text(&self) -> String {
        self.inner.lock().unwrap().text()
    }

    pub fn __hash__(&self) -> isize {
        self.value_hash()
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.value_eq(&other),
            CompareOp::Ne => !self.value_eq(&other),
            _ => false,
        }
    }
}

#[pymethods]
impl LirModule {
    #[new]
    #[pyo3(signature = (name=None, functions=None, data=None))]
    pub fn new(
        py: Python<'_>,
        name: Option<String>,
        functions: Option<Vec<Py<LirFunction>>>,
        data: Option<Vec<Py<LirData>>>,
    ) -> Self {
        let functions = functions
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let data = data
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(InnerLirModule {
            name,
            functions,
            data,
        })
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    pub fn name(&self) -> Option<String> {
        self.inner.lock().unwrap().name.clone()
    }

    pub fn functions(&self, py: Python<'_>) -> PyResult<Vec<Py<LirFunction>>> {
        self.inner
            .lock()
            .unwrap()
            .functions
            .iter()
            .cloned()
            .map(|item| Py::new(py, LirFunction::from_inner(item)))
            .collect()
    }

    pub fn data(&self, py: Python<'_>) -> PyResult<Vec<Py<LirData>>> {
        self.inner
            .lock()
            .unwrap()
            .data
            .iter()
            .cloned()
            .map(|item| Py::new(py, LirData::from_inner(item)))
            .collect()
    }

    pub fn set_name(&mut self, name: Option<String>) {
        self.inner.lock().unwrap().name = name;
    }

    pub fn set_functions(&mut self, py: Python<'_>, functions: Vec<Py<LirFunction>>) {
        let functions = functions
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner.lock().unwrap().functions = functions;
    }

    pub fn append_function(&mut self, py: Python<'_>, function: Py<LirFunction>) {
        let function = function.borrow(py).inner.lock().unwrap().clone();
        self.inner.lock().unwrap().functions.push(function);
    }

    pub fn set_data(&mut self, py: Python<'_>, data: Vec<Py<LirData>>) {
        let data = data
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner.lock().unwrap().data = data;
    }

    pub fn append_data(&mut self, py: Python<'_>, data: Py<LirData>) {
        let data = data.borrow(py).inner.lock().unwrap().clone();
        self.inner.lock().unwrap().data.push(data);
    }
    pub fn optimize_constants(&mut self) {
        self.inner.lock().unwrap().optimize_constants();
    }
    pub fn optimize_identities(&mut self) {
        self.inner.lock().unwrap().optimize_identities();
    }
    pub fn optimize_casts(&mut self) {
        self.inner.lock().unwrap().optimize_casts();
    }
    pub fn optimize_noops(&mut self) {
        self.inner.lock().unwrap().optimize_noops();
    }
    pub fn optimize_branches(&mut self) {
        self.inner.lock().unwrap().optimize_branches();
    }
    pub fn optimize_intrinsics(&mut self) {
        self.inner.lock().unwrap().optimize_intrinsics();
    }
    pub fn optimize(&mut self) {
        self.inner.lock().unwrap().optimize();
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }

    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    pub fn text(&self) -> String {
        self.inner.lock().unwrap().text()
    }

    pub fn print(&self) -> PyResult<()> {
        println!("{}", self.text());
        Ok(())
    }

    pub fn __hash__(&self) -> isize {
        self.value_hash()
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.value_eq(&other),
            CompareOp::Ne => !self.value_eq(&other),
            _ => false,
        }
    }
}

#[pymodule]
#[pyo3(name = "lir")]
pub fn lir_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    register_abi_classes(m)?;
    m.add_class::<LirStatus>()?;
    m.add_class::<LirLocationKind>()?;
    m.add_class::<LirEffectKind>()?;
    m.add_class::<LirExpressionKind>()?;
    m.add_class::<LirTerminatorKind>()?;
    m.add_class::<LirAddressSpace>()?;
    m.add_class::<LirFenceKind>()?;
    m.add_class::<LirTrapKind>()?;
    m.add_class::<LirOperationUnary>()?;
    m.add_class::<LirOperationBinary>()?;
    m.add_class::<LirOperationCast>()?;
    m.add_class::<LirOperationCompare>()?;
    m.add_class::<LirDiagnosticKind>()?;
    m.add_class::<LirCpuKind>()?;
    m.add_class::<LirCpu>()?;
    m.add_class::<LirCpuRegister>()?;
    m.add_class::<LirCpuAlias>()?;
    m.add_class::<LirCpuProgramCounter>()?;
    m.add_class::<LirMemoryIndexed>()?;
    m.add_class::<LirMemoryStack>()?;
    m.add_class::<LirMemoryAddressed>()?;
    m.add_class::<LirCpuEndian>()?;
    m.add_class::<LirTemporary>()?;
    m.add_class::<LirDiagnostic>()?;
    m.add_class::<LirEncoding>()?;
    m.add_class::<LirLocation>()?;
    m.add_class::<LirExpression>()?;
    m.add_class::<LirEffect>()?;
    m.add_class::<LirTerminator>()?;
    m.add_class::<Lir>()?;
    m.add_class::<LirBlock>()?;
    m.add_class::<LirFunction>()?;
    m.add_class::<LirData>()?;
    m.add_class::<LirModule>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.ir.lir", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.ir.lir")?;
    Ok(())
}
