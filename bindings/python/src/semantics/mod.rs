pub mod abis;

use crate::semantics::abis::{SemanticAbi as PySemanticAbi, extract_abi, register_abi_classes};
use binlex::semantics::{
    Semantic as InnerSemantic, SemanticAddressSpace as InnerAddressSpace,
    SemanticCpu as InnerSemanticCpu, SemanticCpuAlias as InnerSemanticCpuAlias,
    SemanticCpuAliasWritePolicy as InnerSemanticCpuAliasWritePolicy,
    SemanticCpuEndian as InnerSemanticCpuEndian, SemanticCpuKind as InnerSemanticCpuKind,
    SemanticCpuProgramCounter as InnerSemanticCpuProgramCounter,
    SemanticCpuRegister as InnerSemanticCpuRegister, SemanticDiagnostic as InnerSemanticDiagnostic,
    SemanticDiagnosticKind as InnerSemanticDiagnosticKind, SemanticEffect as InnerSemanticEffect,
    SemanticEffectKind as InnerSemanticEffectKind, SemanticEncoding as InnerSemanticEncoding,
    SemanticData as InnerSemanticData, SemanticExpression as InnerSemanticExpr,
    SemanticExpressionKind as InnerSemanticExprKind,
    SemanticFenceKind as InnerFenceKind, SemanticLocation as InnerSemanticLocation,
    SemanticLocationKind as InnerSemanticLocationKind, SemanticMemory as InnerSemanticMemory,
    SemanticMemoryAddressed as InnerSemanticMemoryAddressed,
    SemanticMemoryIndexed as InnerSemanticMemoryIndexed,
    SemanticMemoryStack as InnerSemanticMemoryStack, SemanticOperation as InnerSemanticOperation,
    SemanticOperationBinary as InnerSemanticBinaryOp, SemanticOperationCast as InnerSemanticCastOp,
    SemanticOperationCompare as InnerSemanticCompareOp,
    SemanticOperationUnary as InnerSemanticUnaryOp, SemanticStatus as InnerSemanticStatus,
    SemanticTemporary as InnerSemanticTemporary, SemanticTerminator as InnerSemanticTerminator,
    SemanticTerminatorKind as InnerSemanticTerminatorKind, SemanticTrapKind as InnerTrapKind,
    Semantics as InnerSemantics,
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

simple_enum_binding!(SemanticStatus, InnerSemanticStatus, { Partial, Complete });
simple_enum_binding!(
    SemanticLocationKind,
    InnerSemanticLocationKind,
    { Register, Flag, ProgramCounter, Temporary, Memory }
);
simple_enum_binding!(
    SemanticEffectKind,
    InnerSemanticEffectKind,
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
    SemanticExpressionKind,
    InnerSemanticExprKind,
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
    SemanticTerminatorKind,
    InnerSemanticTerminatorKind,
    { FallThrough, Jump, Branch, Call, Return, Unreachable, Trap }
);
simple_enum_binding!(
    SemanticOperationUnary,
    InnerSemanticUnaryOp,
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
    SemanticOperationBinary,
    InnerSemanticBinaryOp,
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
    SemanticOperationCast,
    InnerSemanticCastOp,
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
    SemanticOperationCompare,
    InnerSemanticCompareOp,
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
pub struct SemanticAddressSpace {
    pub inner: InnerAddressSpace,
}

impl SemanticAddressSpace {
    pub fn from_inner(inner: InnerAddressSpace) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl SemanticAddressSpace {
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
pub struct SemanticFenceKind {
    pub inner: InnerFenceKind,
}

impl SemanticFenceKind {
    pub fn from_inner(inner: InnerFenceKind) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl SemanticFenceKind {
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
pub struct SemanticTrapKind {
    pub inner: InnerTrapKind,
}

impl SemanticTrapKind {
    pub fn from_inner(inner: InnerTrapKind) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl SemanticTrapKind {
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
pub struct SemanticDiagnosticKind {
    pub inner: InnerSemanticDiagnosticKind,
}

impl SemanticDiagnosticKind {
    pub fn from_inner(inner: InnerSemanticDiagnosticKind) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl SemanticDiagnosticKind {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const UnsupportedInstruction: Self = Self {
        inner: InnerSemanticDiagnosticKind::UnsupportedInstruction,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const UnsupportedOperandForm: Self = Self {
        inner: InnerSemanticDiagnosticKind::UnsupportedOperandForm,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const UnsupportedRegisterClass: Self = Self {
        inner: InnerSemanticDiagnosticKind::UnsupportedRegisterClass,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const UnsupportedVectorForm: Self = Self {
        inner: InnerSemanticDiagnosticKind::UnsupportedVectorForm,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const UnsupportedFloatingPointForm: Self = Self {
        inner: InnerSemanticDiagnosticKind::UnsupportedFloatingPointForm,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const UnsupportedAtomicForm: Self = Self {
        inner: InnerSemanticDiagnosticKind::UnsupportedAtomicForm,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const PartialFlags: Self = Self {
        inner: InnerSemanticDiagnosticKind::PartialFlags,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const PartialMemoryModel: Self = Self {
        inner: InnerSemanticDiagnosticKind::PartialMemoryModel,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const PartialExceptionModel: Self = Self {
        inner: InnerSemanticDiagnosticKind::PartialExceptionModel,
    };

    #[staticmethod]
    pub fn named(name: String) -> Self {
        Self {
            inner: InnerSemanticDiagnosticKind::Named { name },
        }
    }

    pub fn __str__(&self) -> String {
        match &self.inner {
            InnerSemanticDiagnosticKind::UnsupportedInstruction => {
                "UnsupportedInstruction".to_string()
            }
            InnerSemanticDiagnosticKind::UnsupportedOperandForm => {
                "UnsupportedOperandForm".to_string()
            }
            InnerSemanticDiagnosticKind::UnsupportedRegisterClass => {
                "UnsupportedRegisterClass".to_string()
            }
            InnerSemanticDiagnosticKind::UnsupportedVectorForm => {
                "UnsupportedVectorForm".to_string()
            }
            InnerSemanticDiagnosticKind::UnsupportedFloatingPointForm => {
                "UnsupportedFloatingPointForm".to_string()
            }
            InnerSemanticDiagnosticKind::UnsupportedAtomicForm => {
                "UnsupportedAtomicForm".to_string()
            }
            InnerSemanticDiagnosticKind::PartialFlags => "PartialFlags".to_string(),
            InnerSemanticDiagnosticKind::PartialMemoryModel => "PartialMemoryModel".to_string(),
            InnerSemanticDiagnosticKind::PartialExceptionModel => {
                "PartialExceptionModel".to_string()
            }
            InnerSemanticDiagnosticKind::Named { name } => format!("Named({})", name),
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
pub struct SemanticCpu {
    pub inner: InnerSemanticCpu,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SemanticCpuRegister {
    pub inner: InnerSemanticCpuRegister,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SemanticCpuAlias {
    pub inner: InnerSemanticCpuAlias,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SemanticCpuProgramCounter {
    pub inner: InnerSemanticCpuProgramCounter,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SemanticMemoryIndexed {
    pub inner: InnerSemanticMemoryIndexed,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SemanticMemoryStack {
    pub inner: InnerSemanticMemoryStack,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SemanticMemoryAddressed {
    pub inner: InnerSemanticMemoryAddressed,
}

#[pyclass(eq, eq_int, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SemanticCpuEndian {
    Little,
    Big,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone, Copy)]
pub struct SemanticCpuKind {
    pub inner: InnerSemanticCpuKind,
}

#[pymethods]
impl SemanticCpuKind {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const I386: Self = Self {
        inner: InnerSemanticCpuKind::I386,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Amd64: Self = Self {
        inner: InnerSemanticCpuKind::Amd64,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Arm64: Self = Self {
        inner: InnerSemanticCpuKind::Arm64,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Cil: Self = Self {
        inner: InnerSemanticCpuKind::Cil,
    };

    pub fn __str__(&self) -> String {
        match self.inner {
            InnerSemanticCpuKind::I386 => "I386".to_string(),
            InnerSemanticCpuKind::Amd64 => "Amd64".to_string(),
            InnerSemanticCpuKind::Arm64 => "Arm64".to_string(),
            InnerSemanticCpuKind::Cil => "Cil".to_string(),
        }
    }
}

impl From<SemanticCpuEndian> for InnerSemanticCpuEndian {
    fn from(value: SemanticCpuEndian) -> Self {
        match value {
            SemanticCpuEndian::Little => Self::Little,
            SemanticCpuEndian::Big => Self::Big,
        }
    }
}

#[pymethods]
impl SemanticCpuRegister {
    #[new]
    #[pyo3(text_signature = "(name, bits)")]
    pub fn new(name: String, bits: u16) -> Self {
        Self {
            inner: InnerSemanticCpuRegister::new(name, bits),
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
impl SemanticCpuAlias {
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
            "preserve" => InnerSemanticCpuAlias::new(name, parent, offset, bits),
            "zero_extend" => InnerSemanticCpuAlias::zero_extend(name, parent, offset, bits),
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
            InnerSemanticCpuAliasWritePolicy::Preserve => "preserve",
            InnerSemanticCpuAliasWritePolicy::ZeroExtend => "zero_extend",
        }
        .to_string()
    }
}

#[pymethods]
impl SemanticCpuProgramCounter {
    #[new]
    #[pyo3(text_signature = "(name, bits)")]
    pub fn new(name: String, bits: u16) -> Self {
        Self {
            inner: InnerSemanticCpuProgramCounter::new(name, bits),
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
impl SemanticMemoryIndexed {
    #[new]
    #[pyo3(text_signature = "(name)")]
    pub fn new(name: String) -> Self {
        Self {
            inner: InnerSemanticMemoryIndexed::new(name),
        }
    }

    pub fn name(&self) -> String {
        self.inner.name.clone()
    }
}

#[pymethods]
impl SemanticMemoryStack {
    #[new]
    #[pyo3(text_signature = "(name)")]
    pub fn new(name: String) -> Self {
        Self {
            inner: InnerSemanticMemoryStack::new(name),
        }
    }

    pub fn name(&self) -> String {
        self.inner.name.clone()
    }
}

#[pymethods]
impl SemanticMemoryAddressed {
    #[new]
    #[pyo3(text_signature = "(name, address_bits, endian)")]
    pub fn new(name: String, address_bits: u16, endian: SemanticCpuEndian) -> Self {
        Self {
            inner: InnerSemanticMemoryAddressed::new(name, address_bits, endian.into()),
        }
    }

    pub fn name(&self) -> String {
        self.inner.name.clone()
    }

    pub fn address_bits(&self) -> u16 {
        self.inner.address_bits
    }

    pub fn endian(&self) -> SemanticCpuEndian {
        match self.inner.endian {
            InnerSemanticCpuEndian::Little => SemanticCpuEndian::Little,
            InnerSemanticCpuEndian::Big => SemanticCpuEndian::Big,
        }
    }
}

#[pymethods]
impl SemanticCpu {
    #[new]
    #[pyo3(signature = (*, name, address_bits, endian, registers=None, aliases=None, program_counter=None, memory=None))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        py: Python<'_>,
        name: String,
        address_bits: u16,
        endian: SemanticCpuEndian,
        registers: Option<Vec<Py<SemanticCpuRegister>>>,
        aliases: Option<Vec<Py<SemanticCpuAlias>>>,
        program_counter: Option<Py<SemanticCpuProgramCounter>>,
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
                if let Ok(memory) = bound.extract::<PyRef<'_, SemanticMemoryIndexed>>() {
                    return Ok(InnerSemanticMemory::Indexed(memory.inner.clone()));
                }
                if let Ok(memory) = bound.extract::<PyRef<'_, SemanticMemoryStack>>() {
                    return Ok(InnerSemanticMemory::Stack(memory.inner.clone()));
                }
                if let Ok(memory) = bound.extract::<PyRef<'_, SemanticMemoryAddressed>>() {
                    return Ok(InnerSemanticMemory::Addressed(memory.inner.clone()));
                }
                Err(PyTypeError::new_err(
                    "memory items must be SemanticMemoryIndexed, SemanticMemoryStack, or SemanticMemoryAddressed",
                ))
            })
            .collect::<PyResult<Vec<_>>>()?;
        let inner = InnerSemanticCpu::new(
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
    pub fn from_kind(_cls: &Bound<'_, PyType>, kind: PyRef<'_, SemanticCpuKind>) -> PyResult<Self> {
        let inner = InnerSemanticCpu::from_kind(kind.inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn i386(_cls: &Bound<'_, PyType>) -> PyResult<Self> {
        let inner =
            InnerSemanticCpu::i386().map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn amd64(_cls: &Bound<'_, PyType>) -> PyResult<Self> {
        let inner = InnerSemanticCpu::amd64()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn arm64(_cls: &Bound<'_, PyType>) -> PyResult<Self> {
        let inner = InnerSemanticCpu::arm64()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn cil(_cls: &Bound<'_, PyType>) -> PyResult<Self> {
        let inner =
            InnerSemanticCpu::cil().map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    pub fn kind(&self) -> Option<SemanticCpuKind> {
        self.inner.kind().map(|inner| SemanticCpuKind { inner })
    }

    pub fn name(&self) -> String {
        self.inner.name().to_string()
    }

    pub fn address_bits(&self) -> u16 {
        self.inner.address_bits()
    }

    pub fn endian(&self) -> SemanticCpuEndian {
        match self.inner.endian() {
            InnerSemanticCpuEndian::Little => SemanticCpuEndian::Little,
            InnerSemanticCpuEndian::Big => SemanticCpuEndian::Big,
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

value_wrapper!(SemanticTemporary, InnerSemanticTemporary);
value_wrapper!(SemanticData, InnerSemanticData);
value_wrapper!(SemanticDiagnostic, InnerSemanticDiagnostic);
value_wrapper!(SemanticEncoding, InnerSemanticEncoding);
value_wrapper!(SemanticLocation, InnerSemanticLocation);
value_wrapper!(SemanticExpression, InnerSemanticExpr);
value_wrapper!(SemanticEffect, InnerSemanticEffect);
value_wrapper!(SemanticTerminator, InnerSemanticTerminator);
value_wrapper!(Semantic, InnerSemantic);
value_wrapper!(Semantics, InnerSemantics);

#[pymethods]
impl SemanticTemporary {
    #[new]
    #[pyo3(signature = (id, bits, name=None))]
    pub fn new(id: u32, bits: u16, name: Option<String>) -> Self {
        Self::from_inner(InnerSemanticTemporary { id, bits, name })
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
impl SemanticDiagnostic {
    #[new]
    pub fn new(py: Python<'_>, kind: Py<SemanticDiagnosticKind>, message: String) -> Self {
        Self::from_inner(InnerSemanticDiagnostic {
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
    pub fn kind(&self) -> SemanticDiagnosticKind {
        SemanticDiagnosticKind::from_inner(self.inner.lock().unwrap().kind.clone())
    }
    pub fn message(&self) -> String {
        self.inner.lock().unwrap().message.clone()
    }
    pub fn set_kind(&mut self, py: Python<'_>, kind: Py<SemanticDiagnosticKind>) {
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
impl SemanticEncoding {
    #[new]
    #[pyo3(signature = (architecture, mnemonic, disassembly, address, bytes=None))]
    pub fn new(
        architecture: String,
        mnemonic: String,
        disassembly: String,
        address: u64,
        bytes: Option<&Bound<'_, PyBytes>>,
    ) -> Self {
        Self::from_inner(InnerSemanticEncoding {
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
impl SemanticLocation {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }
    #[classmethod]
    pub fn register(_cls: &Bound<'_, PyType>, name: String, bits: u16) -> Self {
        Self::from_inner(InnerSemanticLocation::Register { name, bits })
    }
    #[classmethod]
    pub fn flag(_cls: &Bound<'_, PyType>, name: String, bits: u16) -> Self {
        Self::from_inner(InnerSemanticLocation::Flag { name, bits })
    }
    #[classmethod]
    pub fn program_counter(_cls: &Bound<'_, PyType>, bits: u16) -> Self {
        Self::from_inner(InnerSemanticLocation::ProgramCounter { bits })
    }
    #[classmethod]
    pub fn temporary(_cls: &Bound<'_, PyType>, id: u32, bits: u16) -> Self {
        Self::from_inner(InnerSemanticLocation::Temporary { id, bits })
    }
    #[classmethod]
    pub fn memory(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        space: Py<SemanticAddressSpace>,
        addr: Py<SemanticExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticLocation::Memory {
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
        index: Py<SemanticExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticLocation::IndexedMemory {
            name,
            index: Box::new(index.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn stack_memory(_cls: &Bound<'_, PyType>, name: String, offset: u32, bits: u16) -> Self {
        Self::from_inner(InnerSemanticLocation::StackMemory { name, offset, bits })
    }
    pub fn kind(&self) -> SemanticLocationKind {
        SemanticLocationKind::from_inner(self.inner.lock().unwrap().kind())
    }
    pub fn bits(&self) -> u16 {
        self.inner.lock().unwrap().bits()
    }
    pub fn name(&self) -> Option<String> {
        match &*self.inner.lock().unwrap() {
            InnerSemanticLocation::Register { name, .. }
            | InnerSemanticLocation::Flag { name, .. }
            | InnerSemanticLocation::IndexedMemory { name, .. }
            | InnerSemanticLocation::StackMemory { name, .. } => Some(name.clone()),
            _ => None,
        }
    }
    pub fn set_kind(&mut self, py: Python<'_>, kind: Py<SemanticLocationKind>) {
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
impl SemanticExpression {
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
        Self::from_inner(InnerSemanticExpr::Const { value, bits })
    }
    #[classmethod]
    pub fn function(_cls: &Bound<'_, PyType>, name: String, bits: u16) -> Self {
        Self::from_inner(InnerSemanticExpr::Function { name, bits })
    }
    #[classmethod]
    pub fn data_address(_cls: &Bound<'_, PyType>, name: String, bits: u16) -> Self {
        Self::from_inner(InnerSemanticExpr::DataAddress { name, bits })
    }
    #[classmethod]
    pub fn address_of(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        location: Py<SemanticLocation>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticExpr::AddressOf {
            location: Box::new(location.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn read(_cls: &Bound<'_, PyType>, py: Python<'_>, location: Py<SemanticLocation>) -> Self {
        Self::from_inner(InnerSemanticExpr::Read(Box::new(
            location.borrow(py).inner.lock().unwrap().clone(),
        )))
    }
    #[classmethod]
    pub fn load(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        space: Py<SemanticAddressSpace>,
        addr: Py<SemanticExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticExpr::Load {
            space: space.borrow(py).inner.clone(),
            addr: Box::new(addr.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn unary(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        op: Py<SemanticOperationUnary>,
        arg: Py<SemanticExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticExpr::Unary {
            op: op.borrow(py).inner,
            arg: Box::new(arg.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn binary(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        op: Py<SemanticOperationBinary>,
        left: Py<SemanticExpression>,
        right: Py<SemanticExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticExpr::Binary {
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
        op: Py<SemanticOperationCast>,
        arg: Py<SemanticExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticExpr::Cast {
            op: op.borrow(py).inner,
            arg: Box::new(arg.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    #[classmethod]
    pub fn compare(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        op: Py<SemanticOperationCompare>,
        left: Py<SemanticExpression>,
        right: Py<SemanticExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticExpr::Compare {
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
        condition: Py<SemanticExpression>,
        when_true: Py<SemanticExpression>,
        when_false: Py<SemanticExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticExpr::Select {
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
        arg: Py<SemanticExpression>,
        lsb: u16,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticExpr::Extract {
            arg: Box::new(arg.borrow(py).inner.lock().unwrap().clone()),
            lsb,
            bits,
        })
    }
    #[classmethod]
    pub fn concat(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        parts: Vec<Py<SemanticExpression>>,
        bits: u16,
    ) -> Self {
        let parts = parts
            .into_iter()
            .map(|part| part.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(InnerSemanticExpr::Concat { parts, bits })
    }
    #[classmethod]
    pub fn undefined(_cls: &Bound<'_, PyType>, bits: u16) -> Self {
        Self::from_inner(InnerSemanticExpr::Undefined { bits })
    }
    #[classmethod]
    pub fn poison(_cls: &Bound<'_, PyType>, bits: u16) -> Self {
        Self::from_inner(InnerSemanticExpr::Poison { bits })
    }
    #[classmethod]
    pub fn intrinsic(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        name: String,
        args: Vec<Py<SemanticExpression>>,
        bits: u16,
    ) -> Self {
        let args = args
            .into_iter()
            .map(|arg| arg.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(InnerSemanticExpr::Intrinsic { name, args, bits })
    }
    #[classmethod]
    pub fn null(_cls: &Bound<'_, PyType>, bits: u16) -> Self {
        Self::from_inner(InnerSemanticExpr::Null { bits })
    }
    #[classmethod]
    pub fn allocate(_cls: &Bound<'_, PyType>, kind: String, bits: u16) -> Self {
        Self::from_inner(InnerSemanticExpr::Allocate { kind, bits })
    }
    #[classmethod]
    pub fn read_property(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        reference: Py<SemanticExpression>,
        name: String,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticExpr::ReadProperty {
            reference: Box::new(reference.borrow(py).inner.lock().unwrap().clone()),
            name,
            bits,
        })
    }
    #[classmethod]
    pub fn read_element(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        reference: Py<SemanticExpression>,
        index: Py<SemanticExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticExpr::ReadElement {
            reference: Box::new(reference.borrow(py).inner.lock().unwrap().clone()),
            index: Box::new(index.borrow(py).inner.lock().unwrap().clone()),
            bits,
        })
    }
    pub fn kind(&self) -> SemanticExpressionKind {
        SemanticExpressionKind::from_inner(self.inner.lock().unwrap().kind())
    }

    pub fn bits(&self) -> u16 {
        self.inner.lock().unwrap().bits()
    }

    pub fn operation(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        match self.inner.lock().unwrap().operation() {
            Some(InnerSemanticOperation::Binary(op)) => Some(
                Py::new(py, SemanticOperationBinary::from_inner(op))
                    .expect("binary operation wrapper allocation should succeed")
                    .into_any(),
            ),
            Some(InnerSemanticOperation::Unary(op)) => Some(
                Py::new(py, SemanticOperationUnary::from_inner(op))
                    .expect("unary operation wrapper allocation should succeed")
                    .into_any(),
            ),
            Some(InnerSemanticOperation::Cast(op)) => Some(
                Py::new(py, SemanticOperationCast::from_inner(op))
                    .expect("cast operation wrapper allocation should succeed")
                    .into_any(),
            ),
            Some(InnerSemanticOperation::Compare(op)) => Some(
                Py::new(py, SemanticOperationCompare::from_inner(op))
                    .expect("compare operation wrapper allocation should succeed")
                    .into_any(),
            ),
            None => None,
        }
    }

    pub fn left(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().left().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }

    pub fn right(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().right().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }

    pub fn argument(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().argument().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }

    pub fn condition(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().condition().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }

    pub fn when_true(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().when_true().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }

    pub fn when_false(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().when_false().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }

    pub fn address(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().address().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }

    pub fn address_space(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticAddressSpace>>> {
        let space = self.inner.lock().unwrap().address_space().cloned();
        space
            .map(|space| Py::new(py, SemanticAddressSpace::from_inner(space)))
            .transpose()
    }

    pub fn location(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticLocation>>> {
        let location = self.inner.lock().unwrap().location().cloned();
        location
            .map(|location| Py::new(py, SemanticLocation::from_inner(location)))
            .transpose()
    }

    pub fn offset(&self) -> Option<u16> {
        self.inner.lock().unwrap().offset()
    }

    pub fn parts(&self, py: Python<'_>) -> PyResult<Option<Vec<Py<SemanticExpression>>>> {
        self.inner
            .lock()
            .unwrap()
            .parts()
            .map(|parts| {
                parts
                    .iter()
                    .cloned()
                    .map(|part| Py::new(py, SemanticExpression::from_inner(part)))
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

    pub fn arguments(&self, py: Python<'_>) -> PyResult<Option<Vec<Py<SemanticExpression>>>> {
        self.inner
            .lock()
            .unwrap()
            .arguments()
            .map(|arguments| {
                arguments
                    .iter()
                    .cloned()
                    .map(|argument| Py::new(py, SemanticExpression::from_inner(argument)))
                    .collect()
            })
            .transpose()
    }

    pub fn value(&self) -> Option<u128> {
        self.inner.lock().unwrap().value()
    }

    pub fn set_kind(&mut self, py: Python<'_>, kind: Py<SemanticExpressionKind>) {
        self.inner.lock().unwrap().set_kind(kind.borrow(py).inner);
    }

    pub fn set_operation(&mut self, py: Python<'_>, operation: Py<PyAny>) -> PyResult<()> {
        let operation = if let Ok(op) = operation.extract::<Py<SemanticOperationBinary>>(py) {
            InnerSemanticOperation::Binary(op.borrow(py).inner)
        } else if let Ok(op) = operation.extract::<Py<SemanticOperationUnary>>(py) {
            InnerSemanticOperation::Unary(op.borrow(py).inner)
        } else if let Ok(op) = operation.extract::<Py<SemanticOperationCast>>(py) {
            InnerSemanticOperation::Cast(op.borrow(py).inner)
        } else if let Ok(op) = operation.extract::<Py<SemanticOperationCompare>>(py) {
            InnerSemanticOperation::Compare(op.borrow(py).inner)
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

    pub fn set_left(&mut self, py: Python<'_>, expression: Py<SemanticExpression>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_left(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_right(
        &mut self,
        py: Python<'_>,
        expression: Py<SemanticExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_right(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_argument(
        &mut self,
        py: Python<'_>,
        expression: Py<SemanticExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_argument(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_condition(
        &mut self,
        py: Python<'_>,
        expression: Py<SemanticExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_condition(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_when_true(
        &mut self,
        py: Python<'_>,
        expression: Py<SemanticExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_when_true(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_when_false(
        &mut self,
        py: Python<'_>,
        expression: Py<SemanticExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_when_false(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_address(
        &mut self,
        py: Python<'_>,
        expression: Py<SemanticExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_address(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_address_space(
        &mut self,
        py: Python<'_>,
        space: Py<SemanticAddressSpace>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_address_space(space.borrow(py).inner.clone())
            .map_err(PyValueError::new_err)
    }

    pub fn set_location(&mut self, py: Python<'_>, location: Py<SemanticLocation>) -> PyResult<()> {
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

    pub fn set_parts(
        &mut self,
        py: Python<'_>,
        parts: Vec<Py<SemanticExpression>>,
    ) -> PyResult<()> {
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
        arguments: Vec<Py<SemanticExpression>>,
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
impl SemanticEffect {
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
        dst: Py<SemanticLocation>,
        expression: Py<SemanticExpression>,
    ) -> Self {
        Self::from_inner(InnerSemanticEffect::Set {
            dst: dst.borrow(py).inner.lock().unwrap().clone(),
            expression: expression.borrow(py).inner.lock().unwrap().clone(),
        })
    }
    #[classmethod]
    pub fn store(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        space: Py<SemanticAddressSpace>,
        addr: Py<SemanticExpression>,
        expression: Py<SemanticExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticEffect::Store {
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
        reference: Py<SemanticExpression>,
        name: String,
        expression: Py<SemanticExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticEffect::WriteProperty {
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
        reference: Py<SemanticExpression>,
        index: Py<SemanticExpression>,
        expression: Py<SemanticExpression>,
        bits: u16,
    ) -> Self {
        Self::from_inner(InnerSemanticEffect::WriteElement {
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
        expression: Py<SemanticExpression>,
    ) -> Self {
        Self::from_inner(InnerSemanticEffect::Push {
            stack,
            expression: expression.borrow(py).inner.lock().unwrap().clone(),
        })
    }
    #[classmethod]
    pub fn pop(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        stack: String,
        dst: Py<SemanticLocation>,
    ) -> Self {
        Self::from_inner(InnerSemanticEffect::Pop {
            stack,
            dst: dst.borrow(py).inner.lock().unwrap().clone(),
        })
    }
    #[classmethod]
    pub fn fence(_cls: &Bound<'_, PyType>, py: Python<'_>, kind: Py<SemanticFenceKind>) -> Self {
        Self::from_inner(InnerSemanticEffect::Fence {
            kind: kind.borrow(py).inner.clone(),
        })
    }
    #[classmethod]
    pub fn trap(_cls: &Bound<'_, PyType>, py: Python<'_>, kind: Py<SemanticTrapKind>) -> Self {
        Self::from_inner(InnerSemanticEffect::Trap {
            kind: kind.borrow(py).inner.clone(),
        })
    }
    #[classmethod]
    pub fn intrinsic(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        name: String,
        args: Vec<Py<SemanticExpression>>,
        outputs: Vec<Py<SemanticLocation>>,
    ) -> Self {
        let args = args
            .into_iter()
            .map(|arg| arg.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let outputs = outputs
            .into_iter()
            .map(|output| output.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(InnerSemanticEffect::Intrinsic {
            name,
            args,
            outputs,
        })
    }
    #[classmethod]
    pub fn nop(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(InnerSemanticEffect::Nop)
    }
    pub fn kind(&self) -> SemanticEffectKind {
        SemanticEffectKind::from_inner(self.inner.lock().unwrap().kind())
    }
    pub fn expression(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().expression().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }
    pub fn location(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticLocation>>> {
        let location = match &*self.inner.lock().unwrap() {
            InnerSemanticEffect::Set { dst, .. } => Some(dst.clone()),
            InnerSemanticEffect::AtomicCmpXchg { observed, .. } => Some(observed.clone()),
            InnerSemanticEffect::Pop { dst, .. } => Some(dst.clone()),
            _ => None,
        };
        location
            .map(|location| Py::new(py, SemanticLocation::from_inner(location)))
            .transpose()
    }
    pub fn set_kind(&mut self, py: Python<'_>, kind: Py<SemanticEffectKind>) {
        self.inner.lock().unwrap().set_kind(kind.borrow(py).inner);
    }
    pub fn set_expression(
        &mut self,
        py: Python<'_>,
        expression: Py<SemanticExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_expression(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }
    pub fn set_location(&mut self, py: Python<'_>, location: Py<SemanticLocation>) -> PyResult<()> {
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
impl SemanticTerminator {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }
    #[classmethod]
    pub fn fallthrough(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(InnerSemanticTerminator::FallThrough)
    }
    #[classmethod]
    pub fn jump(_cls: &Bound<'_, PyType>, py: Python<'_>, target: Py<SemanticExpression>) -> Self {
        Self::from_inner(InnerSemanticTerminator::Jump {
            target: target.borrow(py).inner.lock().unwrap().clone(),
        })
    }
    #[classmethod]
    pub fn branch(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        condition: Py<SemanticExpression>,
        true_target: Py<SemanticExpression>,
        false_target: Py<SemanticExpression>,
    ) -> Self {
        Self::from_inner(InnerSemanticTerminator::Branch {
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
        target: Py<SemanticExpression>,
        return_target: Option<Py<SemanticExpression>>,
        does_return: Option<bool>,
    ) -> Self {
        Self::from_inner(InnerSemanticTerminator::Call {
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
        expression: Option<Py<SemanticExpression>>,
    ) -> Self {
        Self::from_inner(InnerSemanticTerminator::Return {
            expression: expression.map(|item| item.borrow(py).inner.lock().unwrap().clone()),
        })
    }
    #[classmethod]
    pub fn unreachable(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(InnerSemanticTerminator::Unreachable)
    }
    #[classmethod]
    pub fn trap(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(InnerSemanticTerminator::Trap)
    }
    pub fn kind(&self) -> SemanticTerminatorKind {
        SemanticTerminatorKind::from_inner(self.inner.lock().unwrap().kind())
    }
    pub fn condition(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().condition().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }
    pub fn true_target(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().true_target().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }
    pub fn false_target(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().false_target().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }
    pub fn target(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().target().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }
    pub fn return_target(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().return_target().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }
    pub fn does_return(&self) -> Option<bool> {
        self.inner.lock().unwrap().does_return()
    }
    pub fn return_expression(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticExpression>>> {
        let expression = self.inner.lock().unwrap().return_expression().cloned();
        expression
            .map(|expression| Py::new(py, SemanticExpression::from_inner(expression)))
            .transpose()
    }
    pub fn set_kind(&mut self, py: Python<'_>, kind: Py<SemanticTerminatorKind>) {
        self.inner.lock().unwrap().set_kind(kind.borrow(py).inner);
    }
    pub fn set_condition(
        &mut self,
        py: Python<'_>,
        expression: Py<SemanticExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_condition(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }
    pub fn set_true_target(
        &mut self,
        py: Python<'_>,
        expression: Py<SemanticExpression>,
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
        expression: Py<SemanticExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_false_target(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }
    pub fn set_target(
        &mut self,
        py: Python<'_>,
        expression: Py<SemanticExpression>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_target(expression.borrow(py).inner.lock().unwrap().clone())
            .map_err(PyValueError::new_err)
    }
    pub fn set_return_target(
        &mut self,
        py: Python<'_>,
        expression: Option<Py<SemanticExpression>>,
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
        expression: Option<Py<SemanticExpression>>,
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
impl Semantic {
    #[new]
    #[pyo3(signature = (version, status, abi=None, encoding=None, temporaries=None, effects=None, terminator=None, diagnostics=None))]
    pub fn new(
        py: Python<'_>,
        version: u32,
        status: Py<SemanticStatus>,
        abi: Option<Py<PyAny>>,
        encoding: Option<Py<SemanticEncoding>>,
        temporaries: Option<Vec<Py<SemanticTemporary>>>,
        effects: Option<Vec<Py<SemanticEffect>>>,
        terminator: Option<Py<SemanticTerminator>>,
        diagnostics: Option<Vec<Py<SemanticDiagnostic>>>,
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
            .unwrap_or(InnerSemanticTerminator::FallThrough);
        let diagnostics = diagnostics
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Ok(Self::from_inner(InnerSemantic {
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
    pub fn status(&self) -> SemanticStatus {
        SemanticStatus::from_inner(self.inner.lock().unwrap().status)
    }
    pub fn abi(&self) -> Option<PySemanticAbi> {
        self.inner
            .lock()
            .unwrap()
            .abi
            .clone()
            .map(PySemanticAbi::from_inner)
    }
    pub fn encoding(&self, py: Python<'_>) -> PyResult<Option<Py<SemanticEncoding>>> {
        self.inner
            .lock()
            .unwrap()
            .encoding
            .clone()
            .map(|item| Py::new(py, SemanticEncoding::from_inner(item)))
            .transpose()
    }
    pub fn temporaries(&self, py: Python<'_>) -> PyResult<Vec<Py<SemanticTemporary>>> {
        self.inner
            .lock()
            .unwrap()
            .temporaries
            .iter()
            .cloned()
            .map(|item| Py::new(py, SemanticTemporary::from_inner(item)))
            .collect()
    }
    pub fn effects(&self, py: Python<'_>) -> PyResult<Vec<Py<SemanticEffect>>> {
        self.inner
            .lock()
            .unwrap()
            .effects
            .iter()
            .cloned()
            .map(|item| Py::new(py, SemanticEffect::from_inner(item)))
            .collect()
    }
    pub fn terminator(&self, py: Python<'_>) -> PyResult<Py<SemanticTerminator>> {
        Py::new(
            py,
            SemanticTerminator::from_inner(self.inner.lock().unwrap().terminator.clone()),
        )
    }
    pub fn diagnostics(&self, py: Python<'_>) -> PyResult<Vec<Py<SemanticDiagnostic>>> {
        self.inner
            .lock()
            .unwrap()
            .diagnostics
            .iter()
            .cloned()
            .map(|item| Py::new(py, SemanticDiagnostic::from_inner(item)))
            .collect()
    }
    pub fn set_version(&mut self, version: u32) {
        self.inner.lock().unwrap().set_version(version);
    }
    pub fn set_status(&mut self, py: Python<'_>, status: Py<SemanticStatus>) {
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
    pub fn set_encoding(&mut self, py: Python<'_>, encoding: Option<Py<SemanticEncoding>>) {
        let encoding = encoding.map(|item| item.borrow(py).inner.lock().unwrap().clone());
        self.inner.lock().unwrap().set_encoding(encoding);
    }
    pub fn set_temporaries(&mut self, py: Python<'_>, temporaries: Vec<Py<SemanticTemporary>>) {
        let temporaries = temporaries
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner.lock().unwrap().set_temporaries(temporaries);
    }
    pub fn set_effects(&mut self, py: Python<'_>, effects: Vec<Py<SemanticEffect>>) {
        let effects = effects
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner.lock().unwrap().set_effects(effects);
    }
    pub fn set_terminator(&mut self, py: Python<'_>, terminator: Py<SemanticTerminator>) {
        self.inner
            .lock()
            .unwrap()
            .set_terminator(terminator.borrow(py).inner.lock().unwrap().clone());
    }
    pub fn set_diagnostics(&mut self, py: Python<'_>, diagnostics: Vec<Py<SemanticDiagnostic>>) {
        let diagnostics = diagnostics
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner.lock().unwrap().set_diagnostics(diagnostics);
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
    pub fn __str__(&self) -> PyResult<String> {
        self.json()
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
impl SemanticData {
    #[new]
    pub fn new(name: String, bytes: Vec<u8>) -> Self {
        Self::from_inner(InnerSemanticData { name, bytes })
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
impl Semantics {
    #[new]
    #[pyo3(signature = (semantics=None, data=None))]
    pub fn new(
        py: Python<'_>,
        semantics: Option<Vec<Py<Semantic>>>,
        data: Option<Vec<Py<SemanticData>>>,
    ) -> Self {
        let semantics = semantics
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let data = data
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(InnerSemantics { semantics, data })
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    pub fn semantics(&self, py: Python<'_>) -> PyResult<Vec<Py<Semantic>>> {
        self.inner
            .lock()
            .unwrap()
            .semantics
            .iter()
            .cloned()
            .map(|item| Py::new(py, Semantic::from_inner(item)))
            .collect()
    }

    pub fn data(&self, py: Python<'_>) -> PyResult<Vec<Py<SemanticData>>> {
        self.inner
            .lock()
            .unwrap()
            .data
            .iter()
            .cloned()
            .map(|item| Py::new(py, SemanticData::from_inner(item)))
            .collect()
    }

    pub fn set_semantics(&mut self, py: Python<'_>, semantics: Vec<Py<Semantic>>) {
        let semantics = semantics
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner.lock().unwrap().semantics = semantics;
    }

    pub fn append_semantic(&mut self, py: Python<'_>, semantic: Py<Semantic>) {
        let semantic = semantic.borrow(py).inner.lock().unwrap().clone();
        self.inner.lock().unwrap().semantics.push(semantic);
    }

    pub fn set_data(&mut self, py: Python<'_>, data: Vec<Py<SemanticData>>) {
        let data = data
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner.lock().unwrap().data = data;
    }

    pub fn append_data(&mut self, py: Python<'_>, data: Py<SemanticData>) {
        let data = data.borrow(py).inner.lock().unwrap().clone();
        self.inner.lock().unwrap().data.push(data);
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

#[pymodule]
#[pyo3(name = "semantics")]
pub fn semantics_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    register_abi_classes(m)?;
    m.add_class::<SemanticStatus>()?;
    m.add_class::<SemanticLocationKind>()?;
    m.add_class::<SemanticEffectKind>()?;
    m.add_class::<SemanticExpressionKind>()?;
    m.add_class::<SemanticTerminatorKind>()?;
    m.add_class::<SemanticAddressSpace>()?;
    m.add_class::<SemanticFenceKind>()?;
    m.add_class::<SemanticTrapKind>()?;
    m.add_class::<SemanticOperationUnary>()?;
    m.add_class::<SemanticOperationBinary>()?;
    m.add_class::<SemanticOperationCast>()?;
    m.add_class::<SemanticOperationCompare>()?;
    m.add_class::<SemanticDiagnosticKind>()?;
    m.add_class::<SemanticCpuKind>()?;
    m.add_class::<SemanticCpu>()?;
    m.add_class::<SemanticCpuRegister>()?;
    m.add_class::<SemanticCpuAlias>()?;
    m.add_class::<SemanticCpuProgramCounter>()?;
    m.add_class::<SemanticMemoryIndexed>()?;
    m.add_class::<SemanticMemoryStack>()?;
    m.add_class::<SemanticMemoryAddressed>()?;
    m.add_class::<SemanticCpuEndian>()?;
    m.add_class::<SemanticTemporary>()?;
    m.add_class::<SemanticDiagnostic>()?;
    m.add_class::<SemanticEncoding>()?;
    m.add_class::<SemanticLocation>()?;
    m.add_class::<SemanticExpression>()?;
    m.add_class::<SemanticEffect>()?;
    m.add_class::<SemanticTerminator>()?;
    m.add_class::<Semantic>()?;
    m.add_class::<SemanticData>()?;
    m.add_class::<Semantics>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.semantics", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.semantics")?;
    Ok(())
}
