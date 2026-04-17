use ::binlex::semantics::{
    InstructionSemantics as InnerInstructionSemantics, SemanticAddressSpace as InnerAddressSpace,
    SemanticDiagnostic as InnerSemanticDiagnostic,
    SemanticDiagnosticKind as InnerSemanticDiagnosticKind, SemanticEffect as InnerSemanticEffect,
    SemanticEffectKind as InnerSemanticEffectKind, SemanticExpression as InnerSemanticExpr,
    SemanticExpressionKind as InnerSemanticExprKind, SemanticFenceKind as InnerFenceKind,
    SemanticLocation as InnerSemanticLocation, SemanticLocationKind as InnerSemanticLocationKind,
    SemanticOperationBinary as InnerSemanticBinaryOp, SemanticOperationCast as InnerSemanticCastOp,
    SemanticOperationCompare as InnerSemanticCompareOp,
    SemanticOperationUnary as InnerSemanticUnaryOp, SemanticStatus as InnerSemanticStatus,
    SemanticTemporary as InnerSemanticTemporary, SemanticTerminator as InnerSemanticTerminator,
    SemanticTerminatorKind as InnerSemanticTerminatorKind, SemanticTrapKind as InnerTrapKind,
};
use pyo3::class::basic::CompareOp;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyModule, PyType};
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
    { Set, Store, Fence, Trap, Intrinsic, Nop }
);
simple_enum_binding!(
    SemanticExpressionKind,
    InnerSemanticExprKind,
    {
        Const,
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
        Intrinsic
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
    pub fn segment(name: String) -> Self {
        Self {
            inner: InnerAddressSpace::Segment { name },
        }
    }

    #[staticmethod]
    pub fn arch_specific(name: String) -> Self {
        Self {
            inner: InnerAddressSpace::ArchSpecific { name },
        }
    }

    pub fn __str__(&self) -> String {
        match &self.inner {
            InnerAddressSpace::Default => "Default".to_string(),
            InnerAddressSpace::Stack => "Stack".to_string(),
            InnerAddressSpace::Heap => "Heap".to_string(),
            InnerAddressSpace::Global => "Global".to_string(),
            InnerAddressSpace::Io => "Io".to_string(),
            InnerAddressSpace::Segment { name } => format!("Segment({})", name),
            InnerAddressSpace::ArchSpecific { name } => format!("ArchSpecific({})", name),
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
    pub fn arch_specific(name: String) -> Self {
        Self {
            inner: InnerFenceKind::ArchSpecific { name },
        }
    }

    pub fn __str__(&self) -> String {
        match &self.inner {
            InnerFenceKind::Acquire => "Acquire".to_string(),
            InnerFenceKind::Release => "Release".to_string(),
            InnerFenceKind::AcquireRelease => "AcquireRelease".to_string(),
            InnerFenceKind::SequentiallyConsistent => "SequentiallyConsistent".to_string(),
            InnerFenceKind::ArchSpecific { name } => format!("ArchSpecific({})", name),
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
    pub fn arch_specific(name: String) -> Self {
        Self {
            inner: InnerTrapKind::ArchSpecific { name },
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
            InnerTrapKind::ArchSpecific { name } => format!("ArchSpecific({})", name),
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
    pub fn arch_specific(name: String) -> Self {
        Self {
            inner: InnerSemanticDiagnosticKind::ArchSpecific { name },
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
            InnerSemanticDiagnosticKind::ArchSpecific { name } => format!("ArchSpecific({})", name),
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
value_wrapper!(SemanticDiagnostic, InnerSemanticDiagnostic);
value_wrapper!(SemanticLocation, InnerSemanticLocation);
value_wrapper!(SemanticExpression, InnerSemanticExpr);
value_wrapper!(SemanticEffect, InnerSemanticEffect);
value_wrapper!(SemanticTerminator, InnerSemanticTerminator);
value_wrapper!(InstructionSemantics, InnerInstructionSemantics);

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
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&*self.inner.lock().unwrap())
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
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&*self.inner.lock().unwrap())
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
    pub fn kind(&self) -> SemanticLocationKind {
        SemanticLocationKind::from_inner(self.inner.lock().unwrap().kind())
    }
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&*self.inner.lock().unwrap())
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
    pub fn kind(&self) -> SemanticExpressionKind {
        SemanticExpressionKind::from_inner(self.inner.lock().unwrap().kind())
    }
    pub fn binary_operation(&self) -> Option<SemanticOperationBinary> {
        self.inner
            .lock()
            .unwrap()
            .binary_operation()
            .map(SemanticOperationBinary::from_inner)
    }
    pub fn unary_operation(&self) -> Option<SemanticOperationUnary> {
        self.inner
            .lock()
            .unwrap()
            .unary_operation()
            .map(SemanticOperationUnary::from_inner)
    }
    pub fn cast_operation(&self) -> Option<SemanticOperationCast> {
        self.inner
            .lock()
            .unwrap()
            .cast_operation()
            .map(SemanticOperationCast::from_inner)
    }
    pub fn compare_operation(&self) -> Option<SemanticOperationCompare> {
        self.inner
            .lock()
            .unwrap()
            .compare_operation()
            .map(SemanticOperationCompare::from_inner)
    }
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&*self.inner.lock().unwrap())
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
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&*self.inner.lock().unwrap())
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
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&*self.inner.lock().unwrap())
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
impl InstructionSemantics {
    #[new]
    #[pyo3(signature = (version, status, temporaries=None, effects=None, terminator=None, diagnostics=None))]
    pub fn new(
        py: Python<'_>,
        version: u32,
        status: Py<SemanticStatus>,
        temporaries: Option<Vec<Py<SemanticTemporary>>>,
        effects: Option<Vec<Py<SemanticEffect>>>,
        terminator: Option<Py<SemanticTerminator>>,
        diagnostics: Option<Vec<Py<SemanticDiagnostic>>>,
    ) -> Self {
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
        Self::from_inner(InnerInstructionSemantics {
            version,
            status: status.borrow(py).inner,
            temporaries,
            effects,
            terminator,
            diagnostics,
        })
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
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        )
    }
    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&*self.inner.lock().unwrap())
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

#[pymodule]
#[pyo3(name = "semantics")]
pub fn semantics_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
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
    m.add_class::<SemanticTemporary>()?;
    m.add_class::<SemanticDiagnostic>()?;
    m.add_class::<SemanticLocation>()?;
    m.add_class::<SemanticExpression>()?;
    m.add_class::<SemanticEffect>()?;
    m.add_class::<SemanticTerminator>()?;
    m.add_class::<InstructionSemantics>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.semantics", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.semantics")?;
    Ok(())
}
