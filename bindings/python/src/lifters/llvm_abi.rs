use pyo3::class::basic::CompareOp;
use pyo3::prelude::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum AbiValue {
    SysV,
    Windows64,
    Cdecl,
    Stdcall,
    Fastcall,
    LinuxSyscall,
    WindowsSyscall,
}

fn hash_value<T: Hash>(value: &T) -> isize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() as isize
}

#[pyclass(skip_from_py_object)]
#[derive(Clone, Copy)]
pub struct Abi {
    pub inner: binlex::Abi,
}

impl Abi {
    fn value(&self) -> AbiValue {
        match self.inner {
            binlex::Abi::SysV => AbiValue::SysV,
            binlex::Abi::Windows64 => AbiValue::Windows64,
            binlex::Abi::Cdecl => AbiValue::Cdecl,
            binlex::Abi::Stdcall => AbiValue::Stdcall,
            binlex::Abi::Fastcall => AbiValue::Fastcall,
            binlex::Abi::LinuxSyscall => AbiValue::LinuxSyscall,
            binlex::Abi::WindowsSyscall => AbiValue::WindowsSyscall,
        }
    }
}

#[pymethods]
impl Abi {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const SysV: Self = Self {
        inner: binlex::Abi::SysV,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Windows64: Self = Self {
        inner: binlex::Abi::Windows64,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Cdecl: Self = Self {
        inner: binlex::Abi::Cdecl,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Stdcall: Self = Self {
        inner: binlex::Abi::Stdcall,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Fastcall: Self = Self {
        inner: binlex::Abi::Fastcall,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const LinuxSyscall: Self = Self {
        inner: binlex::Abi::LinuxSyscall,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const WindowsSyscall: Self = Self {
        inner: binlex::Abi::WindowsSyscall,
    };

    pub fn __str__(&self) -> String {
        match self.value() {
            AbiValue::SysV => "SysV".to_string(),
            AbiValue::Windows64 => "Windows64".to_string(),
            AbiValue::Cdecl => "Cdecl".to_string(),
            AbiValue::Stdcall => "Stdcall".to_string(),
            AbiValue::Fastcall => "Fastcall".to_string(),
            AbiValue::LinuxSyscall => "LinuxSyscall".to_string(),
            AbiValue::WindowsSyscall => "WindowsSyscall".to_string(),
        }
    }

    pub fn __hash__(&self) -> isize {
        hash_value(&self.__str__())
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

#[pymodule]
#[pyo3(name = "abi")]
pub fn llvm_abi_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Abi>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.lifters.llvm.abi", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.lifters.llvm.abi")?;
    Ok(())
}
