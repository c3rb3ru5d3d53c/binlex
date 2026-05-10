use super::{SemanticCpu, SemanticLocation, SemanticTrapKind};
use binlex::semantics::{
    SemanticAbi as InnerSemanticAbi, SemanticAbiKind as InnerSemanticAbiKind,
    SemanticAbiTrap as InnerSemanticAbiTrap,
};
use pyo3::exceptions::{PyRuntimeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyModule, PyType};

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SemanticAbiKind {
    pub inner: InnerSemanticAbiKind,
}

#[pymethods]
impl SemanticAbiKind {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const SysV: Self = Self {
        inner: InnerSemanticAbiKind::SysV,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Windows64: Self = Self {
        inner: InnerSemanticAbiKind::Windows64,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Cdecl: Self = Self {
        inner: InnerSemanticAbiKind::Cdecl,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Stdcall: Self = Self {
        inner: InnerSemanticAbiKind::Stdcall,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Fastcall: Self = Self {
        inner: InnerSemanticAbiKind::Fastcall,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const LinuxSyscall: Self = Self {
        inner: InnerSemanticAbiKind::LinuxSyscall,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const WindowsSyscall: Self = Self {
        inner: InnerSemanticAbiKind::WindowsSyscall,
    };

    pub fn __str__(&self) -> String {
        match self.inner {
            InnerSemanticAbiKind::SysV => "SysV".to_string(),
            InnerSemanticAbiKind::Windows64 => "Windows64".to_string(),
            InnerSemanticAbiKind::Cdecl => "Cdecl".to_string(),
            InnerSemanticAbiKind::Stdcall => "Stdcall".to_string(),
            InnerSemanticAbiKind::Fastcall => "Fastcall".to_string(),
            InnerSemanticAbiKind::LinuxSyscall => "LinuxSyscall".to_string(),
            InnerSemanticAbiKind::WindowsSyscall => "WindowsSyscall".to_string(),
        }
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SemanticAbiTrap {
    pub inner: InnerSemanticAbiTrap,
}

impl SemanticAbiTrap {
    pub fn from_inner(inner: InnerSemanticAbiTrap) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl SemanticAbiTrap {
    #[new]
    #[pyo3(signature = (kind, argument_registers=None, number_register=None, result_registers=None, shadow_registers=None))]
    pub fn new(
        py: Python<'_>,
        kind: Py<SemanticTrapKind>,
        argument_registers: Option<Vec<Py<SemanticLocation>>>,
        number_register: Option<Py<SemanticLocation>>,
        result_registers: Option<Vec<Py<SemanticLocation>>>,
        shadow_registers: Option<Vec<Py<SemanticLocation>>>,
    ) -> Self {
        let argument_registers = argument_registers
            .unwrap_or_default()
            .into_iter()
            .map(|location| location.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let number_register =
            number_register.map(|location| location.borrow(py).inner.lock().unwrap().clone());
        let result_registers = result_registers
            .unwrap_or_default()
            .into_iter()
            .map(|location| location.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let shadow_registers = shadow_registers
            .unwrap_or_default()
            .into_iter()
            .map(|location| location.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self {
            inner: InnerSemanticAbiTrap {
                kind: kind.borrow(py).inner.clone(),
                argument_registers,
                number_register,
                result_registers,
                shadow_registers,
            },
        }
    }

    pub fn __str__(&self) -> String {
        format!("{:?}", self.inner.kind)
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SemanticAbi {
    pub inner: InnerSemanticAbi,
}

impl SemanticAbi {
    pub fn from_inner(inner: InnerSemanticAbi) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl SemanticAbi {
    #[new]
    #[pyo3(signature = (*, name, cpu, function_arguments=None, return_locations=None, function_return_bits=None, traps=None))]
    pub fn new(
        py: Python<'_>,
        name: String,
        cpu: Py<SemanticCpu>,
        function_arguments: Option<Vec<Py<SemanticLocation>>>,
        return_locations: Option<Vec<Py<SemanticLocation>>>,
        function_return_bits: Option<u16>,
        traps: Option<Vec<Py<SemanticAbiTrap>>>,
    ) -> PyResult<Self> {
        let cpu_inner = cpu.borrow(py).inner.clone();
        let function_arguments = function_arguments
            .unwrap_or_default()
            .into_iter()
            .map(|location| location.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let return_locations = return_locations
            .unwrap_or_default()
            .into_iter()
            .map(|location| location.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let traps = traps
            .unwrap_or_default()
            .into_iter()
            .map(|trap| trap.borrow(py).inner.clone())
            .collect();
        Ok(Self {
            inner: InnerSemanticAbi::new(
                name,
                cpu_inner,
                function_arguments,
                return_locations,
                function_return_bits,
                traps,
            ),
        })
    }

    #[classmethod]
    pub fn from_kind(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        kind: PyRef<'_, SemanticAbiKind>,
        cpu: Py<SemanticCpu>,
    ) -> PyResult<Self> {
        let inner = InnerSemanticAbi::from_kind(kind.inner, &cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn sysv(_cls: &Bound<'_, PyType>, py: Python<'_>, cpu: Py<SemanticCpu>) -> PyResult<Self> {
        let inner = InnerSemanticAbi::sysv(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn windows64(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        cpu: Py<SemanticCpu>,
    ) -> PyResult<Self> {
        let inner = InnerSemanticAbi::windows64(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn cdecl(_cls: &Bound<'_, PyType>, py: Python<'_>, cpu: Py<SemanticCpu>) -> PyResult<Self> {
        let inner = InnerSemanticAbi::cdecl(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn stdcall(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        cpu: Py<SemanticCpu>,
    ) -> PyResult<Self> {
        let inner = InnerSemanticAbi::stdcall(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn fastcall(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        cpu: Py<SemanticCpu>,
    ) -> PyResult<Self> {
        let inner = InnerSemanticAbi::fastcall(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn linux_syscall(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        cpu: Py<SemanticCpu>,
    ) -> PyResult<Self> {
        let inner = InnerSemanticAbi::linux_syscall(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn windows_syscall(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        cpu: Py<SemanticCpu>,
    ) -> PyResult<Self> {
        let inner = InnerSemanticAbi::windows_syscall(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    pub fn __str__(&self) -> String {
        self.inner.to_string()
    }
}

pub(crate) fn extract_abi(value: &Bound<'_, PyAny>) -> PyResult<InnerSemanticAbi> {
    if let Ok(abi) = value.extract::<PyRef<'_, SemanticAbi>>() {
        return Ok(abi.inner.clone());
    }
    if let Ok(inner) = value.getattr("_inner") {
        if let Ok(abi) = inner.extract::<PyRef<'_, SemanticAbi>>() {
            return Ok(abi.inner.clone());
        }
    }
    Err(PyTypeError::new_err("expected a semantic ABI instance"))
}

pub(crate) fn register_abi_classes(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SemanticAbiKind>()?;
    m.add_class::<SemanticAbiTrap>()?;
    m.add_class::<SemanticAbi>()?;
    Ok(())
}
