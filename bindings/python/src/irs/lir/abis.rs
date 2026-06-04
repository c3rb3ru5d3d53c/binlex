use super::{LirCpu, LirLocation, LirTrapKind};
use binlex::irs::lir::{
    LirAbi as InnerLirAbi, LirAbiKind as InnerLirAbiKind, LirAbiTrap as InnerLirAbiTrap,
};
use pyo3::exceptions::{PyRuntimeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyModule, PyType};

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct LirAbiKind {
    pub inner: InnerLirAbiKind,
}

#[pymethods]
impl LirAbiKind {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const SysV: Self = Self {
        inner: InnerLirAbiKind::SysV,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Windows64: Self = Self {
        inner: InnerLirAbiKind::Windows64,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Cdecl: Self = Self {
        inner: InnerLirAbiKind::Cdecl,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Stdcall: Self = Self {
        inner: InnerLirAbiKind::Stdcall,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Fastcall: Self = Self {
        inner: InnerLirAbiKind::Fastcall,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const LinuxSyscall: Self = Self {
        inner: InnerLirAbiKind::LinuxSyscall,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const WindowsSyscall: Self = Self {
        inner: InnerLirAbiKind::WindowsSyscall,
    };

    pub fn __str__(&self) -> String {
        match self.inner {
            InnerLirAbiKind::SysV => "SysV".to_string(),
            InnerLirAbiKind::Windows64 => "Windows64".to_string(),
            InnerLirAbiKind::Cdecl => "Cdecl".to_string(),
            InnerLirAbiKind::Stdcall => "Stdcall".to_string(),
            InnerLirAbiKind::Fastcall => "Fastcall".to_string(),
            InnerLirAbiKind::LinuxSyscall => "LinuxSyscall".to_string(),
            InnerLirAbiKind::WindowsSyscall => "WindowsSyscall".to_string(),
        }
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct LirAbiTrap {
    pub inner: InnerLirAbiTrap,
}

impl LirAbiTrap {
    pub fn from_inner(inner: InnerLirAbiTrap) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl LirAbiTrap {
    #[new]
    #[pyo3(signature = (kind, argument_registers=None, number_register=None, result_registers=None, shadow_registers=None))]
    pub fn new(
        py: Python<'_>,
        kind: Py<LirTrapKind>,
        argument_registers: Option<Vec<Py<LirLocation>>>,
        number_register: Option<Py<LirLocation>>,
        result_registers: Option<Vec<Py<LirLocation>>>,
        shadow_registers: Option<Vec<Py<LirLocation>>>,
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
            inner: InnerLirAbiTrap {
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
pub struct LirAbi {
    pub inner: InnerLirAbi,
}

impl LirAbi {
    pub fn from_inner(inner: InnerLirAbi) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl LirAbi {
    #[new]
    #[pyo3(signature = (*, name, cpu, function_arguments=None, return_locations=None, function_return_bits=None, traps=None))]
    pub fn new(
        py: Python<'_>,
        name: String,
        cpu: Py<LirCpu>,
        function_arguments: Option<Vec<Py<LirLocation>>>,
        return_locations: Option<Vec<Py<LirLocation>>>,
        function_return_bits: Option<u16>,
        traps: Option<Vec<Py<LirAbiTrap>>>,
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
            inner: InnerLirAbi::new(
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
        kind: PyRef<'_, LirAbiKind>,
        cpu: Py<LirCpu>,
    ) -> PyResult<Self> {
        let inner = InnerLirAbi::from_kind(kind.inner, &cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn sysv(_cls: &Bound<'_, PyType>, py: Python<'_>, cpu: Py<LirCpu>) -> PyResult<Self> {
        let inner = InnerLirAbi::sysv(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn windows64(_cls: &Bound<'_, PyType>, py: Python<'_>, cpu: Py<LirCpu>) -> PyResult<Self> {
        let inner = InnerLirAbi::windows64(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn cdecl(_cls: &Bound<'_, PyType>, py: Python<'_>, cpu: Py<LirCpu>) -> PyResult<Self> {
        let inner = InnerLirAbi::cdecl(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn stdcall(_cls: &Bound<'_, PyType>, py: Python<'_>, cpu: Py<LirCpu>) -> PyResult<Self> {
        let inner = InnerLirAbi::stdcall(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn fastcall(_cls: &Bound<'_, PyType>, py: Python<'_>, cpu: Py<LirCpu>) -> PyResult<Self> {
        let inner = InnerLirAbi::fastcall(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn linux_syscall(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        cpu: Py<LirCpu>,
    ) -> PyResult<Self> {
        let inner = InnerLirAbi::linux_syscall(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[classmethod]
    pub fn windows_syscall(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        cpu: Py<LirCpu>,
    ) -> PyResult<Self> {
        let inner = InnerLirAbi::windows_syscall(&cpu.borrow(py).inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    pub fn __str__(&self) -> String {
        self.inner.to_string()
    }
}

pub(crate) fn extract_abi(value: &Bound<'_, PyAny>) -> PyResult<InnerLirAbi> {
    if let Ok(abi) = value.extract::<PyRef<'_, LirAbi>>() {
        return Ok(abi.inner.clone());
    }
    if let Ok(inner) = value.getattr("_inner") {
        if let Ok(abi) = inner.extract::<PyRef<'_, LirAbi>>() {
            return Ok(abi.inner.clone());
        }
    }
    Err(PyTypeError::new_err("expected a lir ABI instance"))
}

pub(crate) fn register_abi_classes(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LirAbiKind>()?;
    m.add_class::<LirAbiTrap>()?;
    m.add_class::<LirAbi>()?;
    Ok(())
}
