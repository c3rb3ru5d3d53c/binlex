#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "blelf.h"
#include <vector>

namespace py = pybind11;

void init_elf(py::module &handle){
  py::class_<binlex::ELF>(handle, "ELF")
  .def(py::init<>())
  .def("setup", &binlex::ELF::Setup)
  .def("read_file", &binlex::ELF::ReadFile)
  .def("read_buffer", &binlex::ELF::ReadBuffer);
  py::enum_<LIEF::ELF::ARCH>(handle, "ARCH")
  .value("EM_386", LIEF::ELF::ARCH::EM_386)
  .value("EM_X86_64", LIEF::ELF::ARCH::EM_X86_64)
  .value("EM_NONE", LIEF::ELF::ARCH::EM_NONE);
}