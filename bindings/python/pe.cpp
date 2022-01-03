#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "pe.h"
#include <vector>

namespace py = pybind11;

void init_pe(py::module &handle){
  py::class_<binlex::PE>(handle, "PE")
  .def(py::init<>())
  .def("setup", &binlex::PE::Setup)
  .def("read_file", &binlex::PE::ReadFile)
  .def("read_buffer", &binlex::PE::ReadBuffer);
  py::enum_<LIEF::PE::MACHINE_TYPES>(handle, "MACHINE_TYPES")
  .value("IMAGE_FILE_MACHINE_I386", LIEF::PE::MACHINE_TYPES::IMAGE_FILE_MACHINE_I386)
  .value("IMAGE_FILE_MACHINE_AMD64", LIEF::PE::MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64)
  .value("IMAGE_FILE_MACHINE_UNKNOWN", LIEF::PE::MACHINE_TYPES::IMAGE_FILE_MACHINE_UNKNOWN);
}