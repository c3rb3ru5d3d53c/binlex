#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "pe.h"
#include "blelf.h"
#include "common.h"
#include <vector>

namespace py = pybind11;

void init_pe(py::module &handle){
  py::class_<binlex::PE>(handle, "PE")
  .def("Setup", &binlex::PE::Setup)
  .def("ReadFile", &binlex::PE::ReadFile)
  .def("ReadBuffer", &binlex::PE::ReadBuffer)
  ;
}

void init_elf(py::module &handle){
  py::class_<binlex::ELF>(handle, "ELF")
  .def("Setup", &binlex::ELF::Setup)
  .def("ReadFile", &binlex::ELF::ReadFile)
  .def("ReadBuffer", &binlex::ELF::ReadBuffer)
  ;
}

void init_common(py::module &handle){
    py::class_<binlex::Common>(handle, "Common")
    .def("SHA256", &binlex::Common::SHA256)
    .def("RemoveWildcards", &binlex::Common::RemoveWildcards)
    .def("GetByteSize", &binlex::Common::GetByteSize)
    .def("RemoveSpaces", &binlex::Common::RemoveSpaces)
    .def("WildcardTrait", &binlex::Common::WildcardTrait)
    .def("TrimRight", &binlex::Common::TrimRight)
    ;
}

PYBIND11_MODULE(pybinlex, handle){
  handle.doc() = "Binlex Module";
  init_pe(handle);
  init_elf(handle);
  init_common(handle);
}
