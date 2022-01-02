#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "pe.h"
#include "blelf.h"
#include "common.h"
#include <vector>

namespace py = pybind11;

void init_pe(py::module &handle){
  py::class_<binlex::PE>(handle, "PE")
  .def(py::init<>())
  .def("Setup", &binlex::PE::Setup)
  .def("ReadFile", &binlex::PE::ReadFile)
  .def("ReadBuffer", &binlex::PE::ReadBuffer)
  ;
}

void init_elf(py::module &handle){
  py::class_<binlex::ELF>(handle, "ELF")
  .def(py::init<>())
  .def("Setup", &binlex::ELF::Setup)
  .def("ReadFile", &binlex::ELF::ReadFile)
  .def("ReadBuffer", &binlex::ELF::ReadBuffer)
  ;
}

void init_common(py::module &handle){
    py::class_<binlex::Common>(handle, "Common")
    .def(py::init<>())
    .def_static("SHA256", &binlex::Common::SHA256)
    .def_static("RemoveWildcards", &binlex::Common::RemoveWildcards)
    .def_static("GetByteSize", &binlex::Common::GetByteSize)
    .def_static("RemoveSpaces", &binlex::Common::RemoveSpaces)
    .def_static("WildcardTrait", &binlex::Common::WildcardTrait)
    .def_static("TrimRight", &binlex::Common::TrimRight)
    .def_static("Wildcards", &binlex::Common::Wildcards)
    .def_static("Entropy", &binlex::Common::Entropy)
    .def_static("HexdumpMemDisp", &binlex::Common::HexdumpMemDisp)
    .def_static("Hexdump", &binlex::Common::Hexdump)
    .def_static("HexdumpBE", &binlex::Common::HexdumpBE)
    ;
}

PYBIND11_MODULE(pybinlex, handle){
  handle.doc() = "Binlex - A Binary Genetic Traits Lexer Library and Utility";
  handle.attr("__version__") = "1.1.1";
  init_pe(handle);
  init_elf(handle);
  init_common(handle);
}
