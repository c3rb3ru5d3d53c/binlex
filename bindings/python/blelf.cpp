#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "blelf.h"
#include <vector>

namespace py = pybind11;

void init_elf(py::module &handle){
  py::class_<binlex::ELF, binlex::File>(handle, "ELF", "Binlex ELF Module")
  .def(py::init<>())
  .def("setup", &binlex::ELF::Setup)
  .def("read_file", &binlex::ELF::ReadFile)
  .def("get_sections", [](binlex::ELF &module){
    auto result = py::list();
    for (int i = 0; i < BINARY_MAX_SECTIONS; i++){
      if (module.sections[i].data != NULL){
        auto dict = py::dict();
        dict["size"] = module.sections[i].size;
        dict["data"] = py::bytes((char *)module.sections[i].data, module.sections[i].size);
        dict["offset"] = module.sections[i].offset;
        dict["functions"] = module.sections[i].functions;
        result.append(dict);
      }
    }
    return result;
  })
  .def("read_buffer", &binlex::ELF::ReadBuffer);
  py::enum_<LIEF::ELF::ARCH>(handle, "ARCH")
  .value("EM_386", LIEF::ELF::ARCH::EM_386)
  .value("EM_X86_64", LIEF::ELF::ARCH::EM_X86_64)
  .value("EM_NONE", LIEF::ELF::ARCH::EM_NONE);
}
