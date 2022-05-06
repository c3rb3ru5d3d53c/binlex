#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "pe.h"
#include <vector>

namespace py = pybind11;

void init_pe(py::module &handle){
  py::class_<binlex::File>(handle, "File", "Binlex File (Base)");
  py::class_<binlex::PE, binlex::File>(handle, "PE", "Binlex PE Module")
  .def(py::init<>())
  .def("setup", &binlex::PE::Setup)
  .def("read_file", &binlex::PE::ReadFile)
  .def("get_sections", [](binlex::PE &module){
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
  .def("read_buffer", &binlex::PE::ReadBuffer);
  py::enum_<LIEF::PE::MACHINE_TYPES>(handle, "MACHINE_TYPES")
  .value("IMAGE_FILE_MACHINE_I386", LIEF::PE::MACHINE_TYPES::IMAGE_FILE_MACHINE_I386)
  .value("IMAGE_FILE_MACHINE_AMD64", LIEF::PE::MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64)
  .value("IMAGE_FILE_MACHINE_UNKNOWN", LIEF::PE::MACHINE_TYPES::IMAGE_FILE_MACHINE_UNKNOWN);
}
