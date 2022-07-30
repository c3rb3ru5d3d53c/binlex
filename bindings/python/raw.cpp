#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>
#include <pybind11/pytypes.h>
#include "raw.h"
#include <vector>
#include <array>

using namespace std;
namespace py = pybind11;

void init_raw(py::module &handle){
    py::class_<binlex::Raw, binlex::File>(handle, "Raw", "Binlex Raw Module")
    .def(py::init<>())
    .def("get_sections", [](binlex::Raw &module){
        auto result = py::list();
        for (int i = 0; i < BINARY_MAX_SECTIONS; i++){
            if (module.sections[i].data != NULL){
                auto dict = py::dict();
                dict["size"] = module.sections[i].size;
                dict["data"] = py::bytes((char *)module.sections[i].data, module.sections[i].size);
                dict["offset"] = module.sections[i].offset;
                result.append(dict);
            }
        }
        return result;
    })
    .def("read_file", &binlex::Raw::ReadFile);
}
