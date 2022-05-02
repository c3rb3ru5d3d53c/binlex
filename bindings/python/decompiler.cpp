#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/pytypes.h>
#include <pybind11/eval.h>
#include "decompiler.h"
#include <vector>
#include <sstream>
#include <string>

using namespace std;
namespace py = pybind11;

void init_decompiler(py::module &handle){
    py::class_<binlex::Decompiler>(handle, "Decompiler", "Binlex Decompiler Module")
    .def(py::init<>())
    .def("setup", &binlex::Decompiler::Setup)
    .def("set_threads", &binlex::Decompiler::py_SetThreads)
    .def("set_corpus", &binlex::Decompiler::py_SetCorpus)
    .def("set_instructions", &binlex::Decompiler::py_SetInstructions)
    .def("decompile", [](binlex::Decompiler &module, py::buffer data, uint offset, uint index){
        py::buffer_info info = data.request();
        module.Decompile(info.ptr, info.size, offset, index);
    })
    .def("get_traits", [](binlex::Decompiler &module){
        py::module_ json = py::module_::import("json");
        ostringstream jsonstr;
        jsonstr << module.GetTraits();
        return json.attr("loads")(jsonstr.str());
    })
    .def("append_queue", &binlex::Decompiler::AppendQueue)
    .def("write_traits", &binlex::Decompiler::WriteTraits);
    py::enum_<cs_arch>(handle, "cs_arch")
    .value("CS_ARCH_X86", CS_ARCH_X86);
    py::enum_<cs_mode>(handle, "cs_mode")
    .value("CS_MODE_32", CS_MODE_32)
    .value("CS_MODE_64", CS_MODE_64);
}
