#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/pytypes.h>
#include <pybind11/eval.h>
#include "disassembler.h"
#include <vector>
#include <sstream>
#include <set>
#include <string>

using namespace std;
namespace py = pybind11;

void init_disassembler(py::module &handle){
    py::class_<binlex::Disassembler>(handle, "Disassembler", "Binlex Disassembler Module")
    .def(py::init<const binlex::File&>())
    .def("set_threads", &binlex::Disassembler::py_SetThreads)
    .def("set_corpus", &binlex::Disassembler::py_SetCorpus)
    .def("set_tags", &binlex::Disassembler::py_SetTags)
    .def("set_mode", &binlex::Disassembler::py_SetMode)
    .def("disassemble", &binlex::Disassembler::Disassemble)
    .def("get_traits", [](binlex::Disassembler &module){
        py::module_ json = py::module_::import("json");
        ostringstream jsonstr;
        jsonstr << module.GetTraits();
        return json.attr("loads")(jsonstr.str());
    })
    .def("append_queue", &binlex::Disassembler::AppendQueue)
    .def("write_traits", &binlex::Disassembler::WriteTraits);
}
