#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/pytypes.h>
#include "decompiler.h"
#include <vector>

namespace py = pybind11;

void init_decompiler(py::module &handle){
    py::class_<binlex::Decompiler>(handle, "Decompiler", "Binlex Decompiler Module")
    .def(py::init<>())
    .def("setup", &binlex::Decompiler::Setup)
    .def("set_threads", &binlex::Decompiler::SetThreads)
    .def("set_corpus", &binlex::Decompiler::SetCorpus)
    .def("set_instructions", &binlex::Decompiler::SetInstructions)
    .def("decompile", &binlex::Decompiler::Decompile)
    .def("append_queue", &binlex::Decompiler::AppendQueue)
    .def("print_traits", &binlex::Decompiler::PrintTraits)
    .def("write_traits", &binlex::Decompiler::WriteTraits);
    py::enum_<cs_arch>(handle, "cs_arch")
    .value("CS_ARCH_X86", CS_ARCH_X86);
    py::enum_<cs_mode>(handle, "cs_mode")
    .value("CS_MODE_32", CS_MODE_32)
    .value("CS_MODE_64", CS_MODE_64);
}