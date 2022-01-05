#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "common.h"
#include <vector>

namespace py = pybind11;

void init_common(py::module &handle){
    py::class_<binlex::Common>(handle, "Common", "Binlex Common Module")
    .def(py::init<>())
    .def_static("sha256", &binlex::Common::SHA256)
    .def_static("remove_wildcards", &binlex::Common::RemoveWildcards)
    .def_static("get_byte_size", &binlex::Common::GetByteSize)
    .def_static("remove_spaces", &binlex::Common::RemoveSpaces)
    .def_static("wildcard_trait", &binlex::Common::WildcardTrait)
    .def_static("trim_right", &binlex::Common::TrimRight)
    .def_static("wildcards", &binlex::Common::Wildcards)
    .def_static("entropy", &binlex::Common::Entropy)
    .def_static("hexdump_mem_disp", &binlex::Common::HexdumpMemDisp)
    .def_static("hexdump", &binlex::Common::Hexdump)
    .def_static("hexdump_be", &binlex::Common::HexdumpBE);
}