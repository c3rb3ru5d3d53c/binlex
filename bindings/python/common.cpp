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
    .def_static("hexdump", &binlex::Common::Hexdump)
    .def_static("hexdump_be", &binlex::Common::HexdumpBE);
    py::enum_<BINARY_ARCH>(handle, "BINARY_ARCH")
    .value("BINARY_ARCH_X86", BINARY_ARCH_X86)
    .value("BINARY_ARCH_X86_64", BINARY_ARCH_X86_64)
    .value("BINARY_ARCH_UNKNOWN", BINARY_ARCH_UNKNOWN);
    py::enum_<BINARY_MODE>(handle, "BINARY_MODE")
    .value("BINARY_MODE_32", BINARY_MODE_32)
    .value("BINARY_MODE_64", BINARY_MODE_64)
    .value("BINARY_MODE_CIL", BINARY_MODE_CIL)
    .value("BINARY_MODE_UNKNOWN", BINARY_MODE_UNKNOWN);
}
