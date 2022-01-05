#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "pe.h"
#include "blelf.h"
#include "common.h"
#include <vector>

namespace py = pybind11;

void init_pe(py::module &handle);
void init_elf(py::module &handle);
void init_common(py::module &handle);
void init_raw(py::module &handle);
void init_decompiler(py::module &handle);

PYBIND11_MODULE(pybinlex, handle){
  handle.doc() = "Binlex - A Binary Genetic Traits Lexer Library and Utility";
  handle.attr("__version__") = "1.1.1";
  init_pe(handle);
  init_elf(handle);
  init_common(handle);
  init_raw(handle);
  init_decompiler(handle);
}
