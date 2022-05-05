#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "file.h"
#include <vector>

namespace py = pybind11;

void init_file(py::module &handle){
  py::class_<binlex::File>(handle, "File", "Binlex File (Base) Module");
}
