#!/usr/bin/env python

import os
import re
import sys
import subprocess
import platform
from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

__version__ = "1.1.1"
__author__ = "@c3rb3ru5d3d53c"

CMAKE_BUILD_ARGS = [
    '-DBUILD_PYTHON_BINDINGS=true',
    '-DPYBIND11_PYTHON_VERSION={version}'.format(
        version=platform.python_version())
]

class CMakeExtension(Extension):
    def __init__(self, name, sources=[]):
        super().__init__(name = name, sources = sources)

class CMakeBuild(build_ext):
    def build_extension(self, ext):
        extdir = os.path.abspath(os.path.dirname(self.get_ext_fullpath(ext.name)))
        if not extdir.endswith(os.path.sep):
            extdir += os.path.sep
        cmake_args = [
            f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={extdir}",
            f"-DPYTHON_EXECUTABLE={sys.executable}",
            "-DCMAKE_BUILD_TYPE=Release",
            '-DBUILD_PYTHON_BINDINGS=true',
            f'-DPYBIND11_PYTHON_VERSION={__version__}'
        ]
        if not os.path.exists(self.build_temp):
            os.makedirs(self.build_temp)
        subprocess.check_call(
            ["cmake", os.path.dirname(os.path.abspath(__file__))] + cmake_args, cwd=self.build_temp
        )
        subprocess.check_call(
            ["cmake", "--build", "."], cwd=self.build_temp
        )

setup(
    name="pybinlex",
    version=__version__,
    author=__author__,
    author_email="c3rb3ru5d3d53c@protonmail.com",
    url="https://github.com/c3rb3ru5d3d53c/binlex",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    ext_modules=[CMakeExtension("pybinlex")],
    cmdclass={
        "build_ext": CMakeBuild
    },
    zip_safe=False,
    python_requires=">=3.6",
)
