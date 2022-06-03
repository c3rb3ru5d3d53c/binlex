#!/usr/bin/env python

import os
import re
import sys
from shutil import move
from glob import glob
import subprocess
import platform
from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

__version__ = "1.1.1"
__author__ = "@c3rb3ru5d3d53c"

def get_base_prefix_compat():
    return getattr(sys, "base_prefix", None) or getattr(sys, "real_prefix", None) or sys.prefix

def in_virtualenv():
    return get_base_prefix_compat() != sys.prefix

class CMakeExtension(Extension):
    def __init__(self, name, sourcedir=""):
        Extension.__init__(self, name, sources=[])
        self.sourcedir = os.path.abspath(sourcedir)

class CMakeBuild(build_ext):
    def build_extension(self, ext):
        extdir = os.path.abspath(os.path.dirname(self.get_ext_fullpath(ext.name)))
        if not extdir.endswith(os.path.sep):
            extdir += os.path.sep
        debug = int(os.environ.get("DEBUG", 0)) if self.debug is None else self.debug
        cfg = "Debug" if debug else "Release"
        cmake_args = [
            f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={extdir}",
            f"-DPYTHON_EXECUTABLE={sys.executable}",
            f"-DCMAKE_BUILD_TYPE={cfg}",
            '-DBUILD_PYTHON_BINDINGS=ON'
        ]
        build_temp = os.path.join(self.build_temp, ext.name)
        if not os.path.exists(build_temp):
            os.makedirs(build_temp)
        subprocess.check_call(["cmake", "-B", "build", ext.sourcedir] + cmake_args, cwd=build_temp)
        subprocess.check_call(["cmake", "--build", "build", "--config", cfg], cwd=build_temp)
        subprocess.check_call(["cmake", "--install", "build", "--prefix", "build/install", "--config", cfg], cwd=build_temp)

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
