#!/usr/bin/env python

import re
import sys
from pybind11 import get_cmake_dir
from pybind11.setup_helpers import Pybind11Extension, build_ext
from setuptools import setup
from glob import glob

__version__ = "1.1.1"
__author__ = "@c3rb3ru5d3d53c"

sources = glob('bindings/python/*.cpp')
sources.extend([
    'src/blelf.cpp',
    'src/pe.cpp',
    'src/decompiler.cpp',
    'src/common.cpp',
    'src/raw.cpp',
    'src/sha256.c'
])

ext_modules = [
    Pybind11Extension(
        name="pybinlex",
        sources=sources,
        include_dirs=['include/'],
        language='c++',
        debug=True,
        extra_link_args=[
            '-lLIEF',
            '-lcapstone',
            '-lpthread',
            '-lm'
        ],
        define_macros = [('VERSION_INFO', __version__)],
        ),
]

setup(
    name="pybinlex",
    version=__version__,
    author=__author__,
    maintainer=__author__,
    author_email="c3rb3ru5d3d53c@protonmail.com",
    url="https://github.com/c3rb3ru5d3d53c/binlex",
    description="A Genetic Binary Trait Lexer Library and Utility",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
    zip_safe=False,
    python_requires=">=3.6",
)