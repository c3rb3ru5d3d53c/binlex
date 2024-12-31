#!/usr/bin/env python

import os
from glob import glob
try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

__author__  = '@c3rb3ru5d3d53c'
__version__ = '2.0.0'

setup(
    name='blserver',
    version=__version__,
    maintainer=__author__,
    description='A Binlex HTTP Server',
    install_requires=open('requirements.txt', 'r').read().splitlines(),
    scripts=['blserver.py'],
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
