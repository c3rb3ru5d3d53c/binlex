#!/usr/bin/env python

import os
try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

__author__  = 'c3r3b3ru5'
__version__ = '1.1.1'

this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='bldb',
    version=__version__,
    maintainer=__author__,
    description='A Binlex MongoDB Database Worker',
    long_description=long_description,
    long_description_content_type='text/markdown',
    install_requires=[
        'pika==1.2.0',
        'pymongo==4.0.1'
    ],
    scripts=['bldb'],
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)