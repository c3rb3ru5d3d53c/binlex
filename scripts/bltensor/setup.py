#!/usr/bin/env python

from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='bltensor',
    version='2.0.0',
    author='@c3rb3ru5d3d53c',
    description='A Binlex Tensorflow Tool',
    long_description=long_description,
    long_description_content_type='text/markdown',
    scripts=['scripts/bltensor'],
    install_requires=requirements,
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
