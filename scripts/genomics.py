#!/usr/bin/env python

import re
import argparse
from glob import glob

__author__  = 'c3rb3ru5'
__version__ = '1.0.0'

class Similar():

    """
    Find Similar Binlex Traits
    """

    def __init__(self):
        pass

    def arguments(self):
        self.parser = argparse.ArgumentParser(
            prog=f'similar v{__version__}',
            description='A Binlex Utility to Identify Similar Binary Traits',
            epilog=f'Author: {__author__}'
        )
        self.parser.add_argument(
            '--version',
            action='version',
            version=f'v{__version__}'
        )
        self.parser.add_argument(
            '-i',
            '--input',
            type=str,
            default=None,
            help='Input Directory of Traits',
            required=True
        )
        self.parser.add_argument(
            '-d',
            '--debug',
            action='store_true',
            required=False,
            default=False,
            help='Debug'
        )
        self.parser.add_argument(
            '-t',
            '--threads',
            default=1,
            type=int,
            required=False,
            help='Threads'
        )
        self.parser.add_argument(
            '-r',
            '--recursive',
            action='store_true',
            default=False,
            required=False,
            help='Recursive'
        )
        self.args = self.parser.parse_args()

    def get_files():
        if os.path.isdir(self.args.input):
            return glob(f'{self.args.input}/**', recursive=self.args.recursive)
        return False


    def main(self):
        self.arguments()
        trait_files = self.get_files()

if __name__ in '__main__':
    similar = Similar()
    similar.main()
