#!/usr/bin/env python

import json
import sys
import os
from smda.Disassembler import Disassembler

disassembler = Disassembler()
report = disassembler.disassembleFile(sys.argv[1])
json_report = report.toDict()
