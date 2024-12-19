#!/usr/bin/env python

# Example on Finding common sub sequences

import sys
import json
from binlex.genetics import Chromosome
from binlex import Config

config = Config()

config.chromosomes.homologues.maximum = 2

lhs = Chromosome('deadbeef', config)
rhs = Chromosome('fedeadbeeffe', config)

delta = lhs.compare(rhs)

print(json.dumps(json.loads(delta.json())))
