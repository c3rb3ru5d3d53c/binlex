#!/usr/bin/env python

import sys
from binlex import Configuration
from binlex.formats import PE
from binlex.disassemblers import Disassembler
from binlex.controlflow import Graph, Function
from binlex.math.similarity import cosine


# replace this with your own function.embedding()
VECTOR = []


def get_target_function_score(function: Function) -> float:
    embedding = function.embedding()
    if not embedding:
        return 0.0
    return cosine(
        VECTOR,
        embedding,
    )


def get_target_function(
    graph: Graph,
    threshold: float,
) -> Function | None:
    best_func = None
    best_score = threshold

    for f in graph.functions():
        score = get_target_function_score(f)
        if score >= best_score:
            best_func = f
            best_score = score

    return best_func


configuration = Configuration()

pe = PE(open(sys.argv[1], "rb").read(), configuration)

graph = Graph(pe.architecture(), configuration)

disassembler = Disassembler(
    pe.architecture(), pe.image(), pe.executable_virtual_address_ranges(), configuration
)

disassembler.disassemble(pe.entrypoint_virtual_addresses(), graph)

function = get_target_function(graph, threshold=0.85)

assert function, "failed to find function"

print(hex(function.address()))
