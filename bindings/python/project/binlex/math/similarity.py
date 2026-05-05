"""Similarity and distance helpers."""

from binlex_bindings.binlex.math.similarity import chebyshev as _chebyshev
from binlex_bindings.binlex.math.similarity import cosine as _cosine
from binlex_bindings.binlex.math.similarity import dice as _dice
from binlex_bindings.binlex.math.similarity import dot as _dot
from binlex_bindings.binlex.math.similarity import euclidean as _euclidean
from binlex_bindings.binlex.math.similarity import hamming as _hamming
from binlex_bindings.binlex.math.similarity import jaccard_set as _jaccard_set
from binlex_bindings.binlex.math.similarity import (
    jaccard_signature as _jaccard_signature,
)
from binlex_bindings.binlex.math.similarity import manhattan as _manhattan
from binlex_bindings.binlex.math.similarity import (
    overlap_coefficient as _overlap_coefficient,
)
from binlex_bindings.binlex.math.similarity import pearson as _pearson


def dot(lhs: list[float], rhs: list[float]) -> float:
    return _dot(lhs, rhs)


def cosine(lhs: list[float], rhs: list[float]) -> float:
    return _cosine(lhs, rhs)


def euclidean(lhs: list[float], rhs: list[float]) -> float:
    return _euclidean(lhs, rhs)


def manhattan(lhs: list[float], rhs: list[float]) -> float:
    return _manhattan(lhs, rhs)


def chebyshev(lhs: list[float], rhs: list[float]) -> float:
    return _chebyshev(lhs, rhs)


def hamming(lhs: list[int], rhs: list[int]) -> int:
    return _hamming(lhs, rhs)


def jaccard_signature(lhs: list[int], rhs: list[int]) -> float:
    return _jaccard_signature(lhs, rhs)


def jaccard_set(lhs: list[int], rhs: list[int]) -> float:
    return _jaccard_set(lhs, rhs)


def dice(lhs: list[int], rhs: list[int]) -> float:
    return _dice(lhs, rhs)


def overlap_coefficient(lhs: list[int], rhs: list[int]) -> float:
    return _overlap_coefficient(lhs, rhs)


def pearson(lhs: list[float], rhs: list[float]) -> float:
    return _pearson(lhs, rhs)


__all__ = [
    "chebyshev",
    "cosine",
    "dice",
    "dot",
    "euclidean",
    "hamming",
    "jaccard_set",
    "jaccard_signature",
    "manhattan",
    "overlap_coefficient",
    "pearson",
]
