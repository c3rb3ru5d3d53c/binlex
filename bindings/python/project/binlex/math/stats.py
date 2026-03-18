from binlex_bindings.binlex.math import downsample_vector as _downsample_vector
from binlex_bindings.binlex.math import max_or_zero as _max_or_zero
from binlex_bindings.binlex.math import mean as _mean
from binlex_bindings.binlex.math import normalize_l2 as _normalize_l2
from binlex_bindings.binlex.math import weighted_histogram as _weighted_histogram
from binlex_bindings.binlex.math import weighted_mean as _weighted_mean


def normalize_l2(values):
    return _normalize_l2(values)


def mean(values):
    return _mean(values)


def max_or_zero(values):
    return _max_or_zero(values)


def weighted_mean(values, weights):
    return _weighted_mean(values, weights)


def weighted_histogram(values, weights, buckets, scale):
    return _weighted_histogram(values, weights, buckets, scale)


def downsample_vector(values, dimensions):
    return _downsample_vector(values, dimensions)


__all__ = [
    "downsample_vector",
    "max_or_zero",
    "mean",
    "normalize_l2",
    "weighted_histogram",
    "weighted_mean",
]
