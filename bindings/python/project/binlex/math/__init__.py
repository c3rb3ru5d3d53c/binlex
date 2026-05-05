"""Math helpers exposed by the binlex Python bindings."""

from . import entropy, similarity, stats
from .entropy import shannon
from .similarity import chebyshev
from .similarity import cosine
from .similarity import dice
from .similarity import dot
from .similarity import euclidean
from .similarity import hamming
from .similarity import jaccard_set
from .similarity import jaccard_signature
from .similarity import manhattan
from .similarity import overlap_coefficient
from .similarity import pearson
from .stats import downsample_vector
from .stats import max_or_zero
from .stats import mean
from .stats import normalize_l2
from .stats import weighted_histogram
from .stats import weighted_mean

__all__ = [
    "chebyshev",
    "cosine",
    "dice",
    "dot",
    "downsample_vector",
    "entropy",
    "euclidean",
    "hamming",
    "jaccard_set",
    "jaccard_signature",
    "manhattan",
    "max_or_zero",
    "mean",
    "normalize_l2",
    "overlap_coefficient",
    "pearson",
    "shannon",
    "similarity",
    "stats",
    "weighted_histogram",
    "weighted_mean",
]
