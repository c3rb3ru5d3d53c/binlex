from __future__ import annotations

from enum import Enum

class Architecture(str, Enum):
    AMD64: Architecture
    I386: Architecture
    ARM64: Architecture
    CIL: Architecture

__all__ = ["Architecture"]
