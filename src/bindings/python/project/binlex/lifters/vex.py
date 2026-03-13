# MIT License
#
# Copyright (c) [2025] [c3rb3ru5d3d53c]
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from binlex_bindings.binlex.lifters.vex import Lifter as _LifterBinding
from binlex_bindings.binlex.lifters.vex import LifterJsonDeserializer as _LifterJsonDeserializerBinding

from binlex.architecture import Architecture
from binlex.architecture import _coerce_architecture


class Lifter:
    def __init__(self, architecture, bytes, address, config):
        self._inner = _LifterBinding(
            _coerce_architecture(architecture),
            bytes,
            address,
            config,
        )

    def architecture(self):
        return Architecture.from_binding(self._inner.architecture())

    def address(self):
        return self._inner.address()

    def bytes(self):
        return self._inner.bytes()

    def ir(self):
        return self._inner.ir()

    def to_dict(self):
        return self._inner.to_dict()

    def json(self):
        return self._inner.json()

    def print(self):
        return self._inner.print()

    def __str__(self):
        return str(self._inner)


class LifterJsonDeserializer:
    def __init__(self, string, config):
        self._inner = _LifterJsonDeserializerBinding(string, config)

    def architecture(self):
        return Architecture.from_binding(self._inner.architecture())

    def address(self):
        return self._inner.address()

    def bytes(self):
        return self._inner.bytes()

    def ir_string(self):
        return self._inner.ir_string()

    def ir(self):
        return self._inner.ir()

    def to_dict(self):
        return self._inner.to_dict()

    def json(self):
        return self._inner.json()

    def process(self):
        return self._inner.process()

    def print(self):
        return self._inner.print()

    def __str__(self):
        return str(self._inner)

__all__ = ["Lifter", "LifterJsonDeserializer"]
