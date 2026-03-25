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

"""VEX lifter wrappers for translating code into IR."""

from binlex_bindings.binlex.lifters.vex import Lifter as _LifterBinding
from binlex_bindings.binlex.lifters.vex import LifterJsonDeserializer as _LifterJsonDeserializerBinding

from binlex.core.architecture import Architecture
from binlex.core.architecture import _coerce_architecture


class Lifter:
    """Lift machine code bytes into VEX intermediate representation."""

    def __init__(self, architecture, bytes, address, config):
        """Create a VEX lifter for the supplied bytes and base address."""
        self._inner = _LifterBinding(
            _coerce_architecture(architecture),
            bytes,
            address,
            config,
        )

    def architecture(self):
        """Return the architecture associated with this lift."""
        return Architecture.from_binding(self._inner.architecture())

    def address(self):
        """Return the base virtual address used for lifting."""
        return self._inner.address()

    def bytes(self):
        """Return the original byte sequence that was lifted."""
        return self._inner.bytes()

    def ir(self):
        """Return the lifted VEX IR object."""
        return self._inner.ir()

    def to_dict(self):
        """Serialize the lift into a Python dictionary."""
        return self._inner.to_dict()

    def json(self):
        """Serialize the lift into a JSON string."""
        return self._inner.json()

    def print(self):
        """Print the serialized lift representation to stdout."""
        return self._inner.print()

    def __str__(self):
        """Return the string form of the underlying native lift object."""
        return str(self._inner)


class LifterJsonDeserializer:
    """Rehydrate a VEX lift from its serialized JSON representation."""

    def __init__(self, string, config):
        """Create a deserializer from a serialized VEX lift payload."""
        self._inner = _LifterJsonDeserializerBinding(string, config)

    def architecture(self):
        """Return the architecture described by the serialized lift."""
        return Architecture.from_binding(self._inner.architecture())

    def address(self):
        """Return the base address embedded in the serialized lift."""
        return self._inner.address()

    def bytes(self):
        """Return the original byte sequence stored in the serialized lift."""
        return self._inner.bytes()

    def ir_string(self):
        """Return the serialized intermediate representation as a string."""
        return self._inner.ir_string()

    def ir(self):
        """Return the deserialized VEX IR object."""
        return self._inner.ir()

    def to_dict(self):
        """Deserialize the payload into a Python dictionary."""
        return self._inner.to_dict()

    def json(self):
        """Return the normalized JSON form of the deserialized payload."""
        return self._inner.json()

    def process(self):
        """Materialize the deserialized lift into a processed Python object."""
        return self._inner.process()

    def print(self):
        """Print the deserialized lift representation to stdout."""
        return self._inner.print()

    def __str__(self):
        """Return the string form of the deserialized native object."""
        return str(self._inner)

__all__ = ["Lifter", "LifterJsonDeserializer"]
