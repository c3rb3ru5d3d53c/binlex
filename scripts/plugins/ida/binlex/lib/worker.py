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

import inspect
from typing import Callable
from dataclasses import field, dataclass
from threading import Thread
import ida_kernwin

@dataclass(unsafe_hash=True)
class Worker(Thread):
    target: Callable
    args: tuple = field(default_factory=tuple, compare=False)
    done_callback: Callable = None
    error_callback: Callable = None

    def __post_init__(self):
        super().__init__(target=self.__wrapped_target, args=self.args, daemon=True)

    def __wrapped_target(self, *args, **kwargs):
        try:
            results = self.target(*args, **kwargs)

            if self.done_callback is not None:
                def call_done_callback():
                    argument_spec = inspect.getfullargspec(self.done_callback)
                    argument_count = len(argument_spec.args)
                    if argument_count > 1:
                        self.done_callback(*results)
                    elif argument_count == 1 and results is not None:
                        self.done_callback(results)
                    else:
                        self.done_callback()

                ida_kernwin.execute_sync(call_done_callback, ida_kernwin.MFF_FAST)
        except Exception as exception:
            if self.error_callback is not None:
                def call_error_callback():
                    argument_spec = inspect.getfullargspec(self.error_callback)
                    argument_count = len(argument_spec.args)
                    if argument_count == 1:
                        self.error_callback(exception)
                    else:
                        self.error_callback()

                ida_kernwin.execute_sync(call_error_callback, ida_kernwin.MFF_FAST)
            else:
                raise exception
        finally:
            if self.done_callback is not None:
                del self.done_callback
            if self.error_callback is not None:
                del self.error_callback
