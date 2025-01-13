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
