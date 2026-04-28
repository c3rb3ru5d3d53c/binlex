from __future__ import annotations

class Abi:
    SysV: Abi
    Windows64: Abi
    Cdecl: Abi
    Stdcall: Abi
    Fastcall: Abi
    LinuxSyscall: Abi
    WindowsSyscall: Abi

__all__: list[str]
