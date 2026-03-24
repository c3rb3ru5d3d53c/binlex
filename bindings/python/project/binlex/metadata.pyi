from binlex.formats import File


class Attribute:
    @classmethod
    def from_file(cls, file: File) -> "Attribute": ...
    @classmethod
    def tag(cls, value: str) -> "Attribute": ...
    @classmethod
    def symbol(cls, name: str, symbol_type: "SymbolType", address: int) -> "Attribute": ...
    def json(self) -> str: ...
    def to_dict(self) -> dict[str, object]: ...

class SymbolType:
    Instruction: "SymbolType"
    Block: "SymbolType"
    Function: "SymbolType"


__all__: list[str]
