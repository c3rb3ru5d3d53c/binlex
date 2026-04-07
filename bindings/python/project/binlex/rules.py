from __future__ import annotations

from pathlib import Path

from binlex_bindings.binlex.rules import CompiledRuleSet as _CompiledRuleSetBinding
from binlex_bindings.binlex.rules import Condition as _ConditionBinding
from binlex_bindings.binlex.rules import Pattern as _PatternBinding
from binlex_bindings.binlex.rules import Rule as _RuleBinding
from binlex_bindings.binlex.rules import YARAMatch as _YARAMatchBinding
from binlex_bindings.binlex.rules import RuleSet as _RuleSetBinding
from binlex_bindings.binlex.rules import YARAScanResults as _YARAScanResultsBinding

_UNSET = object()


class Pattern:
    def __init__(self, binding: _PatternBinding) -> None:
        self._inner = binding

    def get_name(self) -> str:
        return self._inner.get_name()

    def get_pattern(self) -> str:
        return self._inner.get_pattern()

    def get_comment(self) -> str | None:
        return self._inner.get_comment()

    def get_kind(self) -> str:
        return self._inner.get_kind()

    def is_ascii(self) -> bool:
        return self._inner.is_ascii()

    def is_wide(self) -> bool:
        return self._inner.is_wide()


class Condition:
    def __init__(self, binding: _ConditionBinding) -> None:
        self._inner = binding

    def __str__(self) -> str:
        return str(self._inner)


class YARAMatch:
    def __init__(self, binding: _YARAMatchBinding) -> None:
        self._inner = binding

    def rule(self) -> str:
        return self._inner.rule()

    def offset(self) -> int:
        return self._inner.offset()

    def data(self) -> bytes:
        return self._inner.data()

    def size(self) -> int:
        return self._inner.size()


class YARAScanResults:
    def __init__(self, binding: _YARAScanResultsBinding) -> None:
        self._inner = binding

    def get_matches(self) -> list[YARAMatch]:
        return [YARAMatch(binding) for binding in self._inner.get_matches()]

    def __iter__(self):
        return iter(self.get_matches())


class CompiledRuleSet:
    def __init__(self, binding: _CompiledRuleSetBinding) -> None:
        self._inner = binding

    def scan(self, data: bytes) -> YARAScanResults:
        return YARAScanResults(self._inner.scan(data))

    def scan_path(self, path: str | Path) -> YARAScanResults:
        return YARAScanResults(self._inner.scan_path(str(path)))


class Rule:
    def __init__(self, name: str | None = None, comment: str | None = None) -> None:
        self._inner = _RuleBinding(name, comment)

    def get_name(self) -> str:
        return self._inner.get_name()

    def get_comment(self) -> str | None:
        return self._inner.get_comment()

    def add_import(self, value: str) -> "Rule":
        self._inner.add_import(value)
        return self

    def remove_import(self, value: str) -> bool:
        return self._inner.remove_import(value)

    def clear_imports(self) -> "Rule":
        self._inner.clear_imports()
        return self

    def add_tag(self, value: str) -> "Rule":
        self._inner.add_tag(value)
        return self

    def remove_tag(self, value: str) -> bool:
        return self._inner.remove_tag(value)

    def clear_tags(self) -> "Rule":
        self._inner.clear_tags()
        return self

    def set_global(self, value: bool = True) -> "Rule":
        self._inner.set_global(value)
        return self

    def set_private(self, value: bool = True) -> "Rule":
        self._inner.set_private(value)
        return self

    def is_global(self) -> bool:
        return self._inner.is_global()

    def is_private(self) -> bool:
        return self._inner.is_private()

    def set_comment(self, value: str) -> "Rule":
        self._inner.set_comment(value)
        return self

    def clear_comment(self) -> "Rule":
        self._inner.clear_comment()
        return self

    def check(self) -> bool:
        return self._inner.check()

    def set_metadata(self, key: str, value) -> "Rule":
        self._inner.set_metadata(key, value)
        return self

    def remove_metadata(self, key: str) -> bool:
        return self._inner.remove_metadata(key)

    def clear_metadata(self) -> "Rule":
        self._inner.clear_metadata()
        return self

    def get_metadata(self) -> list[tuple[str, str | int | float | bool]]:
        return self._inner.get_metadata()

    def add_pattern(self, pattern: str, comment: str | None = None) -> str:
        return self._inner.add_pattern(pattern, comment)

    def fragment_pattern(self, name: str, parts: int, destructive: bool = True) -> list[str]:
        return self._inner.fragment_pattern(name, parts, destructive)

    def add_text(
        self,
        text: str,
        ascii: bool = True,
        wide: bool = False,
        nocase: bool = False,
        xor: bool = False,
        base64: bool = False,
        base64wide: bool = False,
        fullword: bool = False,
        private: bool = False,
        comment: str | None = None,
    ) -> str:
        return self._inner.add_text(
            text,
            ascii,
            wide,
            nocase,
            xor,
            base64,
            base64wide,
            fullword,
            private,
            comment,
        )

    def add_regex(self, regex: str, comment: str | None = None) -> str:
        return self._inner.add_regex(regex, comment)

    def update_pattern(
        self,
        name: str,
        pattern: str | None = None,
        comment=_UNSET,
    ) -> bool:
        if comment is _UNSET:
            return self._inner.update_pattern(name, pattern, None)
        return self._inner.update_pattern(name, pattern, comment)

    def remove_pattern(self, name: str) -> bool:
        return self._inner.remove_pattern(name)

    def clear_patterns(self) -> "Rule":
        self._inner.clear_patterns()
        return self

    def get_patterns(self) -> list[Pattern]:
        return [Pattern(binding) for binding in self._inner.get_patterns()]

    def condition(self, value: str) -> Condition:
        return Condition(self._inner.condition(value))

    def condition_at_least(self, minimum: int, patterns: list[str]) -> Condition:
        return Condition(self._inner.condition_at_least(minimum, patterns))

    def condition_and(self, *values: Condition) -> Condition:
        return Condition(self._inner.condition_and([value._inner for value in values]))

    def condition_or(self, *values: Condition) -> Condition:
        return Condition(self._inner.condition_or([value._inner for value in values]))

    def condition_not(self, value: Condition) -> Condition:
        return Condition(self._inner.condition_not(value._inner))

    def set_condition(self, value: Condition) -> "Rule":
        self._inner.set_condition(value._inner)
        return self

    def add_condition(self, value: Condition) -> "Rule":
        self._inner.add_condition(value._inner)
        return self

    def clear_condition(self) -> "Rule":
        self._inner.clear_condition()
        return self

    def get_condition(self) -> Condition | None:
        binding = self._inner.get_condition()
        if binding is None:
            return None
        return Condition(binding)

    def add_string(self, value: str, comment: str | None = None) -> str:
        return self._inner.add_string(value, comment)

    def render(self) -> str:
        return self._inner.render()

    def print(self) -> None:
        self._inner.print()

    def write(self, path: str | Path) -> None:
        self._inner.write(str(path))

    def compile(self) -> CompiledRuleSet:
        return CompiledRuleSet(self._inner.compile())

    def scan(self, data: bytes) -> YARAScanResults:
        return YARAScanResults(self._inner.scan(data))

    def scan_path(self, path: str | Path) -> YARAScanResults:
        return YARAScanResults(self._inner.scan_path(str(path)))

    def __str__(self) -> str:
        return self.render()


class RuleSet:
    def __init__(self) -> None:
        self._inner = _RuleSetBinding()

    def add(self, rule: Rule) -> "RuleSet":
        self._inner.add(rule._inner)
        return self

    def remove(self, name: str) -> bool:
        return self._inner.remove(name)

    def clear(self) -> "RuleSet":
        self._inner.clear()
        return self

    def get_rules(self) -> list[Rule]:
        rules: list[Rule] = []
        for binding in self._inner.get_rules():
            rule = Rule.__new__(Rule)
            rule._inner = binding
            rules.append(rule)
        return rules

    def check(self) -> bool:
        return self._inner.check()

    def compile(self) -> CompiledRuleSet:
        return CompiledRuleSet(self._inner.compile())

    def scan(self, data: bytes) -> YARAScanResults:
        return YARAScanResults(self._inner.scan(data))

    def scan_path(self, path: str | Path) -> YARAScanResults:
        return YARAScanResults(self._inner.scan_path(str(path)))

YARA = RuleSet
YARACondition = Condition
YARARule = Rule
YARAPattern = Pattern
YARACompiledRuleSet = CompiledRuleSet

__all__ = [
    "CompiledRuleSet",
    "Condition",
    "Pattern",
    "Rule",
    "RuleSet",
    "YARA",
    "YARACondition",
    "YARARule",
    "YARAPattern",
    "YARAMatch",
    "YARAScanResults",
    "YARACompiledRuleSet",
]
