from __future__ import annotations

from pathlib import Path

from binlex_bindings.binlex.yara import CompiledRuleSet as _CompiledRuleSetBinding
from binlex_bindings.binlex.yara import Pattern as _PatternBinding
from binlex_bindings.binlex.yara import Rule as _RuleBinding
from binlex_bindings.binlex.yara import RuleMatch as _RuleMatchBinding
from binlex_bindings.binlex.yara import RuleSet as _RuleSetBinding
from binlex_bindings.binlex.yara import ScanResults as _ScanResultsBinding

_UNSET = object()


class Pattern:
    def __init__(self, binding: _PatternBinding) -> None:
        self._inner = binding

    def name(self) -> str:
        return self._inner.name()

    def pattern(self) -> str:
        return self._inner.pattern()

    def comment(self) -> str | None:
        return self._inner.comment()

    def kind(self) -> str:
        return self._inner.kind()

    def ascii(self) -> bool:
        return self._inner.ascii()

    def wide(self) -> bool:
        return self._inner.wide()


class RuleMatch:
    def __init__(self, binding: _RuleMatchBinding) -> None:
        self._inner = binding

    def rule(self) -> str:
        return self._inner.rule()

    def offset(self) -> int:
        return self._inner.offset()

    def data(self) -> bytes:
        return self._inner.data()

    def size(self) -> int:
        return self._inner.size()


class ScanResults:
    def __init__(self, binding: _ScanResultsBinding) -> None:
        self._inner = binding

    def matches(self) -> list[RuleMatch]:
        return [RuleMatch(binding) for binding in self._inner.matches()]

    def __iter__(self):
        return iter(self.matches())


class CompiledRuleSet:
    def __init__(self, binding: _CompiledRuleSetBinding) -> None:
        self._inner = binding

    def scan(self, data: bytes) -> ScanResults:
        return ScanResults(self._inner.scan(data))

    def scan_file(self, path: str | Path) -> ScanResults:
        return ScanResults(self._inner.scan_file(str(path)))


class Rule:
    def __init__(self, name: str | None = None, comment: str | None = None) -> None:
        self._inner = _RuleBinding(name, comment)

    def name(self) -> str:
        return self._inner.name()

    def comment(self) -> str | None:
        return self._inner.comment()

    def comment_set(self, value: str) -> "Rule":
        self._inner.comment_set(value)
        return self

    def comment_clear(self) -> "Rule":
        self._inner.comment_clear()
        return self

    def check(self) -> bool:
        return self._inner.check()

    def meta(self, key: str, value) -> "Rule":
        self._inner.meta(key, value)
        return self

    def meta_set(self, key: str, value) -> "Rule":
        self._inner.meta_set(key, value)
        return self

    def meta_remove(self, key: str) -> bool:
        return self._inner.meta_remove(key)

    def meta_clear(self) -> "Rule":
        self._inner.meta_clear()
        return self

    def metadata(self) -> list[tuple[str, str | int | float | bool]]:
        return self._inner.metadata()

    def pattern(self, pattern: str, comment: str | None = None) -> "Rule":
        self._inner.pattern(pattern, comment)
        return self

    def pattern_add(self, pattern: str, comment: str | None = None) -> str:
        return self._inner.pattern_add(pattern, comment)

    def text_add(
        self,
        text: str,
        ascii: bool = True,
        wide: bool = False,
        comment: str | None = None,
    ) -> str:
        return self._inner.text_add(text, ascii, wide, comment)

    def regex_add(self, regex: str, comment: str | None = None) -> str:
        return self._inner.regex_add(regex, comment)

    def pattern_update(
        self,
        name: str,
        pattern: str | None = None,
        comment=_UNSET,
    ) -> bool:
        if comment is _UNSET:
            return self._inner.pattern_update(name, pattern, None)
        return self._inner.pattern_update(name, pattern, comment)

    def remove(self, name: str) -> bool:
        return self._inner.remove(name)

    def pattern_clear(self) -> "Rule":
        self._inner.pattern_clear()
        return self

    def patterns(self) -> list[Pattern]:
        return [Pattern(binding) for binding in self._inner.patterns()]

    def condition(self, value: str) -> "Rule":
        self._inner.condition(value)
        return self

    def condition_clear(self) -> "Rule":
        self._inner.condition_clear()
        return self

    def condition_value(self) -> str | None:
        return self._inner.condition_value()

    def condition_all_of_them(self) -> "Rule":
        self._inner.condition_all_of_them()
        return self

    def condition_number_of_them(self, n: int) -> "Rule":
        self._inner.condition_number_of_them(n)
        return self

    def condition_any_of(self, names: list[str]) -> "Rule":
        self._inner.condition_any_of(names)
        return self

    def condition_all_of(self, names: list[str]) -> "Rule":
        self._inner.condition_all_of(names)
        return self

    def condition_at_least(self, n: int, names: list[str]) -> "Rule":
        self._inner.condition_at_least(n, names)
        return self

    def string_add(self, value: str, comment: str | None = None) -> str:
        return self._inner.string_add(value, comment)

    def render(self) -> str:
        return self._inner.render()

    def print(self) -> None:
        self._inner.print()

    def write(self, path: str | Path) -> None:
        self._inner.write(str(path))

    def compile(self) -> CompiledRuleSet:
        return CompiledRuleSet(self._inner.compile())

    def scan(self, data: bytes) -> ScanResults:
        return ScanResults(self._inner.scan(data))

    def scan_file(self, path: str | Path) -> ScanResults:
        return ScanResults(self._inner.scan_file(str(path)))

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

    def rules(self) -> list[Rule]:
        rules: list[Rule] = []
        for binding in self._inner.rules():
            rule = Rule.__new__(Rule)
            rule._inner = binding
            rules.append(rule)
        return rules

    def check(self) -> bool:
        return self._inner.check()

    def compile(self) -> CompiledRuleSet:
        return CompiledRuleSet(self._inner.compile())

    def scan(self, data: bytes) -> ScanResults:
        return ScanResults(self._inner.scan(data))

    def scan_file(self, path: str | Path) -> ScanResults:
        return ScanResults(self._inner.scan_file(str(path)))
