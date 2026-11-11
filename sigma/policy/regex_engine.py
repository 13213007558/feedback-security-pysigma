from __future__ import annotations

import re
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Any, Mapping, Protocol, cast


class RegexFeature(Enum):
    """Regular expression constructs that are not supported by all regex engines."""

    BACKREFERENCE = auto()
    LOOKAROUND = auto()


def find_regex_features(pattern: str) -> set[RegexFeature]:
    """Scan a regular expression pattern for constructs from the RegexFeature enum.

    The scanner implements a small tokenizer instead of plain substring matching so that
    escaped characters (e.g. ``\\(`` or ``\\1`` as literal backslash followed by ``1``) and
    character classes (e.g. ``[(?=]`` or ``[\\1]``) are not misinterpreted as group syntax,
    lookarounds or backreferences.
    """
    features: set[RegexFeature] = set()
    i = 0
    n = len(pattern)
    in_class = False
    while i < n:
        c = pattern[i]
        if c == "\\":  # escaped character: consume next char without interpreting it
            if i + 1 < n:
                if not in_class and pattern[i + 1] in "123456789":
                    # Numeric escape outside character classes is a group backreference.
                    features.add(RegexFeature.BACKREFERENCE)
                i += 2
            else:  # trailing backslash: invalid pattern, leave detection to the engine
                i += 1
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            i += 1
            # A ']' directly after '[' or '[^' is a literal character, not the class end.
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1
            continue
        if c == "(" and pattern.startswith("(?", i):
            if (
                pattern.startswith("(?=", i)
                or pattern.startswith("(?!", i)
                or pattern.startswith("(?<=", i)
                or pattern.startswith("(?<!", i)
            ):
                features.add(RegexFeature.LOOKAROUND)
            elif pattern.startswith("(?P=", i):
                # Named group backreference, (?P<name>...) group definitions are no feature.
                features.add(RegexFeature.BACKREFERENCE)
        i += 1
    return features


class RegexPattern(Protocol):
    """Protocol for compiled regex objects from Python ``re`` and Google RE2."""

    groupindex: Mapping[str, int]

    def match(self, string: str, *args: Any, **kwargs: Any) -> Any: ...

    def fullmatch(self, string: str, *args: Any, **kwargs: Any) -> Any: ...

    def search(self, string: str, *args: Any, **kwargs: Any) -> Any: ...

    def sub(self, repl: Any, string: str, *args: Any, **kwargs: Any) -> str: ...

    def finditer(self, string: str, *args: Any, **kwargs: Any) -> Any: ...


class RegexEngine(ABC):
    """Strategy base class for regex engine implementations."""

    def __eq__(self, other: object) -> bool:
        return type(self) is type(other)

    def __hash__(self) -> int:
        return hash(type(self))

    @abstractmethod
    def compile(self, pattern: str, flags: int = 0) -> RegexPattern:
        """Compile a regex pattern and return a compiled pattern object."""

    @property
    @abstractmethod
    def error(self) -> type[Exception]:
        """The exception type raised for invalid regex patterns."""

    @property
    @abstractmethod
    def supported_features(self) -> frozenset[RegexFeature]:
        """The regex features from RegexFeature supported by this engine."""

    def unsupported_features(self, pattern: str) -> set[RegexFeature]:
        """Return the features used by *pattern* that are not supported by this engine."""
        return find_regex_features(pattern) - self.supported_features


class PythonRegexEngine(RegexEngine):
    """Regex engine backed by Python's built-in re module."""

    def compile(self, pattern: str, flags: int = 0) -> RegexPattern:
        return cast(RegexPattern, re.compile(pattern, flags))

    @property
    def error(self) -> type[re.error]:
        return re.error

    @property
    def supported_features(self) -> frozenset[RegexFeature]:
        return frozenset(RegexFeature)


class RE2RegexEngine(RegexEngine):
    """DoS-safe regex engine backed by Google RE2 (no backtracking)."""

    def __init__(self) -> None:
        try:
            import re2  # type: ignore[import-untyped]

            self._re2 = re2
        except ImportError as exc:
            raise ImportError(
                "The 'google-re2' package is required for RE2RegexEngine (SafePolicy). "
                "Install it with: pip install google-re2"
            ) from exc

    def compile(self, pattern: str, flags: int = 0) -> RegexPattern:
        # RE2's Python binding doesn't accept Python re int-flags as a positional arg;
        # embed them as inline flags instead, which RE2 supports natively.
        import re

        flag_map = {re.IGNORECASE: "i", re.MULTILINE: "m", re.DOTALL: "s"}
        prefix = "".join(v for k, v in flag_map.items() if int(flags) & int(k))
        if prefix:
            pattern = f"(?{prefix})" + pattern
        return cast(RegexPattern, self._re2.compile(pattern))

    @property
    def error(self) -> type[Exception]:
        return self._re2.error  # type: ignore[no-any-return]

    @property
    def supported_features(self) -> frozenset[RegexFeature]:
        # RE2 neither supports backreferences nor lookaround assertions.
        return frozenset()
