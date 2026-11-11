"""Python scalar functions registered on the SQLite connection.

Every function receives the raw JSON-encoded value extracted by
``json_extract`` (so the connection keeps the event in a single ``data`` JSON
column) plus the field path, and re-extracts using ``json_extract`` in Python.
Returning 0/1 lets the predicates compose with ordinary SQL ``NOT``/``AND``/
``OR`` while preserving three-valued semantics for missing fields:

* a missing JSON path and an explicit JSON null both produce SQL NULL;
* positive predicates return 0 for them (no match), so ``NOT`` yields 1,
  matching the pySigma matcher's ``field|neq`` behaviour;
* ``sigma_isnull`` is the dedicated null test that also covers missing paths,
  and ``sigma_exists`` separates "key present" from "key absent".
"""

from __future__ import annotations

import json
import re
from typing import Any


def _extract(data_text: str | None, field: str) -> tuple[bool, Any]:
    """Return (path_exists, value). value is None for missing path and null."""
    if data_text is None:
        return False, None
    try:
        data = json.loads(data_text)
    except (TypeError, ValueError):
        return False, None
    if not isinstance(data, dict) or field not in data:
        return False, None
    return True, data[field]


def _iter_scalars(value: Any) -> list[Any]:
    """Flatten a JSON array into its scalar elements; scalars wrap themselves."""
    if isinstance(value, list):
        return [item for item in value if not isinstance(item, (dict, list))]
    return [value]


def sigma_eq(data_text: str | None, field: str, expected: Any) -> int:
    """Case-insensitive equality over any element of a multi-valued field."""
    exists, value = _extract(data_text, field)
    if not exists or value is None:
        return 0
    for element in _iter_scalars(value):
        if isinstance(element, str) and isinstance(expected, str):
            if element.lower() == expected.lower():
                return 1
        elif element == expected:
            return 1
    return 0


def sigma_eq_cased(data_text: str | None, field: str, expected: str) -> int:
    """Case-sensitive equality over any element of a multi-valued field."""
    exists, value = _extract(data_text, field)
    if not exists or value is None:
        return 0
    return int(any(isinstance(e, str) and e == expected for e in _iter_scalars(value)))


def sigma_num_eq(data_text: str | None, field: str, expected: float) -> int:
    exists, value = _extract(data_text, field)
    if not exists or value is None:
        return 0
    for element in _iter_scalars(value):
        if isinstance(element, bool) or not isinstance(element, (int, float)):
            continue
        if element == expected:
            return 1
    return 0


def sigma_bool_eq(data_text: str | None, field: str, expected: int) -> int:
    exists, value = _extract(data_text, field)
    if not exists or not isinstance(value, bool):
        return 0
    return int(value == bool(expected))


def sigma_compare(data_text: str | None, field: str, op: str, expected: float) -> int:
    exists, value = _extract(data_text, field)
    if not exists or value is None:
        return 0
    for element in _iter_scalars(value):
        if isinstance(element, bool) or not isinstance(element, (int, float)):
            continue
        if op == "<" and element < expected:
            return 1
        if op == "<=" and element <= expected:
            return 1
        if op == ">" and element > expected:
            return 1
        if op == ">=" and element >= expected:
            return 1
        if op == "!=" and element != expected:
            return 1
    return 0


def sigma_glob(data_text: str | None, field: str, pattern: str, case_insensitive: int) -> int:
    """Match a Sigma wildcard pattern (``*``/``?``) against any element."""
    exists, value = _extract(data_text, field)
    if not exists or value is None:
        return 0
    regex = _sigma_wildcard_to_regex(pattern)
    flags = re.IGNORECASE if case_insensitive else 0
    compiled = re.compile(regex, flags)
    for element in _iter_scalars(value):
        if isinstance(element, str) and compiled.fullmatch(element):
            return 1
    return 0


def sigma_contains(data_text: str | None, field: str, needle: str, case_insensitive: int) -> int:
    exists, value = _extract(data_text, field)
    if not exists or value is None:
        return 0
    for element in _iter_scalars(value):
        if not isinstance(element, str):
            continue
        haystack = element.lower() if case_insensitive else element
        target = needle.lower() if case_insensitive else needle
        if target in haystack:
            return 1
    return 0


def sigma_starts(data_text: str | None, field: str, prefix: str, case_insensitive: int) -> int:
    exists, value = _extract(data_text, field)
    if not exists or value is None:
        return 0
    for element in _iter_scalars(value):
        if not isinstance(element, str):
            continue
        haystack = element.lower() if case_insensitive else element
        target = prefix.lower() if case_insensitive else prefix
        if haystack.startswith(target):
            return 1
    return 0


def sigma_ends(data_text: str | None, field: str, suffix: str, case_insensitive: int) -> int:
    exists, value = _extract(data_text, field)
    if not exists or value is None:
        return 0
    for element in _iter_scalars(value):
        if not isinstance(element, str):
            continue
        haystack = element.lower() if case_insensitive else element
        target = suffix.lower() if case_insensitive else suffix
        if haystack.endswith(target):
            return 1
    return 0


def sigma_regexp(data_text: str | None, field: str, pattern: str) -> int:
    exists, value = _extract(data_text, field)
    if not exists or value is None:
        return 0
    try:
        compiled = re.compile(pattern)
    except re.error:
        return 0
    for element in _iter_scalars(value):
        if isinstance(element, str) and compiled.search(element):
            return 1
    return 0


def _match_typed(element: Any, spec: dict[str, Any]) -> bool:
    """Evaluate one typed list element against one event field element."""
    kind = spec.get("t")
    if kind == "str":
        return isinstance(element, str) and element.lower() == str(spec["v"]).lower()
    if kind == "cased":
        return isinstance(element, str) and element == spec["v"]
    if kind == "num":
        return (
            not isinstance(element, bool)
            and isinstance(element, (int, float))
            and element == spec["v"]
        )
    if kind == "glob":
        return (
            isinstance(element, str)
            and re.compile(_sigma_wildcard_to_regex(spec["v"]), re.IGNORECASE).fullmatch(element)
            is not None
        )
    if kind == "null":
        return element is None
    return False


def sigma_in_list(data_text: str | None, field: str, operator: str, specs_json: str) -> int:
    """OR/AND membership over typed value specs and multi-valued event fields.

    ``specs_json`` is a JSON array of typed specs emitted by the backend. An OR
    list matches when any spec matches any field element; an AND list (the
    ``all`` modifier) matches only when *every* spec is satisfied by at least
    one field element. Missing fields and explicit null never satisfy positive
    specs, so the predicate returns 0 and an outer NOT negates correctly.
    """
    exists, value = _extract(data_text, field)
    if not exists:
        return 0
    try:
        specs = json.loads(specs_json)
    except (TypeError, ValueError):
        return 0
    elements = _iter_scalars(value) if value is not None else [None]
    if operator == "OR":
        return int(any(_match_typed(element, spec) for spec in specs for element in elements))
    if operator == "AND":
        return int(
            all(any(_match_typed(element, spec) for element in elements) for spec in specs)
        )
    return 0


def sigma_isnull(data_text: str | None, field: str) -> int:
    """Match explicit JSON null *and* missing path (pySigma ``field: null``)."""
    exists, value = _extract(data_text, field)
    return int(not exists or value is None)


def sigma_exists(data_text: str | None, field: str) -> int:
    """Match a present key, including one whose value is explicit null."""
    exists, _ = _extract(data_text, field)
    return int(exists)


def _sigma_wildcard_to_regex(pattern: str) -> str:
    out: list[str] = []
    for char in pattern:
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
    return "".join(out)


FUNCTIONS = (
    ("sigma_eq", 3, sigma_eq),
    ("sigma_eq_cased", 3, sigma_eq_cased),
    ("sigma_num_eq", 3, sigma_num_eq),
    ("sigma_bool_eq", 3, sigma_bool_eq),
    ("sigma_compare", 4, sigma_compare),
    ("sigma_glob", 4, sigma_glob),
    ("sigma_contains", 4, sigma_contains),
    ("sigma_starts", 4, sigma_starts),
    ("sigma_ends", 4, sigma_ends),
    ("sigma_regexp", 3, sigma_regexp),
    ("sigma_in_list", 4, sigma_in_list),
    ("sigma_isnull", 2, sigma_isnull),
    ("sigma_exists", 2, sigma_exists),
)
