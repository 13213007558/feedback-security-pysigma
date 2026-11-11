"""Semantic differential tests: pySigma matcher vs. an executable SQLite backend.

Every rule below is paired with a hand-written set of event ids that *must*
alert. The same events are evaluated on two independent paths:

1. the in-process :class:`~sigma.matching.matcher.SigmaMatcher` (the reference
   implementation of Sigma semantics), and
2. a SQL WHERE clause produced by :class:`SQLiteSemanticBackend` and executed
   by :class:`SQLiteEventEngine` over the same events stored as JSON.

The point of the table is the shape of the events, not the volume: each rule
is exercised against scalar values, multi-valued (JSON array) fields, empty
arrays, missing fields and explicit JSON nulls, so that a matcher or converter
which silently coerces missing fields to empty strings, or stringifies arrays,
cannot hide behind a green test run.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.matching.event import Event, EventLogSource
from sigma.matching.matcher import SigmaMatcher
from tests.semantic_sqlite.backend import SQLiteSemanticBackend
from tests.semantic_sqlite.engine import SQLiteEventEngine

LOGSOURCE = EventLogSource(category="test", product="test")

# ---------------------------------------------------------------------------
# Event universe: deliberately covers every field shape under test.
# ---------------------------------------------------------------------------
EVENTS: dict[str, dict] = {
    "scalar_hit": {"f": "evil", "n": 1, "flag": True},
    "scalar_miss": {"f": "good", "n": 9, "flag": False},
    "list_hit": {"f": ["evil", "good"], "n": [1, 2]},
    "list_partial": {"f": ["good", "bad"], "n": [8, 9]},
    "empty_list": {"f": [], "n": []},
    "missing": {"other": "present"},
    "explicit_null": {"f": None, "n": None},
    "numeric_in_f": {"f": 7},
}

# ---------------------------------------------------------------------------
# Rule definitions and the manually specified expected hit sets.
# Each tuple: (rule name, detection YAML, condition, expected event ids).
# Detection YAML is written at a 4-space base indent so it slots under the
# generated rule's top-level ``detection:`` mapping.
# ---------------------------------------------------------------------------
RULE_SPECS: list[tuple[str, str, str, set[str]]] = [
    (
        "eq_string",
        """
    s:
        f: evil
""",
        "s",
        {"scalar_hit", "list_hit"},
    ),
    (
        "eq_number",
        """
    s:
        n: 1
""",
        "s",
        {"scalar_hit", "list_hit"},
    ),
    (
        "eq_bool",
        """
    s:
        flag: true
""",
        "s",
        {"scalar_hit"},
    ),
    (
        "wildcard_glob",
        """
    s:
        f: "ev*"
""",
        "s",
        {"scalar_hit", "list_hit"},
    ),
    (
        "value_list_or",
        """
    s:
        f:
            - evil
            - bad
""",
        "s",
        {"scalar_hit", "list_hit", "list_partial"},
    ),
    (
        "all_modifier_contains",
        """
    s:
        f|contains|all:
            - good
            - bad
""",
        "s",
        {"list_partial"},
    ),
    (
        "all_modifier_eq",
        """
    s:
        f|all:
            - evil
            - good
""",
        "s",
        {"list_hit"},
    ),
    (
        "neq_single_value",
        """
    s:
        f|neq: evil
""",
        "s",
        # NOT of a positive predicate: missing/null/empty/other values all
        # pass, while the scalar hit and any array containing the value do not.
        {"scalar_miss", "list_partial", "empty_list", "missing", "explicit_null", "numeric_in_f"},
    ),
    (
        "null_check",
        """
    s:
        f: null
""",
        "s",
        # pySigma treats a missing path like null for the null test (see
        # tests/test_matching.py::test_null).
        {"missing", "explicit_null"},
    ),
    (
        "exists_true",
        """
    s:
        f|exists: true
""",
        "s",
        {
            "scalar_hit",
            "scalar_miss",
            "list_hit",
            "list_partial",
            "empty_list",
            "explicit_null",
            "numeric_in_f",
        },
    ),
    (
        "exists_false",
        """
    s:
        f|exists: false
""",
        "s",
        {"missing"},
    ),
    (
        "numeric_compare_lt",
        """
    s:
        n|lt: 5
""",
        "s",
        {"scalar_hit", "list_hit"},
    ),
    (
        "and_not_combined",
        """
    positive:
        n: 1
    negative:
        f|neq: evil
""",
        "positive and negative",
        # n==1 holds on scalar_hit/list_hit; both also carry f=evil, so the NOT
        # side removes them. No event may alert.
        set(),
    ),
    (
        "or_with_negated_branch",
        """
    nullish:
        f: null
    evilish:
        f: evil
""",
        "nullish or evilish",
        {"missing", "explicit_null", "scalar_hit", "list_hit"},
    ),
    (
        "not_of_value_list",
        """
    s:
        f|neq:
            - evil
            - bad
""",
        "s",
        # NOT (f in [evil, bad]): arrays containing either value are excluded.
        {"scalar_miss", "empty_list", "missing", "explicit_null", "numeric_in_f"},
    ),
]


def _rule_yaml(name: str, detection_block: str, condition: str) -> str:
    return f"""
title: {name}
name: {name}
status: test
logsource:
    category: test
    product: test
detection:
{detection_block}    condition: {condition}
"""


@pytest.fixture(scope="module")
def compiled_rules() -> dict[str, SigmaCollection]:
    return {
        name: SigmaCollection.from_yaml(_rule_yaml(name, detection, condition))
        for name, detection, condition, _ in RULE_SPECS
    }


@pytest.fixture(scope="module")
def matcher_hits(compiled_rules) -> dict[str, set[str]]:
    collections = SigmaCollection(
        [rule for collection in compiled_rules.values() for rule in collection.rules]
    )
    results: dict[str, set[str]] = {name: set() for name in compiled_rules}
    with SigmaMatcher(collections) as matcher:
        for event_id, data in EVENTS.items():
            event = Event(
                timestamp=datetime.now(tz=timezone.utc),
                logsource=LOGSOURCE,
                data=dict(data),
            )
            for match in matcher.match(event):
                results[match.rule.name].add(event_id)
    return results


@pytest.fixture(scope="module")
def sqlite_hits(compiled_rules) -> dict[str, set[str]]:
    backend = SQLiteSemanticBackend()
    engine = SQLiteEventEngine()
    engine.load(EVENTS)
    try:
        results: dict[str, set[str]] = {}
        for name, collection in compiled_rules.items():
            where_sql = backend.convert(collection)[0]
            results[name] = engine.query(where_sql)
    finally:
        engine.close()
    return results


@pytest.mark.parametrize(
    "rule_name,expected",
    [(name, expected) for name, _, _, expected in RULE_SPECS],
    ids=[name for name, _, _, _ in RULE_SPECS],
)
def test_matcher_matches_manual_truth_table(rule_name, expected, matcher_hits):
    """The reference matcher must alert on exactly the hand-specified events."""
    assert matcher_hits[rule_name] == expected


@pytest.mark.parametrize(
    "rule_name,expected",
    [(name, expected) for name, _, _, expected in RULE_SPECS],
    ids=[name for name, _, _, _ in RULE_SPECS],
)
def test_sqlite_backend_matches_manual_truth_table(rule_name, expected, sqlite_hits):
    """The converted, executed SQL must alert on the same hand-specified events."""
    assert sqlite_hits[rule_name] == expected


@pytest.mark.parametrize(
    "rule_name",
    [name for name, _, _, _ in RULE_SPECS],
    ids=[name for name, _, _, _ in RULE_SPECS],
)
def test_both_paths_agree(rule_name, matcher_hits, sqlite_hits):
    """Matcher and SQL execution must never disagree on the truth table."""
    assert matcher_hits[rule_name] == sqlite_hits[rule_name]


def test_missing_field_is_not_backfilled_to_empty_string():
    """Regression guard: absent keys and empty strings must stay distinguishable.

    A rule matching the empty string must not fire on an event where the field
    is simply missing, and vice versa.
    """
    rule = SigmaCollection.from_yaml(
        _rule_yaml("empty_string", "    s:\n        f: ''\n", "s")
    )
    backend = SQLiteSemanticBackend()
    engine = SQLiteEventEngine()
    engine.load({"has_empty": {"f": ""}, "missing_field": {"other": 1}})
    try:
        where_sql = backend.convert(rule)[0]
        assert engine.query(where_sql) == {"has_empty"}
    finally:
        engine.close()

    with SigmaMatcher(rule) as matcher:
        empty_event = Event(datetime.now(tz=timezone.utc), LOGSOURCE, {"f": ""})
        missing_event = Event(datetime.now(tz=timezone.utc), LOGSOURCE, {"other": 1})
        assert bool(matcher.match(empty_event)) is True
        assert bool(matcher.match(missing_event)) is False


UNSUPPORTED_RULES = [
    ("regex", "    s:\n        f|re: '^a.*z$'\n"),
    ("cidr", "    s:\n        f|cidr: '10.0.0.0/8'\n"),
    ("keyword", "    s:\n        - orphankeyword\n"),
    ("fieldref", "    s:\n        f|fieldref: g\n"),
]


@pytest.mark.parametrize("rule_name,detection_block", UNSUPPORTED_RULES)
def test_inexpressible_features_are_rejected(rule_name, detection_block):
    """Features outside the restricted subset must fail loudly, not silently."""
    rule = SigmaCollection.from_yaml(_rule_yaml(rule_name, detection_block, "s"))
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        SQLiteSemanticBackend().convert(rule)
