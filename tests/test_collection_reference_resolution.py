"""
Deterministic, traceable rule reference resolution for SigmaCollection.

These tests cover the guarantees required when rule repositories are merged:

* name ambiguity and id conflicts are reported instead of being resolved by load order,
* missing references and dependency cycles fail with the concrete reference chain,
* references appearing only in field aliases are rejected,
* forward references are supported,
* the invalid collection raises before conversion or event matching and keeps source locations,
* a failed resolution never leaves a partially resolved collection behind,
* replaying the same rule set in different load orders yields identical dependency relations.
"""

import itertools
from datetime import datetime, timezone
from uuid import UUID

import pytest
import yaml

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule, SigmaRuleReference
from sigma.exceptions import (
    SigmaAliasReferenceError,
    SigmaAmbiguousRuleNameError,
    SigmaCorrelationCycleError,
    SigmaDuplicateIdentifierError,
    SigmaRuleLocation,
    SigmaRuleNotFoundError,
)
from sigma.matching import Event, EventLogSource, SigmaMatcher

RULE_1 = """
title: Rule 1
name: rule-1
id: 11111111-1111-1111-1111-111111111111
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ImageFile|endswith: 'a.exe'
    condition: selection
"""

RULE_2 = """
title: Rule 2
name: rule-2
id: 22222222-2222-2222-2222-222222222222
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ImageFile|endswith: 'b.exe'
    condition: selection
"""

CORRELATION = """
title: Correlating 1 and 2
name: corr
correlation:
    type: temporal
    rules:
        - rule-1
        - rule-2
    timespan: 5m
"""


def _correlation(collection: SigmaCollection) -> SigmaCorrelationRule:
    return next(rule for rule in collection.rules if isinstance(rule, SigmaCorrelationRule))


def _dependency_edges(collection: SigmaCollection) -> dict[str, tuple[str, ...]]:
    edges: dict[str, tuple[str, ...]] = {}
    for rule in collection.rules:
        if isinstance(rule, SigmaCorrelationRule):
            edges[rule.name] = tuple(
                sorted(reference.rule.name for reference in rule.referenced_rules)
            )
    return edges


def test_forward_references_are_resolved():
    # The correlation document comes before the rules it references.
    collection = SigmaCollection.from_yaml("---\n".join([CORRELATION, RULE_1, RULE_2]))
    correlation = _correlation(collection)
    assert [reference.rule.name for reference in correlation.referenced_rules] == [
        "rule-1",
        "rule-2",
    ]
    assert collection["rule-1"].referenced_by(correlation)
    assert collection["rule-2"].referenced_by(correlation)


def test_references_resolve_by_id_and_name():
    by_id = CORRELATION.replace("- rule-1", "- 11111111-1111-1111-1111-111111111111").replace(
        "- rule-2", "- 22222222-2222-2222-2222-222222222222"
    )
    collection = SigmaCollection.from_yaml("---\n".join([RULE_1, RULE_2, by_id]))
    assert [reference.rule.id for reference in _correlation(collection).referenced_rules] == [
        UUID("11111111-1111-1111-1111-111111111111"),
        UUID("22222222-2222-2222-2222-222222222222"),
    ]


def test_ambiguous_rule_name_is_rejected_regardless_of_load_order():
    ambiguous = RULE_2.replace("name: rule-2", "name: rule-1")
    for order in itertools.permutations([RULE_1, ambiguous, CORRELATION]):
        with pytest.raises(SigmaAmbiguousRuleNameError) as exc_info:
            SigmaCollection.from_yaml("---\n".join(order))
        error = exc_info.value
        assert error.reference_chain == ["corr", "rule-1"]
        assert "rule-1" in str(error)


def test_unreferenced_duplicate_names_are_allowed():
    # Same name, different ids, but no rule refers to the ambiguous name.
    duplicate = RULE_2.replace("name: rule-2", "name: rule-1")
    collection = SigmaCollection.from_yaml("---\n".join([RULE_1, duplicate]))
    assert len(collection.rules) == 2


def test_id_reference_stays_unambiguous_with_duplicate_names():
    rule_a = RULE_1
    rule_b = RULE_2.replace("name: rule-2", "name: rule-1")
    by_id = CORRELATION.replace("- rule-1", "- 11111111-1111-1111-1111-111111111111").replace(
        "- rule-2", "- 22222222-2222-2222-2222-222222222222"
    )
    collection = SigmaCollection.from_yaml("---\n".join([rule_a, rule_b, by_id]))
    assert _correlation(collection).referenced_rules[0].rule.id == UUID(
        "11111111-1111-1111-1111-111111111111"
    )


def test_duplicate_rule_id_is_rejected_with_sources():
    duplicate = RULE_2.replace(
        "22222222-2222-2222-2222-222222222222",
        "11111111-1111-1111-1111-111111111111",
    )
    with pytest.raises(SigmaDuplicateIdentifierError) as exc_info:
        SigmaCollection.from_dicts(
            list(yaml.safe_load_all("---\n".join([RULE_1, duplicate]))),
            source=SigmaRuleLocation("merged/rules.yml"),
        )
    error = exc_info.value
    assert str(UUID("11111111-1111-1111-1111-111111111111")) in str(error)
    assert "merged/rules.yml" in str(error)


def test_missing_reference_reports_chain_and_source():
    broken = CORRELATION.replace("- rule-2", "- rule-missing")
    with pytest.raises(SigmaRuleNotFoundError) as exc_info:
        SigmaCollection.from_dicts(
            list(yaml.safe_load_all("---\n".join([RULE_1, RULE_2, broken]))),
            source=SigmaRuleLocation("corpus/broken.yml"),
        )
    error = exc_info.value
    assert error.reference_chain == ["corr", "rule-missing"]
    assert "reference chain: corr -> rule-missing" in str(error)
    assert "corpus/broken.yml" in str(error)


def test_missing_nested_reference_chain():
    inner = """
title: Inner correlation
name: inner
correlation:
    type: event_count
    rules:
        - rule-missing
    timespan: 5m
    condition:
        gte: 1
"""
    outer = """
title: Outer correlation
name: outer
correlation:
    type: event_count
    rules:
        - inner
    timespan: 1h
    condition:
        gte: 2
"""
    with pytest.raises(SigmaRuleNotFoundError) as exc_info:
        SigmaCollection.from_yaml("---\n".join([outer, inner, RULE_1]))
    assert exc_info.value.reference_chain == ["inner", "rule-missing"]


def test_dependency_cycle_reports_cycle_chain():
    rule_a = """
title: Correlation A
name: corr-a
correlation:
    type: event_count
    rules:
        - corr-b
    timespan: 5m
    condition:
        gte: 1
"""
    rule_b = """
title: Correlation B
name: corr-b
correlation:
    type: event_count
    rules:
        - corr-a
    timespan: 5m
    condition:
        gte: 1
"""
    for order in itertools.permutations([rule_a, rule_b]):
        with pytest.raises(SigmaCorrelationCycleError) as exc_info:
            SigmaCollection.from_yaml("---\n".join(order))
        chain = exc_info.value.reference_chain
        assert chain[0] == chain[-1]
        assert set(chain) == {"corr-a", "corr-b"}


def test_self_referencing_correlation_is_a_cycle():
    self_reference = """
title: Self reference
name: corr-self
correlation:
    type: event_count
    rules:
        - corr-self
    timespan: 5m
    condition:
        gte: 1
"""
    with pytest.raises(SigmaCorrelationCycleError) as exc_info:
        SigmaCollection.from_yaml(self_reference)
    assert exc_info.value.reference_chain == ["corr-self", "corr-self"]


def test_alias_only_reference_is_rejected():
    # rule-3 exists in the collection but is only mentioned in the alias, not in rules.
    rule_3 = RULE_2.replace("name: rule-2", "name: rule-3").replace(
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
    )
    with_alias = CORRELATION + """    group-by:
        - user
    aliases:
        user:
            rule-3: username
"""
    with pytest.raises(SigmaAliasReferenceError) as exc_info:
        SigmaCollection.from_yaml("---\n".join([RULE_1, RULE_2, rule_3, with_alias]))
    assert exc_info.value.reference_chain == ["corr", "rule-3"]


def test_alias_reference_to_unknown_rule_is_reported():
    with_alias = CORRELATION + """    group-by:
        - user
    aliases:
        user:
            rule-2: username
            rule-missing: account
"""
    with pytest.raises(SigmaRuleNotFoundError) as exc_info:
        SigmaCollection.from_yaml("---\n".join([RULE_1, RULE_2, with_alias]))
    assert exc_info.value.reference_chain == ["corr", "rule-missing"]


def test_alias_references_are_resolved():
    with_alias = CORRELATION + """    group-by:
        - user
    aliases:
        user:
            rule-1: username
            rule-2: account
"""
    collection = SigmaCollection.from_yaml("---\n".join([RULE_1, RULE_2, with_alias]))
    mapping = _correlation(collection).aliases.aliases["user"].mapping
    assert {reference.rule.name for reference in mapping} == {"rule-1", "rule-2"}


def test_failed_resolution_leaves_no_partial_state():
    broken = CORRELATION.replace("- rule-2", "- rule-missing")
    collection = SigmaCollection.from_yaml(
        "---\n".join([RULE_1, RULE_2, broken]), resolve_references=False
    )
    correlation = _correlation(collection)

    for _ in range(2):
        with pytest.raises(SigmaRuleNotFoundError):
            collection.resolve_rule_references()

    assert collection._references_resolved is False
    assert correlation.referenced_rules == []
    assert all(not hasattr(reference, "rule") for reference in (correlation.rules or []))
    assert all(not rule._backreferences for rule in collection.rules)
    assert all(rule._output for rule in collection.rules)
    # The static id/name indexes exist independently of resolution and stay usable.
    assert collection["rule-1"].name == "rule-1"
    assert collection[UUID("22222222-2222-2222-2222-222222222222")].name == "rule-2"


def test_resolution_is_idempotent():
    collection = SigmaCollection.from_yaml("---\n".join([RULE_1, RULE_2, CORRELATION]))
    collection.resolve_rule_references()
    collection.resolve_rule_references()
    assert [rule.name for rule in collection["rule-1"]._backreferences] == ["corr"]
    assert collection["rule-1"]._output is False


def test_load_order_replay_produces_identical_dependencies():
    documents = [RULE_1, RULE_2, CORRELATION]
    observed = set()
    for order in itertools.permutations(documents):
        collection = SigmaCollection.from_yaml("---\n".join(order))
        observed.add(tuple(sorted(_dependency_edges(collection).items())))
        # Topological order: the correlation always comes after the rules it depends on.
        names = [rule.name for rule in collection.rules]
        assert names.index("corr") > names.index("rule-1")
        assert names.index("corr") > names.index("rule-2")
    assert observed == {(("corr", ("rule-1", "rule-2")),)}


def test_load_order_replay_produces_identical_failure_chain():
    broken = CORRELATION.replace("- rule-2", "- rule-missing")
    documents = [RULE_1, RULE_2, broken]
    chains = set()
    for order in itertools.permutations(documents):
        with pytest.raises(SigmaRuleNotFoundError) as exc_info:
            SigmaCollection.from_yaml("---\n".join(order))
        chains.add(tuple(exc_info.value.reference_chain))
    assert chains == {("corr", "rule-missing")}


def test_invalid_collection_is_rejected_before_matching():
    broken = CORRELATION.replace("- rule-2", "- rule-missing")
    collection = SigmaCollection.from_yaml(
        "---\n".join([RULE_1, RULE_2, broken]), resolve_references=False
    )
    event = Event(
        timestamp=datetime.now(tz=timezone.utc),
        logsource=EventLogSource(category="process_creation", product="windows"),
        data={"ImageFile": "C:\\a.exe"},
    )
    with pytest.raises(SigmaRuleNotFoundError):
        SigmaMatcher(collection).match(event)


def test_merged_collections_resolve_across_file_boundaries():
    first = SigmaCollection.from_yaml(RULE_1, resolve_references=False)
    second = SigmaCollection.from_yaml(
        "---\n".join([RULE_2, CORRELATION]), resolve_references=False
    )
    merged = SigmaCollection.merge([first, second])
    assert [reference.rule.name for reference in _correlation(merged).referenced_rules] == [
        "rule-1",
        "rule-2",
    ]
    assert merged._references_resolved is True


def test_unresolved_collection_still_exposes_rule_objects():
    collection = SigmaCollection.from_yaml(
        "---\n".join([RULE_1, RULE_2, CORRELATION]), resolve_references=False
    )
    assert len(collection.rules) == 3
    assert isinstance(_correlation(collection).rules[0], SigmaRuleReference)
    assert not hasattr(_correlation(collection).rules[0], "rule")
