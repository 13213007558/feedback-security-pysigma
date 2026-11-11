"""Regression tests: value placeholders insert configuration data as data.

ValueListPlaceholderTransformation must treat variable values from the pipeline
configuration as plain data values. Quotes, wildcards or query-language-looking
text in a value must never change the structure of the generated query. This is
in contrast to QueryExpressionPlaceholderTransformation, which intentionally
inserts trusted raw query fragments.
"""

import pytest

from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaValueError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.types import SigmaString, SpecialChars


def value_pipeline(vars: dict) -> ProcessingPipeline:
    return ProcessingPipeline.from_dict(
        {
            "name": "value_placeholders_test",
            "transformations": [{"type": "value_placeholders"}],
            "vars": vars,
        }
    )


def queryexpr_pipeline(expression: str) -> ProcessingPipeline:
    return ProcessingPipeline.from_dict(
        {
            "name": "query_expression_placeholders_test",
            "transformations": [
                {"type": "query_expression_placeholders", "expression": expression}
            ],
        }
    )


def convert(detection: str, pipeline: ProcessingPipeline) -> list:
    rule = (
        """
title: Placeholder value test
status: test
logsource:
    category: test
detection:
    sel:
"""
        + detection
        + """
    condition: sel
"""
    )
    return TextQueryTestBackend(pipeline).convert(SigmaCollection.from_yaml(rule))


def expanded_values(detection: str, vars: dict):
    """Apply the transformation and return the expanded SigmaString values."""
    pipeline = value_pipeline(vars)
    collection = SigmaCollection.from_yaml(
        """
title: Placeholder value test
status: test
logsource:
    category: test
detection:
    sel:
"""
        + detection
        + """
    condition: sel
"""
    )
    rule = collection.rules[0]
    pipeline.apply(rule)
    return rule.detection.detections["sel"].detection_items[0].value


def test_single_value_is_plain_data():
    (value,) = expanded_values('        User|expand: "%acct%"', {"acct": "svc_backup"})
    assert value == SigmaString("svc_backup")
    assert not any(isinstance(part, SpecialChars) for part in value.s)


def test_single_number_value():
    (value,) = expanded_values('        User|expand: "%uid%"', {"uid": 123})
    assert value == SigmaString("123")


def test_multiple_values_expand_to_list():
    values = expanded_values('        User|expand: "%acct%"', {"acct": ["a", "b", 3]})
    assert values == [SigmaString("a"), SigmaString("b"), SigmaString("3")]


def test_empty_list_raises_clear_error():
    with pytest.raises(SigmaValueError, match="'acct' is empty"):
        expanded_values('        User|expand: "%acct%"', {"acct": []})


def test_multiple_placeholders_in_one_value():
    values = expanded_values(
        '        User|expand: "prefix-%dom%\\\\%acct%"',
        {"dom": "CORP", "acct": ["svc1", "svc2"]},
    )
    assert values == [SigmaString("prefix-CORP\\svc1"), SigmaString("prefix-CORP\\svc2")]


def test_wildcards_in_value_are_literal_data():
    (value,) = expanded_values('        User|expand: "%acct%"', {"acct": "admin*?"})
    assert value == SigmaString("admin\\*\\?")
    assert not any(isinstance(part, SpecialChars) for part in value.s)


def test_rule_declared_wildcards_are_kept():
    (value,) = expanded_values('        User|expand: "start*%acct%"', {"acct": "end*"})
    assert value == SigmaString("start*end\\*")
    assert any(part == SpecialChars.WILDCARD_MULTI for part in value.s)


def test_query_syntax_like_value_is_escaped():
    assert convert(
        '        User|expand: "%acct%"',
        value_pipeline({"acct": 'x" or 1=1 or "'}),
    ) == ['User="x\\" or 1=1 or \\""']


def test_wildcard_value_does_not_change_query_semantics():
    assert convert(
        '        User|expand: "%acct%"',
        value_pipeline({"acct": "*"}),
    ) == ['User="\\*"']


def test_contains_modifier_with_placeholder_value():
    assert convert(
        '        Path|contains|expand: "%path%"',
        value_pipeline({"path": "C:\\Users"}),
    ) == ['Path contains "C\\:\\Users"']


def test_contains_all_modifier_with_multi_value():
    assert convert(
        '        Path|contains|all|expand: "%path%"',
        value_pipeline({"path": ["a", "b*"]}),
    ) == ['Path contains-all ("*a*", "*b\\**")']


def test_multi_value_list_escapes_each_value():
    assert convert(
        '        User|expand: ["%acct%", "other"]',
        value_pipeline({"acct": ["a", 'b" or 1=1']}),
    ) == ['User in ("a", "b\\" or 1=1", "other")']


def test_query_expression_placeholder_stays_raw_by_contrast():
    # QueryExpressionPlaceholderTransformation intentionally inserts the configured
    # expression verbatim: it is a trusted capability for pipeline authors and is
    # not affected by the data handling of value placeholders.
    assert convert(
        '        User|expand: "%acct%"',
        queryexpr_pipeline("{field} in list({id})"),
    ) == ["User in list(acct)"]


def test_regex_value_remains_trusted_fragment():
    # In |re values the placeholder content is a regular expression fragment by
    # definition and keeps its semantics; such variables are trusted configuration.
    assert convert(
        '        User|re|expand: "%pattern%"',
        value_pipeline({"pattern": "svc_.*"}),
    ) == ["User=/svc_.*/"]
