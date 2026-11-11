"""Tests for regex capability checks of backends during query conversion."""

from dataclasses import dataclass

import pytest

from sigma.backends.test.backend import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.policy.profiles import TrustedPolicy
from sigma.policy.regex_engine import (
    PythonRegexEngine,
    RE2RegexEngine,
    RegexFeature,
    find_regex_features,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import ValueListPlaceholderTransformation
from sigma.processing.transformations.base import StringValueTransformation
from sigma.rule import SigmaRule
from sigma.types import SigmaRegularExpression, SigmaString


class FullRegexTestBackend(TextQueryTestBackend):
    """Test backend whose target query language supports all regex features."""

    name = "Test backend with full regex support"
    regex_engine = PythonRegexEngine()


class LimitedRegexTestBackend(TextQueryTestBackend):
    """Test backend whose target query language supports neither backreferences nor
    lookaround assertions."""

    name = "Test backend without backreference and lookaround support"
    regex_engine = RE2RegexEngine()


@pytest.mark.parametrize(
    "pattern,expected",
    [
        # plain patterns without special features
        ("foo.*bar", set()),
        ("(?:abc)+", set()),
        ("(?i)foo", set()),
        ("(?ims:foo)", set()),
        ("(?#comment)foo", set()),
        ("(?P<name>abc)", set()),
        # lookaround assertions
        ("foo(?=bar)", {RegexFeature.LOOKAROUND}),
        ("foo(?!bar)", {RegexFeature.LOOKAROUND}),
        ("(?<=foo)bar", {RegexFeature.LOOKAROUND}),
        ("(?<!foo)bar", {RegexFeature.LOOKAROUND}),
        # backreferences
        (r"(abc)\1", {RegexFeature.BACKREFERENCE}),
        (r"(a)(b)\2", {RegexFeature.BACKREFERENCE}),
        (r"(?P<name>abc)(?P=name)", {RegexFeature.BACKREFERENCE}),
        # multiple features in one pattern
        (r"(?=foo)(abc)\1", {RegexFeature.LOOKAROUND, RegexFeature.BACKREFERENCE}),
        # escaped characters are no features
        (r"\(", set()),
        (r"\(?=foo", set()),
        (r"\\1", set()),
        (r"\(?P=name)", set()),
        (r"\\(?P=name)", {RegexFeature.BACKREFERENCE}),
        (r"\[foo\]", set()),
        # character class content is no feature
        ("[(?=]", set()),
        ("[(?<=]", set()),
        (r"[\1]", set()),
        ("[()]", set()),
        ("[]=?]", set()),
        ("[^]a]", set()),
        # feature outside of character class after class was closed
        ("[abc](?=foo)", {RegexFeature.LOOKAROUND}),
        (r"[abc](x)\1", {RegexFeature.BACKREFERENCE}),
    ],
)
def test_find_regex_features(pattern, expected):
    assert find_regex_features(pattern) == expected


def test_python_engine_supports_all_features():
    assert PythonRegexEngine().supported_features == frozenset(RegexFeature)
    assert PythonRegexEngine().unsupported_features(r"(?=foo)(abc)\1") == set()


def test_re2_engine_supports_no_features():
    assert RE2RegexEngine().supported_features == frozenset()
    assert RE2RegexEngine().unsupported_features(r"(?=foo)(abc)\1") == {
        RegexFeature.LOOKAROUND,
        RegexFeature.BACKREFERENCE,
    }
    assert RE2RegexEngine().unsupported_features("foo.*bar") == set()


lookahead_rule = r"""
title: Regex capability test
status: test
logsource:
    category: test
detection:
    selection:
        field|re: 'foo(?=xyz)'
    condition: selection
"""

backreference_rule = r"""
title: Regex capability test
status: test
logsource:
    category: test
detection:
    selection:
        field|re: '(abc)\1'
    condition: selection
"""

named_backreference_rule = r"""
title: Regex capability test
status: test
logsource:
    category: test
detection:
    selection:
        field|re: '(?P<word>abc)(?P=word)'
    condition: selection
"""

supported_rule = r"""
title: Regex capability test
status: test
logsource:
    category: test
detection:
    selection:
        field|re: 'foo.*(?:xyz|abc)[0-9]+'
    condition: selection
"""

escaped_rule = r"""
title: Regex capability test
status: test
logsource:
    category: test
detection:
    selection:
        field|re: '[(?=]+\('
    condition: selection
"""


def test_lookahead_accepted_by_full_backend():
    collection = SigmaCollection.from_yaml(lookahead_rule, policy=TrustedPolicy)
    assert FullRegexTestBackend().convert(collection) == ["field=/foo(?=xyz)/"]


def test_lookahead_rejected_by_limited_backend():
    collection = SigmaCollection.from_yaml(lookahead_rule, policy=TrustedPolicy)
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="lookaround"):
        LimitedRegexTestBackend().convert(collection)


def test_backreference_rejected_by_limited_backend():
    collection = SigmaCollection.from_yaml(backreference_rule, policy=TrustedPolicy)
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="backreference"):
        LimitedRegexTestBackend().convert(collection)


def test_named_backreference_rejected_by_limited_backend():
    collection = SigmaCollection.from_yaml(named_backreference_rule, policy=TrustedPolicy)
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="backreference"):
        LimitedRegexTestBackend().convert(collection)


def test_backreference_accepted_by_full_backend():
    collection = SigmaCollection.from_yaml(backreference_rule, policy=TrustedPolicy)
    # the escape character itself is escaped by the test backend
    assert FullRegexTestBackend().convert(collection) == [r"field=/(abc)\\1/"]


def test_supported_regex_converted_unchanged_by_limited_backend():
    collection = SigmaCollection.from_yaml(supported_rule, policy=TrustedPolicy)
    assert LimitedRegexTestBackend().convert(collection) == [
        "field=/foo.*(?:xyz|abc)[0-9]+/"
    ]


def test_escaped_and_character_class_patterns_accepted_by_limited_backend():
    collection = SigmaCollection.from_yaml(escaped_rule, policy=TrustedPolicy)
    assert LimitedRegexTestBackend().convert(collection) == [r"field=/[(?=]+\\(/"]


def test_capability_error_is_associated_with_rule():
    collection = SigmaCollection.from_yaml(lookahead_rule, policy=TrustedPolicy)
    rule = collection.rules[0]
    backend = LimitedRegexTestBackend(collect_errors=True)
    backend.convert(collection)
    assert len(backend.errors) == 1
    error_rule, error = backend.errors[0]
    assert error_rule is rule
    assert isinstance(error, SigmaFeatureNotSupportedByBackendError)
    assert "lookaround" in str(error)


placeholder_rule = r"""
title: Regex capability test
status: test
logsource:
    category: test
detection:
    selection:
        field|re|expand: 'foo%suffix%'
    condition: selection
"""


@pytest.fixture
def placeholder_pipeline():
    return ProcessingPipeline(
        items=[
            ProcessingItem(
                ValueListPlaceholderTransformation(),
                identifier="expand-suffix",
            )
        ],
        vars={"suffix": "xyz(?=abc)"},
        policy=TrustedPolicy,
    )


def test_placeholder_expansion_accepted_by_full_backend(placeholder_pipeline):
    collection = SigmaCollection.from_yaml(placeholder_rule, policy=TrustedPolicy)
    assert FullRegexTestBackend(placeholder_pipeline).convert(collection) == [
        "field=/fooxyz(?=abc)/"
    ]


def test_placeholder_expansion_rejected_by_limited_backend(placeholder_pipeline):
    collection = SigmaCollection.from_yaml(placeholder_rule, policy=TrustedPolicy)
    backend = LimitedRegexTestBackend(placeholder_pipeline, collect_errors=True)
    backend.convert(collection)
    assert len(backend.errors) == 1
    error_rule, error = backend.errors[0]
    assert error_rule is collection.rules[0]
    assert isinstance(error, SigmaFeatureNotSupportedByBackendError)
    assert "lookaround" in str(error)
    # error is associated with the processing step that introduced the expression
    assert "expand-suffix" in str(error)


@dataclass
class AddLookaroundTransformation(StringValueTransformation):
    """Test transformation that turns a plain string value into a regular expression
    containing a lookaround assertion."""

    def apply_string_value(self, field, val: SigmaString) -> SigmaRegularExpression:
        return SigmaRegularExpression(str(val) + "(?=xyz)", policy=TrustedPolicy)


string_rule = r"""
title: Regex capability test
status: test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"""


@pytest.fixture
def lookaround_transformation_pipeline():
    return ProcessingPipeline(
        items=[
            ProcessingItem(
                AddLookaroundTransformation(),
                identifier="add-lookaround",
            )
        ],
        policy=TrustedPolicy,
    )


def test_transformation_output_accepted_by_full_backend(lookaround_transformation_pipeline):
    collection = SigmaCollection.from_yaml(string_rule, policy=TrustedPolicy)
    assert FullRegexTestBackend(lookaround_transformation_pipeline).convert(collection) == [
        "field=/value(?=xyz)/"
    ]


def test_transformation_output_rejected_by_limited_backend(lookaround_transformation_pipeline):
    collection = SigmaCollection.from_yaml(string_rule, policy=TrustedPolicy)
    backend = LimitedRegexTestBackend(lookaround_transformation_pipeline, collect_errors=True)
    backend.convert(collection)
    assert len(backend.errors) == 1
    error_rule, error = backend.errors[0]
    assert error_rule is collection.rules[0]
    assert isinstance(error, SigmaFeatureNotSupportedByBackendError)
    assert "lookaround" in str(error)
    # error is associated with the processing step that introduced the expression
    assert "add-lookaround" in str(error)
