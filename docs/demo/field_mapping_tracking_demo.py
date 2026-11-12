"""Short-pipeline demonstration of per-item tracking across 1:N field splits."""
import fnmatch
from sigma.rule import SigmaRule
from sigma.rule.detection import SigmaDetection, SigmaDetectionItem
from sigma.conditions import (
    ConditionAND, ConditionOR, ConditionNOT,
    ConditionFieldEqualsValueExpression, ConditionValueExpression,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.processing.conditions import (
    DetectionItemProcessingItemAppliedCondition,
    FieldNameProcessingItemAppliedCondition,
)
from sigma.backends.test import TextQueryTestBackend
from sigma.types import SigmaString, SigmaNumber, SigmaNull


def walk(cond, depth=0):
    name = type(cond).__name__
    extra = ""
    if isinstance(cond, ConditionFieldEqualsValueExpression):
        extra = f"  {cond.field} = {cond.value.to_plain() if hasattr(cond.value,'to_plain') else cond.value}"
    elif isinstance(cond, ConditionValueExpression):
        extra = f"  _ = {cond.value.to_plain()}"
    print("  " * depth + name + extra)
    for arg in getattr(cond, "args", []) or []:
        walk(arg, depth + 1)


def flatten_items(rule):
    out = []
    for det_name, det in rule.detection.detections.items():
        def collect(d):
            for it in d.detection_items:
                if isinstance(it, SigmaDetection):
                    yield from collect(it)
                else:
                    yield it
        for it in collect(det):
            out.append((det_name, it))
    return out


def leaf_match(cond, event):
    if isinstance(cond, ConditionFieldEqualsValueExpression):
        if cond.field not in event:
            return False
        actual = event[cond.field]
        v = cond.value
        if isinstance(v, SigmaNull):
            return actual is None
        expected = v.to_plain() if hasattr(v, "to_plain") else v
        if isinstance(expected, str) and any(c in expected for c in "*?"):
            return isinstance(actual, str) and fnmatch.fnmatchcase(actual, expected)
        if isinstance(v, SigmaString):
            return actual == expected
        if isinstance(v, SigmaNumber):
            return actual == expected
        return actual == expected
    if isinstance(cond, ConditionValueExpression):
        needle = cond.value.to_plain()
        return any(isinstance(val, str) and needle in val for val in event.values())
    raise TypeError(type(cond))


def evaluate(cond, event):
    if isinstance(cond, (ConditionAND, ConditionOR)):
        results = [evaluate(a, event) for a in cond.args]
        return all(results) if isinstance(cond, ConditionAND) else any(results)
    if isinstance(cond, ConditionNOT):
        return not evaluate(cond.args[0], event)
    return leaf_match(cond, event)


def scenario(title, yaml_doc, items, events):
    print("=" * 84)
    print(title)
    print("=" * 84)
    rule = SigmaRule.from_yaml(yaml_doc)
    print("\n[BEFORE] condition tree:")
    walk(rule.detection.parsed_condition[0].parsed)

    pipeline = ProcessingPipeline(items)
    pipeline.apply(rule)

    print("\n[AFTER] condition tree:")
    walk(rule.detection.parsed_condition[0].parsed)

    print("\n[TRACKING] per detection item (identity-based, survives splits):")
    for det_name, it in flatten_items(rule):
        print(f"   {det_name:8} field={str(it.field):16} applied={sorted(it.applied_processing_items)}")
    print("   field_mappings:", dict(pipeline.field_mappings))

    query = TextQueryTestBackend(pipeline).convert_rule(SigmaRule.from_yaml(yaml_doc))[0]
    print("\n[FINAL QUERY]:", query)

    tree = rule.detection.parsed_condition[0].parsed
    print("\n[EVENT MATCH]:")
    for event in events:
        print(f"   {evaluate(tree, event)!s:5} <- {event}")
    print()


# ---------------------------------------------------------------- scenario 1: 1:N
scenario(
    "1) One-to-many split; guard only touches items that went through the split",
    """
title: t
logsource: {product: test}
detection:
  sel: {src: evil}
  other: {unrelated: x}
  condition: sel or other
""",
    [
        ProcessingItem(identifier="split",
                       transformation=FieldMappingTransformation({"src": ["src_a", "src_b"]})),
        ProcessingItem(identifier="guard",
                       transformation=FieldMappingTransformation(
                           {"src_a": "src_a_sec", "src_b": "src_b_sec"}),
                       detection_item_conditions=[
                           DetectionItemProcessingItemAppliedCondition("split")]),
    ],
    [
        {"src_a_sec": "evil", "src_b_sec": "benign", "unrelated": "z"},  # hit via split branch
        {"src_a": "evil", "src_b": "evil", "unrelated": "z"},            # no hit: guard renamed fields
        {"unrelated": "x"},                                              # hit via untouched OR branch
    ],
)

# ------------------------------------------------- scenario 2: two consecutive 1:N
scenario(
    "2) Two consecutive one-to-many splits; guard gated on the FIRST split",
    """
title: t
logsource: {product: test}
detection:
  sel: {src: evil}
  other: {unrelated: x}
  condition: sel or other
""",
    [
        ProcessingItem(identifier="split1",
                       transformation=FieldMappingTransformation({"src": ["a", "b"]})),
        ProcessingItem(identifier="split2",
                       transformation=FieldMappingTransformation(
                           {"a": ["a1", "a2"], "b": ["b1", "b2"]})),
        ProcessingItem(identifier="guard",
                       transformation=FieldMappingTransformation(
                           {"a1": "a1_g", "a2": "a2_g", "b1": "b1_g", "b2": "b2_g"}),
                       detection_item_conditions=[
                           DetectionItemProcessingItemAppliedCondition("split1")]),
    ],
    [
        {"a1_g": "evil"},                  # hit: history split1 carried through split2
        {"a1": "evil", "b2": "evil"},      # no hit: guard fields expected
        {"unrelated": "x"},                # hit: OR branch never processed
    ],
)

# ------------------------------------- scenario 3: two origins, same target name
scenario(
    "3) Two source fields converge on one target name; guard must not cross origins",
    """
title: t
logsource: {product: test}
detection:
  sel:
    src: evil
    direct: data
  condition: sel
""",
    [
        ProcessingItem(identifier="split",
                       transformation=FieldMappingTransformation(
                           {"src": ["shared", "src_extra"]})),
        ProcessingItem(identifier="alias",
                       transformation=FieldMappingTransformation({"direct": "shared"})),
        ProcessingItem(identifier="guard",
                       transformation=FieldMappingTransformation({"shared": "shared_guarded"}),
                       detection_item_conditions=[
                           DetectionItemProcessingItemAppliedCondition("split")]),
    ],
    [
        {"shared_guarded": "evil", "shared": "data"},  # hit: only split-origin shared was guarded
        {"shared": "evil", "shared_x": "data"},        # no hit: direct-origin stays 'shared'
    ],
)

# ------------------------------------- scenario 4: AND/OR composition with NOT
scenario(
    "4) AND/OR/NOT composition: guarded splits inside an AND with a negated branch",
    """
title: t
logsource: {product: test}
detection:
  sel:
    src: evil
  excl:
    noisy: true
  condition: sel and not excl
""",
    [
        ProcessingItem(identifier="split",
                       transformation=FieldMappingTransformation({"src": ["l", "r"]})),
        ProcessingItem(identifier="guard",
                       transformation=FieldMappingTransformation(
                           {"l": "l_sec", "r": "r_sec"}),
                       detection_item_conditions=[
                           DetectionItemProcessingItemAppliedCondition("split")]),
    ],
    [
        {"l_sec": "evil", "r_sec": "x", "noisy": False},  # hit
        {"l_sec": "evil", "noisy": True},                 # excluded by NOT
        {"l": "evil", "r": "evil"},                       # no hit: unguarded field names
    ],
)
