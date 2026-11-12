import pytest
from sigma.processing.tracking import FieldMappingTracking


@pytest.fixture
def field_mapping_tracking():
    return FieldMappingTracking()


def test_field_mapping_tracking_single(field_mapping_tracking: FieldMappingTracking):
    field_mapping_tracking.add_mapping("fieldA", "mappedA")
    assert field_mapping_tracking["fieldA"] == {"mappedA"}


def test_field_mapping_tracking_cascaded(field_mapping_tracking: FieldMappingTracking):
    field_mapping_tracking.add_mapping("fieldA", "mappedA")
    field_mapping_tracking.add_mapping("mappedA", "mappedB")
    assert field_mapping_tracking["fieldA"] == {"mappedB"}
    assert field_mapping_tracking["mappedA"] == {"mappedB"}


def test_field_mapping_tracking_listitem_replaced(
    field_mapping_tracking: FieldMappingTracking,
):
    field_mapping_tracking.add_mapping("fieldA", ["mappedA", "mappedB", "mappedC"])
    field_mapping_tracking.add_mapping("mappedB", "mappedD")
    assert field_mapping_tracking["fieldA"] == {"mappedA", "mappedC", "mappedD"}


def test_field_mapping_tracking_merge():
    field_mapping_tracking = FieldMappingTracking()
    field_mapping_tracking.add_mapping("fieldA", "mappedA")
    field_mapping_tracking.add_mapping("mappedA", "mappedB")
    field_mapping_tracking.add_mapping("fieldB", "mappedC")

    other_field_mapping_tracking = FieldMappingTracking()
    other_field_mapping_tracking.add_mapping("mappedB", "mappedD")
    other_field_mapping_tracking.add_mapping("fieldC", "mappedE")

    field_mapping_tracking.merge(other_field_mapping_tracking)

    assert field_mapping_tracking["fieldA"] == {"mappedD"}
    assert field_mapping_tracking["fieldB"] == {"mappedC"}
    assert field_mapping_tracking["fieldC"] == {"mappedE"}


def test_field_mapping_tracking_collision_keeps_independent_origins():
    """Two origins producing the same target name are tracked separately while no follow-up
    mapping touches the shared name.

    Note: FieldMappingTracking is indexed by field *names* and therefore cannot distinguish two
    origins that share a name which is itself mapped again. The identity-aware gating that must
    not cross origins lives on the detection items (see
    test_field_mapping_same_target_name_does_not_cross_origins).
    """
    tracking = FieldMappingTracking()
    tracking.add_mapping("src", ["shared", "extra"])
    tracking.add_mapping("direct", "shared")

    assert tracking["src"] == {"shared", "extra"}
    assert tracking["direct"] == {"shared"}
    assert tracking.target_fields["shared"] == {"src", "direct"}
    assert tracking.target_fields["extra"] == {"src"}


def test_field_mapping_tracking_diamond_rewrites_both_real_origins():
    """When both origins genuinely flow through the same intermediate field, a follow-up
    mapping must rewrite both chains."""
    tracking = FieldMappingTracking()
    tracking.add_mapping("origin_one", "shared")
    tracking.add_mapping("origin_two", "shared")
    tracking.add_mapping("shared", "final")

    assert tracking["origin_one"] == {"final"}
    assert tracking["origin_two"] == {"final"}


def test_field_mapping_tracking_none_source_cascade():
    """Keyword (None) origins keep behaving like regular origins across cascaded mappings."""
    tracking = FieldMappingTracking()
    tracking.add_mapping(None, ["a", "b"])
    tracking.add_mapping("a", "c")
    assert tracking[None] == {"b", "c"}
    assert tracking["a"] == {"c"}
