from __future__ import annotations

from collections import UserDict, defaultdict
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from sigma.processing.pipeline import ProcessingItemBase


@dataclass
class ProcessingItemTrackingMixin:
    """
    Provides attributes and methods for tracking processing items applied to Sigma rule objects
    like detection items and conditions.
    """

    applied_processing_items: set[str] = field(init=False, compare=False, default_factory=set)

    def add_applied_processing_item(self, processing_item: "ProcessingItemBase" | None) -> None:
        """Add identifier of processing item to set of applied processing items."""
        if processing_item is not None and processing_item.identifier is not None:
            self.applied_processing_items.add(processing_item.identifier)

    def was_processed_by(self, processing_item_id: str) -> bool:
        """Determines if detection item was processed by a processing item with the given id."""
        return processing_item_id in self.applied_processing_items


class FieldMappingTracking(UserDict[str | None, set[str]]):
    """
    Tracking class for field mappings. Tracks initial field name to finally mapped name after a
    processing pipeline was applied. Each key maps the source field to a set of target fields.

    Every origin field keeps an independent mapping chain. When several origins end up at the
    same target field name, the chains are not merged: a follow-up mapping of that name only
    rewrites the chains whose items actually went through the mapping step. This prevents origins
    that merely share a target name from being treated as if they were processed by a step they
    never passed through.

    Currently this class is intentionally only used to track field mappings in detection items and
    the fields list is excluded from it. This might change in the future depending on use cases.
    """

    def __init__(self, *args: list[Any], **kwargs: dict[str, Any]) -> None:
        super().__init__(*args, **kwargs)
        self.target_fields: defaultdict[str | None, set[str | None]] = defaultdict(
            set
        )  # Reverse mapping derived from the per-origin mapping chains.

    def _rebuild_reverse_mapping(self) -> None:
        """Rebuild the target-to-origin reverse mapping from the per-origin forward chains."""
        reverse: defaultdict[str | None, set[str | None]] = defaultdict(set)
        for origin, targets in self.data.items():
            for target in targets:
                reverse[target].add(origin)
        self.target_fields = reverse

    def add_mapping(self, source: str | None, target: str | list[str]) -> None:
        """
        This method must be invoked for each field name mapping applied in a processing pipeline to
        get a precise result of the final mapping.
        """
        if not isinstance(target, list):  # Ensure that the target is a list.
            target = [target]

        if source in self.target_fields:  # Source field was itself a target of a previous mapping.
            # Rewrite only the chains that currently end at the source field. Each origin is
            # updated on its own so that other origins sharing the same target name but never
            # passing through this step stay untouched.
            for origin in self.target_fields[source]:
                target_set = self[origin]
                if source is not None:
                    target_set.discard(source)
                target_set.update(target)
            self._rebuild_reverse_mapping()

            # Keep an intermediate record of the source mapping itself.
            if source not in self:
                self[source] = set(target)
            else:
                self[source].update(target)
        else:
            # A new, not previously mapped origin. Registering it must not alter the chains of
            # other origins, even if one of the target names is already in use.
            if source not in self:
                self[source] = set(target)
            else:
                self[source].update(target)
            for t in target:
                self.target_fields[t].add(source)

    def merge(self, other: "FieldMappingTracking") -> None:
        """Merge another FieldMappingTracking into this one."""
        for source, target_set in other.items():
            self.add_mapping(source, list(target_set))
