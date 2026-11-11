from __future__ import annotations

from collections import defaultdict
from statistics import median
from typing import Any

from sigma.correlations import (
    CorrelationConditionAND,
    CorrelationConditionItem,
    CorrelationConditionNOT,
    CorrelationConditionOR,
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
    SigmaExtendedCorrelationCondition,
    SigmaRuleReference,
)
from sigma.matching.event import Event
from sigma.matching.match import SigmaMatch
from sigma.matching.state import SlidingWindowState


class SigmaCorrelationRuleMatcher:
    """Evaluates a SigmaCorrelationRule by tracking matches from referenced base rules."""

    def __init__(
        self,
        rule: SigmaCorrelationRule,
        max_state: int | None = None,
        max_events_per_match: int | None = 100,
    ) -> None:
        self.rule = rule
        self.max_events_per_match = max_events_per_match
        self._state = SlidingWindowState(
            window_seconds=rule.timespan.seconds,
            max_entries=max_state,
        )
        # Track which base rule names are relevant
        self._rule_names: set[str] = set()
        if rule.rules:
            for ref in rule.rules:
                self._rule_names.add(ref.reference)
        elif isinstance(rule.condition, SigmaExtendedCorrelationCondition):
            for name in rule.condition.get_referenced_rules():
                self._rule_names.add(name)

    def receive_match(self, match: SigmaMatch, source_rule_name: str) -> list[SigmaMatch]:
        """Process an incoming match from a base rule and return correlation matches if any."""
        group_key = self._extract_group_key(match)
        self._state.add(group_key, match)

        window_matches = self._state.get_window(group_key, match.timestamp)
        result = self._evaluate(window_matches, group_key, match.timestamp)
        return result

    def _extract_group_key(self, match: SigmaMatch) -> tuple[Any, ...]:
        """Extract group-by field values from match events."""
        if not self.rule.group_by:
            return ()

        values: list[Any] = []
        event = match.events[0] if match.events else None
        if event is None:
            return tuple(None for _ in self.rule.group_by)

        for field_name in self.rule.group_by:
            # Check aliases
            resolved_field = self._resolve_alias(field_name, match)
            values.append(event.data.get(resolved_field))
        return tuple(values)

    def _resolve_alias(self, field_name: str, match: SigmaMatch) -> str:
        """Resolve field alias to actual field name based on source rule."""
        if field_name in self.rule.aliases.aliases:
            alias = self.rule.aliases.aliases[field_name]
            # Try to find mapping for the source rule
            for ref, mapped_field in alias.mapping.items():
                if hasattr(ref, "rule") and ref.rule is match.rule:
                    return mapped_field
        return field_name

    def _evaluate(
        self,
        window_matches: list[SigmaMatch],
        group_key: tuple[Any, ...],
        now: Any,
    ) -> list[SigmaMatch]:
        """Evaluate the correlation condition against current window state."""
        ctype = self.rule.type
        condition = self.rule.condition

        if ctype == SigmaCorrelationType.EVENT_COUNT:
            return self._eval_event_count(window_matches, group_key, now, condition)
        elif ctype == SigmaCorrelationType.VALUE_COUNT:
            return self._eval_value_count(window_matches, group_key, now, condition)
        elif ctype == SigmaCorrelationType.TEMPORAL:
            return self._eval_temporal(window_matches, group_key, now)
        elif ctype == SigmaCorrelationType.TEMPORAL_ORDERED:
            return self._eval_temporal_ordered(window_matches, group_key, now)
        elif ctype == SigmaCorrelationType.VALUE_SUM:
            return self._eval_value_aggregate(window_matches, group_key, now, condition, "sum")
        elif ctype == SigmaCorrelationType.VALUE_AVG:
            return self._eval_value_aggregate(window_matches, group_key, now, condition, "avg")
        elif ctype == SigmaCorrelationType.VALUE_MEDIAN:
            return self._eval_value_aggregate(window_matches, group_key, now, condition, "median")
        elif ctype == SigmaCorrelationType.VALUE_PERCENTILE:
            return self._eval_value_aggregate(
                window_matches, group_key, now, condition, "percentile"
            )
        return []

    def _compare(
        self, op: SigmaCorrelationConditionOperator, value: Any, threshold: int | float
    ) -> bool:
        """Compare a value against a threshold using the given operator."""
        if value is None:
            return False
        op_map = {
            SigmaCorrelationConditionOperator.LT: lambda a, b: a < b,
            SigmaCorrelationConditionOperator.LTE: lambda a, b: a <= b,
            SigmaCorrelationConditionOperator.GT: lambda a, b: a > b,
            SigmaCorrelationConditionOperator.GTE: lambda a, b: a >= b,
            SigmaCorrelationConditionOperator.EQ: lambda a, b: a == b,
            SigmaCorrelationConditionOperator.NEQ: lambda a, b: a != b,
        }
        return bool(op_map[op](value, threshold))

    def _collect_events(self, matches: list[SigmaMatch]) -> list[Event]:
        """Collect events from matches, respecting the max_events_per_match limit.

        The same event object is included only once, even if several matches
        reference it (one event hitting multiple base rules, duplicate delivery).
        """
        events: list[Event] = []
        seen: set[int] = set()
        limit = self.max_events_per_match
        for m in matches:
            for e in m.events:
                if id(e) in seen:
                    continue
                if limit is not None and len(events) >= limit:
                    return events
                seen.add(id(e))
                events.append(e)
        return events

    def _make_group_values(self, group_key: tuple[Any, ...]) -> dict[str, Any] | None:
        if not self.rule.group_by:
            return None
        return dict(zip(self.rule.group_by, group_key))

    def _eval_event_count(
        self,
        matches: list[SigmaMatch],
        group_key: tuple[Any, ...],
        now: Any,
        condition: Any,
    ) -> list[SigmaMatch]:
        if not isinstance(condition, SigmaCorrelationCondition):
            return []
        count = len(matches)
        if self._compare(condition.op, count, condition.count):
            return [
                SigmaMatch(
                    rule=self.rule,
                    events=self._collect_events(matches),
                    timestamp=now,
                    group_values=self._make_group_values(group_key),
                )
            ]
        return []

    def _eval_value_count(
        self,
        matches: list[SigmaMatch],
        group_key: tuple[Any, ...],
        now: Any,
        condition: Any,
    ) -> list[SigmaMatch]:
        if not isinstance(condition, SigmaCorrelationCondition):
            return []
        field_ref = condition.fieldref
        if field_ref is None:
            return []
        # Count distinct values of the field
        values: set[Any] = set()
        for m in matches:
            for e in m.events:
                val = e.data.get(field_ref)  # type: ignore[arg-type]
                if val is not None:
                    values.add(val)
        if self._compare(condition.op, len(values), condition.count):
            return [
                SigmaMatch(
                    rule=self.rule,
                    events=self._collect_events(matches),
                    timestamp=now,
                    group_values=self._make_group_values(group_key),
                )
            ]
        return []

    def _eval_extended_expr(
        self, node: CorrelationConditionItem | SigmaRuleReference, fired_rules: set[str]
    ) -> bool:
        """Recursively evaluate a boolean extended correlation condition expression."""
        if isinstance(node, SigmaRuleReference):
            return node.reference in fired_rules
        elif isinstance(node, CorrelationConditionAND):
            return all(self._eval_extended_expr(arg, fired_rules) for arg in node.args)
        elif isinstance(node, CorrelationConditionOR):
            return any(self._eval_extended_expr(arg, fired_rules) for arg in node.args)
        elif isinstance(node, CorrelationConditionNOT):
            return not self._eval_extended_expr(node.args[0], fired_rules)
        return False

    def _eval_ordered_extended_expr(
        self,
        node: CorrelationConditionItem | SigmaRuleReference,
        rule_timestamps: dict[str, list[Any]],
        after: Any = None,
    ) -> tuple[bool, Any]:
        """Evaluate a boolean expression with ordering constraints.

        rule_timestamps maps each referenced rule name to its sorted match timestamps.
        Returns (satisfied, end_timestamp) where end_timestamp is the earliest timestamp
        at which the sub-expression can be satisfied using only matches strictly after
        `after` (None for negated sub-expressions, which contribute no ordering
        constraint). Strictly increasing timestamps are required between successive
        AND operands, so a single event can never satisfy two successive operands.
        """
        if isinstance(node, SigmaRuleReference):
            for ts in rule_timestamps.get(node.reference, ()):
                if after is None or ts > after:
                    return True, ts
            return False, None
        elif isinstance(node, CorrelationConditionAND):
            end = after
            for arg in node.args:
                ok, ts = self._eval_ordered_extended_expr(arg, rule_timestamps, end)
                if not ok:
                    return False, None
                if ts is not None:
                    end = ts
            return True, end
        elif isinstance(node, CorrelationConditionOR):
            satisfied = False
            best: Any = None
            for arg in node.args:
                ok, ts = self._eval_ordered_extended_expr(arg, rule_timestamps, after)
                if ok:
                    satisfied = True
                    if ts is not None and (best is None or ts < best):
                        best = ts
            return satisfied, best
        elif isinstance(node, CorrelationConditionNOT):
            ok, _ = self._eval_ordered_extended_expr(node.args[0], rule_timestamps)
            return not ok, None
        return False, None

    def _eval_temporal(
        self,
        matches: list[SigmaMatch],
        group_key: tuple[Any, ...],
        now: Any,
    ) -> list[SigmaMatch]:
        """All referenced rules must fire within the time window.

        Set semantics: every referenced rule needs at least one match in the
        window. Duplicate rule references collapse, duplicate delivery of a
        match does not change the outcome, and one event hitting several
        referenced rules satisfies each of them.
        """
        if isinstance(self.rule.condition, SigmaExtendedCorrelationCondition):
            fired_rules: set[str] = {
                name for m in matches if (name := getattr(m.rule, "name", None))
            }
            if self._eval_extended_expr(self.rule.condition.parsed, fired_rules):
                return [
                    SigmaMatch(
                        rule=self.rule,
                        events=self._collect_events(matches),
                        timestamp=now,
                        group_values=self._make_group_values(group_key),
                    )
                ]
            return []
        matched_rules: set[str] = set()
        for m in matches:
            if hasattr(m.rule, "name") and m.rule.name:
                matched_rules.add(m.rule.name)
        if self._rule_names and self._rule_names.issubset(matched_rules):
            return [
                SigmaMatch(
                    rule=self.rule,
                    events=self._collect_events(matches),
                    timestamp=now,
                    group_values=self._make_group_values(group_key),
                )
            ]
        return []

    def _eval_temporal_ordered(
        self,
        matches: list[SigmaMatch],
        group_key: tuple[Any, ...],
        now: Any,
    ) -> list[SigmaMatch]:
        """All referenced rules must fire in order within the time window.

        Ordering criterion: successive referenced rules must be satisfied by matches
        with strictly increasing event timestamps. Matches with equal timestamps
        (one event hitting several rules, distinct events sharing a timestamp,
        duplicate delivery) cannot establish an order and never satisfy two
        successive positions, so the result never depends on traversal order.
        """
        if isinstance(self.rule.condition, SigmaExtendedCorrelationCondition):
            rule_timestamps: dict[str, list[Any]] = defaultdict(list)
            for m in matches:
                name = getattr(m.rule, "name", None)
                if name:
                    rule_timestamps[name].append(m.timestamp)
            for timestamps in rule_timestamps.values():
                timestamps.sort()
            ok, _ = self._eval_ordered_extended_expr(self.rule.condition.parsed, rule_timestamps)
            if ok:
                return [
                    SigmaMatch(
                        rule=self.rule,
                        events=self._collect_events(matches),
                        timestamp=now,
                        group_values=self._make_group_values(group_key),
                    )
                ]
            return []
        if not self.rule.rules:
            return []
        expected_order = [ref.reference for ref in self.rule.rules]
        # Greedily match the expected rule sequence against matches sorted by
        # timestamp, requiring strictly increasing timestamps between positions.
        seen_idx = 0
        last_ts: Any = None
        for m in sorted(matches, key=lambda x: x.timestamp):
            if not (hasattr(m.rule, "name") and m.rule.name == expected_order[seen_idx]):
                continue
            if last_ts is not None and m.timestamp <= last_ts:
                continue
            last_ts = m.timestamp
            seen_idx += 1
            if seen_idx >= len(expected_order):
                return [
                    SigmaMatch(
                        rule=self.rule,
                        events=self._collect_events(matches),
                        timestamp=now,
                        group_values=self._make_group_values(group_key),
                    )
                ]
        return []

    def _eval_value_aggregate(
        self,
        matches: list[SigmaMatch],
        group_key: tuple[Any, ...],
        now: Any,
        condition: Any,
        agg_type: str,
    ) -> list[SigmaMatch]:
        if not isinstance(condition, SigmaCorrelationCondition):
            return []
        field_ref = condition.fieldref
        if field_ref is None:
            return []

        values: list[float] = []
        for m in matches:
            for e in m.events:
                val = e.data.get(field_ref)  # type: ignore[arg-type]
                if val is not None:
                    try:
                        values.append(float(val))
                    except (ValueError, TypeError):
                        pass

        if not values:
            return []

        if agg_type == "sum":
            result = sum(values)
        elif agg_type == "avg":
            result = sum(values) / len(values)
        elif agg_type == "median":
            result = median(values)
        elif agg_type == "percentile":
            percentile = condition.percentile or 95
            sorted_vals = sorted(values)
            idx = int(len(sorted_vals) * percentile / 100)
            idx = min(idx, len(sorted_vals) - 1)
            result = sorted_vals[idx]
        else:
            return []

        if self._compare(condition.op, result, condition.count):
            return [
                SigmaMatch(
                    rule=self.rule,
                    events=self._collect_events(matches),
                    timestamp=now,
                    group_values=self._make_group_values(group_key),
                )
            ]
        return []
