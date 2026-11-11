"""Restricted SQLite execution engine for semantic differential tests.

Events are stored verbatim as JSON documents. No normalization, no empty
string backfills: a missing key is simply absent from the JSON object, and an
explicit null stays an explicit JSON null.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable

from tests.semantic_sqlite.sql_functions import FUNCTIONS


class SQLiteEventEngine:
    """Holds an in-memory SQLite table populated with JSON-encoded events."""

    def __init__(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        for name, arity, function in FUNCTIONS:
            self.connection.create_function(name, arity, function)
        self.connection.execute(
            "CREATE TABLE events (event_id TEXT PRIMARY KEY, data TEXT NOT NULL)"
        )

    def load(self, events: dict[str, dict[str, Any]]) -> None:
        rows = [
            (event_id, json.dumps(data, ensure_ascii=False))
            for event_id, data in events.items()
        ]
        self.connection.executemany(
            "INSERT INTO events(event_id, data) VALUES (?, ?)", rows
        )

    def query(self, where_sql: str) -> set[str]:
        """Return the set of event_ids selected by a converted WHERE clause."""
        cursor = self.connection.execute(
            "SELECT event_id FROM events WHERE " + where_sql
        )
        return {row[0] for row in cursor.fetchall()}

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> SQLiteEventEngine:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def convert_rule_to_sql(rule: Any, backend: Any) -> str:
    """Convert a single SigmaRule to one SQL WHERE expression via the backend."""
    from sigma.collection import SigmaCollection

    queries = backend.convert(SigmaCollection([rule]))
    if len(queries) != 1:
        raise AssertionError(f"Expected one converted query, got {queries!r}")
    return cast_str(queries[0])


def cast_str(value: Any) -> str:
    if not isinstance(value, str):
        raise AssertionError(f"Backend returned non-string query: {value!r}")
    return value


def run_rules(
    rules: Iterable[Any], backend: Any, events: dict[str, dict[str, Any]]
) -> dict[str, set[str]]:
    """Return {rule_name: matched event_id set} for every convertible rule."""
    engine = SQLiteEventEngine()
    engine.load(events)
    results: dict[str, set[str]] = {}
    try:
        for rule in rules:
            where_sql = convert_rule_to_sql(rule, backend)
            results[rule.name] = engine.query(where_sql)
    finally:
        engine.close()
    return results
