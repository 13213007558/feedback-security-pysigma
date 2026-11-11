"""Minimal pySigma backend that emits executable SQL predicates for SQLite."""

from __future__ import annotations

import json
from typing import Any, ClassVar, cast

from sigma.backends.test.backend import TextQueryTestBackend
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCasedString,
    SigmaCompareExpression,
    SigmaNull,
    SigmaNumber,
    SigmaString,
)


class SQLiteSemanticBackend(TextQueryTestBackend):
    """Converts the supported condition subset into a SQL WHERE expression.

    The emitted expression references the scalar functions from
    :mod:`tests.semantic_sqlite.sql_functions`, which operate on the JSON event
    document stored in the ``data`` column. Features outside the test subset are
    rejected explicitly rather than converted to SQL with different semantics.
    """

    name: ClassVar[str] = "SQLite semantic test backend"
    formats: ClassVar[dict[str, str]] = {"default": "Executable SQL WHERE clause"}
    backend_processing_pipeline: ClassVar[ProcessingPipeline] = ProcessingPipeline()

    group_expression: ClassVar[str] = "({expr})"
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = " = "

    # No field quoting: fields are passed as SQL text literals to the functions.
    field_quote: ClassVar[str | None] = None
    field_quote_pattern: ClassVar[Any] = None
    str_quote: ClassVar[str] = "'"
    escape_char: ClassVar[str] = "\\"

    # Disable every template that the base class would render into non-SQL text.
    startswith_expression: ClassVar[str | None] = None
    endswith_expression: ClassVar[str | None] = None
    contains_expression: ClassVar[str | None] = None
    wildcard_match_expression: ClassVar[str | None] = None
    case_sensitive_match_expression: ClassVar[str | None] = None
    case_sensitive_startswith_expression: ClassVar[str | None] = None
    case_sensitive_endswith_expression: ClassVar[str | None] = None
    case_sensitive_contains_expression: ClassVar[str | None] = None
    cidr_expression: ClassVar[str | None] = None
    re_expression: ClassVar[str | None] = None
    field_equals_field_expression: ClassVar[str | None] = None
    field_null_expression: ClassVar[str] = "sigma_isnull(data, {field})"
    field_exists_expression: ClassVar[str] = "sigma_exists(data, {field})"
    field_not_exists_expression: ClassVar[str] = "NOT sigma_exists(data, {field})"
    explicit_not_exists_expression: ClassVar[bool] = True

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = True
    in_expressions_allow_wildcards: ClassVar[bool] = True
    field_in_list_expression: ClassVar[str] = (
        "sigma_in_list(data, {field}, {op}, json_array({list}))"
    )
    or_in_operator: ClassVar[str] = "'OR'"
    and_in_operator: ClassVar[str] = "'AND'"
    list_separator: ClassVar[str] = ", "

    _UNSUPPORTED_MESSAGE = (
        " is not part of the restricted SQLite semantic backend condition subset"
    )

    def escape_and_quote_field(self, field_name: str) -> str:
        return self._sql_text(field_name)

    def _sql_text(self, value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def _unsupported(
        self, feature: str, source: Any = None
    ) -> SigmaFeatureNotSupportedByBackendError:
        return SigmaFeatureNotSupportedByBackendError(
            feature + self._UNSUPPORTED_MESSAGE, source=source
        )

    # -- value-only (keyword) conditions are not expressible on a JSON column --
    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        raise self._unsupported("Keyword (unbound) conditions", cond.source)

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        raise self._unsupported("Keyword (unbound) conditions", cond.source)

    def convert_condition_val_re(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        raise self._unsupported("Keyword (unbound) conditions", cond.source)

    def convert_condition_query_expr(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        raise self._unsupported("Query expressions", cond.source)

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise self._unsupported("Regular expression conditions", cond.source)

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise self._unsupported("CIDR conditions", cond.source)

    def convert_condition_field_eq_field(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise self._unsupported("Field reference conditions", cond.source)

    def convert_condition_field_eq_val_timestamp_part(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        raise self._unsupported("Timestamp part conditions", cond.source)

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        field = self.escape_and_quote_field(cond.field)
        value = cast(SigmaString, cond.value)
        if not value.contains_special():
            return f"sigma_eq(data, {field}, {self._sql_text(str(value))})"
        pattern = value.convert(
            self.escape_char, self.wildcard_multi, self.wildcard_single, "", self.filter_chars
        )
        return f"sigma_glob(data, {field}, {self._sql_text(pattern)}, 1)"

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        field = self.escape_and_quote_field(cond.field)
        value = cast(SigmaCasedString, cond.value)
        if not value.contains_special():
            return f"sigma_eq_cased(data, {field}, {self._sql_text(str(value))})"
        pattern = value.convert(
            self.escape_char, self.wildcard_multi, self.wildcard_single, "", self.filter_chars
        )
        return f"sigma_glob(data, {field}, {self._sql_text(pattern)}, 0)"

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        field = self.escape_and_quote_field(cond.field)
        number = cast(SigmaNumber, cond.value).number
        return f"sigma_num_eq(data, {field}, {json.dumps(number)})"

    def convert_condition_field_eq_val_bool(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        field = self.escape_and_quote_field(cond.field)
        boolean = int(cast(SigmaBool, cond.value).boolean)
        return f"sigma_bool_eq(data, {field}, {boolean})"

    def convert_condition_field_compare_op_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        operator_map = {
            CompareOperators.LT: "<",
            CompareOperators.LTE: "<=",
            CompareOperators.GT: ">",
            CompareOperators.GTE: ">=",
            CompareOperators.NEQ: "!=",
        }
        compare = cast(SigmaCompareExpression, cond.value)
        operator = operator_map.get(compare.op)
        if operator is None:  # pragma: no cover - enum is closed
            raise self._unsupported(f"Compare operator {compare.op}", cond.source)
        field = self.escape_and_quote_field(cond.field)
        return f"sigma_compare(data, {field}, '{operator}', {json.dumps(compare.number.number)})"

    def convert_condition_as_in_expression(
        self, cond: ConditionOR | ConditionAND, state: ConversionState
    ) -> str:
        if not all(isinstance(arg, ConditionFieldEqualsValueExpression) for arg in cond.args):
            raise self._unsupported("Mixed-field in-expressions", cond.source)
        first = cast(ConditionFieldEqualsValueExpression, cond.args[0])
        field = self.escape_and_quote_field(first.field)
        values_sql: list[str] = []
        for arg in cond.args:
            expression = cast(ConditionFieldEqualsValueExpression, arg)
            if expression.field != first.field:
                raise self._unsupported("Mixed-field in-expressions", cond.source)
            values_sql.append(self._in_list_value(expression))
        operator = "OR" if isinstance(cond, ConditionOR) else "AND"
        joined = ", ".join(values_sql)
        return f"sigma_in_list(data, {field}, '{operator}', json_array({joined}))"

    def _in_list_value(self, expression: ConditionFieldEqualsValueExpression) -> str:
        """Emit one typed list element as a SQL JSON literal.

        Types are tagged explicitly so the executor never has to guess:
        ``{"t": "str", "v": ...}`` (optionally with a wildcard pattern),
        ``{"t": "num", "v": ...}`` and ``{"t": "null"}``.
        """
        value = expression.value
        if isinstance(value, SigmaString):
            if value.contains_special():
                pattern = value.convert(
                    self.escape_char,
                    self.wildcard_multi,
                    self.wildcard_single,
                    "",
                    self.filter_chars,
                )
                payload = {"t": "glob", "v": pattern}
            else:
                payload = {"t": "str", "v": str(value)}
        elif isinstance(value, SigmaCasedString):
            payload = {"t": "cased", "v": str(value)}
        elif isinstance(value, SigmaNumber):
            payload = {"t": "num", "v": value.number}
        elif isinstance(value, SigmaNull):
            payload = {"t": "null"}
        else:
            raise self._unsupported(
                f"List values of type {value.__class__.__name__}", expression.source
            )
        return "json('" + json.dumps(payload).replace("'", "''") + "')"
