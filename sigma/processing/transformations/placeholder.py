from abc import abstractmethod
import re
from typing import (
    ClassVar,
    Iterable,
    Optional,
    Union,
    Iterator,
)
from dataclasses import dataclass, field
from sigma.processing.transformations.base import StringValueTransformation, ValueTransformation
from sigma.exceptions import (
    SigmaValueError,
    SigmaConfigurationError,
)
from sigma.types import (
    Placeholder,
    SigmaString,
    SigmaType,
    SigmaRegularExpression,
    SpecialChars,
    SigmaQueryExpression,
)


@dataclass
class PlaceholderIncludeExcludeMixin:
    include: list[str] | None = field(default=None)
    exclude: list[str] | None = field(default=None)

    def check_exclusivity(self) -> None:
        if self.include is not None and self.exclude is not None:
            raise SigmaConfigurationError(
                "Placeholder transformation include and exclude lists can only be used exclusively!"
            )

    def is_handled_placeholder(self, p: Placeholder) -> bool:
        return (
            (self.include is None and self.exclude is None)
            or (self.include is not None and p.name in self.include)
            or (self.exclude is not None and p.name not in self.exclude)
        )


@dataclass
class BasePlaceholderTransformation(ValueTransformation, PlaceholderIncludeExcludeMixin):
    """
    Placeholder base transformation. The parameters include and exclude can contain variable names that
    are handled by this transformation. Unhandled placeholders are left as they are and must be handled by
    later transformations.
    """

    def __post_init__(self) -> None:
        self.check_exclusivity()
        return super().__post_init__()

    def apply_value(
        self, field: str | None, val: SigmaType
    ) -> (
        None
        | SigmaString
        | Iterable[SigmaString]
        | SigmaRegularExpression
        | Iterable[SigmaRegularExpression]
    ):
        if isinstance(val, (SigmaString, SigmaRegularExpression)) and val.contains_placeholder(
            self.include, self.exclude
        ):
            return val.replace_placeholders(self.placeholder_replacements_base)
        else:
            return None

    def placeholder_replacements_base(
        self, p: Placeholder
    ) -> Iterator[str | SpecialChars | Placeholder | SigmaString]:
        """
        Base placeholder replacement callback. Calls real callback if placeholder is included or not excluded,
        else it passes the placeholder back to caller.
        """
        if self.is_handled_placeholder(p):
            yield from self.placeholder_replacements(p)
        else:
            yield p

    @abstractmethod
    def placeholder_replacements(
        self, p: Placeholder
    ) -> Iterable[str | SpecialChars | Placeholder | SigmaString]:
        """
        Placeholder replacement callback used by SigmaString.replace_placeholders(). This must return one
        of the following object types:

        * Plain strings
        * SpecialChars instances for insertion of wildcards
        * Placeholder instances, it may even return the same placeholder. These must be handled by following processing
          pipeline items or the backend or the conversion will fail.
        * SigmaString instances, these are used to replace the placeholder with a SigmaString that
          may contain plain strings, placeholders and special characters.
        """


@dataclass
class WildcardPlaceholderTransformation(BasePlaceholderTransformation):
    """
    Replaces placeholders with wildcards. This transformation is useful if remaining placeholders should
    be replaced with something meaningful to make conversion of rules possible without defining the
    placeholders content.
    """

    def placeholder_replacements(self, p: Placeholder) -> Iterable[SpecialChars]:
        return [SpecialChars.WILDCARD_MULTI]


@dataclass
class ValueListPlaceholderTransformation(BasePlaceholderTransformation):
    """
    Replaces placeholders with values contained in variables defined in the configuration.

    The replacement values are treated as plain data: wildcard characters and escaping
    sequences contained in them are inserted literally and don't change the matching
    semantics declared by the rule. Backends escape them further as required by the
    target query language, so values can never break out of the value context and alter
    the structure of the generated query. Use QueryExpressionPlaceholderTransformation
    if raw query expressions should be generated from the configuration.

    Exception: placeholders in regular expression values (``|re`` modifier) are replaced
    with the parsed value, because such values are regular expression fragments by
    definition. Like query expressions, these must only come from trusted configuration.
    """

    def apply_value(
        self, field: str | None, val: SigmaType
    ) -> (
        None
        | SigmaString
        | Iterable[SigmaString]
        | SigmaRegularExpression
        | Iterable[SigmaRegularExpression]
    ):
        if isinstance(val, SigmaRegularExpression) and val.contains_placeholder(
            self.include, self.exclude
        ):  # regex values are regex fragments: keep parsing replacements
            return val.replace_placeholders(self.placeholder_replacements_regex_base)
        return super().apply_value(field, val)

    def placeholder_replacements_regex_base(
        self, p: Placeholder
    ) -> Iterator[str | SpecialChars | Placeholder | SigmaString]:
        if self.is_handled_placeholder(p):
            yield from (SigmaString(v) for v in self.replacement_values(p))
        else:
            yield p

    def placeholder_replacements(self, p: Placeholder) -> Iterable[SigmaString]:
        return [SigmaString.from_str(v) for v in self.replacement_values(p)]

    def replacement_values(self, p: Placeholder) -> list[str]:
        try:
            if self._pipeline is None:
                raise SigmaValueError("No pipeline available for placeholder replacement.")
            values = self._pipeline.vars[p.name]
        except KeyError:
            raise SigmaValueError(f"Placeholder replacement variable '{ p.name }' doesn't exists.")

        if not isinstance(values, list):
            values = [values]

        if not values:
            raise SigmaValueError(f"Replacement variable '{ p.name }' is empty.")

        if {isinstance(item, (str, int, float)) for item in values} != {True}:
            raise SigmaValueError(
                f"Replacement variable '{ p.name }' contains value which is not a string or number."
            )

        return [str(v) for v in values]


@dataclass
class QueryExpressionPlaceholderTransformation(
    StringValueTransformation, PlaceholderIncludeExcludeMixin
):
    """
    Replaces a placeholder with a plain query containing the placeholder or an identifier
    mapped from the placeholder name. The main purpose is the generation of arbitrary
    list lookup expressions which are passed to the resulting query.

    .. warning::
       The expression and the mapped identifiers are inserted into the resulting query
       verbatim and are NOT escaped. They are trusted raw query fragments that must only
       be provided and reviewed by the processing pipeline author or another trusted
       configuration source, never from untrusted input such as rule content. Use
       ValueListPlaceholderTransformation for plain data values, which are always escaped.

    Parameters:
    * expression: string that contains query expression with {field} and {id} placeholder
    where placeholder identifier or a mapped identifier is inserted.
    * mapping: Mapping between placeholders and identifiers that should be used in the expression.
    If no mapping is provided the placeholder name is used. In this case the placeholder name is
    inserted into the expression unchanged and must therefore only consist of letters, digits, '_',
    '.' and '-', otherwise a SigmaValueError is raised.
    """

    expression: str = ""
    mapping: dict[str, str] = field(default_factory=dict)
    unmapped_name_pattern: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_.\-]+")

    def __post_init__(self) -> None:
        self.check_exclusivity()
        return super().__post_init__()

    def apply_string_value(self, field: str | None, val: SigmaString) -> SigmaType | None:
        if val.contains_placeholder():
            if len(val.s) == 1 and isinstance(
                val.s[0], Placeholder
            ):  # Sigma string must only contain placeholder, nothing else.
                p = val.s[0]
                if self.is_handled_placeholder(p):
                    mapped_id = self.mapping.get(p.name)
                    if mapped_id:  # Identifier is taken from the pipeline configuration as given.
                        return SigmaQueryExpression(self.expression, mapped_id)
                    if not self.unmapped_name_pattern.fullmatch(p.name):
                        raise SigmaValueError(
                            f"Placeholder name '{p.name}' contains characters that are not allowed "
                            "in query expressions without a mapping (allowed: letters, digits, "
                            "'_', '.', '-'). Use a mapping to provide an identifier for this "
                            "placeholder."
                        )
                    return SigmaQueryExpression(self.expression, p.name)
            else:  # SigmaString contains placeholder as well as other parts
                raise SigmaValueError(
                    "Placeholder query expression transformation only allows placeholder-only strings."
                )
        return None
