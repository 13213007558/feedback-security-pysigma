from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import InitVar, dataclass, field
from functools import reduce
from pathlib import Path
from typing import IO, Any, Callable, cast
from uuid import UUID

import yaml
from typing import Self

from sigma.correlations import SigmaCorrelationRule, SigmaRuleReference
from sigma.exceptions import (
    SigmaAliasReferenceError,
    SigmaAmbiguousRuleNameError,
    SigmaCollectionError,
    SigmaCorrelationCycleError,
    SigmaDuplicateIdentifierError,
    SigmaError,
    SigmaRuleLocation,
    SigmaRuleNotFoundError,
)
from sigma.filters import SigmaFilter
from sigma.rule import SigmaRule, SigmaRuleBase
from sigma.rule.base import check_alias_expansion
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sigma.policy import SigmaPolicy

NestedDict = dict[str, "str | int | float | bool | None | NestedDict"]
RuleIdentifierIndex = dict[str, list["SigmaRule | SigmaCorrelationRule"]]
ReferencePlan = dict[
    int,
    list[tuple["SigmaRuleReference", "SigmaRule | SigmaCorrelationRule"]],
]


@dataclass
class SigmaCollection:
    """Collection of Sigma rules"""

    init_rules: InitVar[list[SigmaRule | SigmaCorrelationRule | SigmaFilter]]
    errors: list[SigmaError] = field(default_factory=list)
    collect_filters: InitVar[bool] = False
    resolve_references: InitVar[bool] = True
    rules: list[SigmaRule | SigmaCorrelationRule] = field(default_factory=list)
    filters: list[SigmaFilter] = field(default_factory=list)
    ids_to_rules: dict[UUID, SigmaRule | SigmaCorrelationRule] = field(
        init=False, repr=False, hash=False, compare=False
    )
    names_to_rules: dict[str, SigmaRule | SigmaCorrelationRule] = field(
        init=False, repr=False, hash=False, compare=False
    )
    _references_resolved: bool = field(
        init=False, repr=False, hash=False, compare=False, default=False
    )
    _filters_applied: bool = field(
        init=False, repr=False, hash=False, compare=False, default=False
    )

    def __post_init__(
        self: Self,
        init_rules: list[SigmaRule | SigmaCorrelationRule | SigmaFilter],
        collect_filters: bool,
        resolve_references: bool,
    ) -> None:
        """
        Map rule identifiers to rules and resolve rule references in correlation rules.
        """
        self.ids_to_rules = {}
        self.names_to_rules = {}
        for rule in init_rules:
            if isinstance(rule, (SigmaRule, SigmaCorrelationRule)):
                self.rules.append(rule)
                if rule.id is not None:
                    self.ids_to_rules[rule.id] = rule
                if rule.name is not None:
                    self.names_to_rules[rule.name] = rule
            elif isinstance(rule, SigmaFilter):
                self.filters.append(rule)
            else:
                raise TypeError(f"Object of type { type(rule) } not supported in SigmaCollection")
        # By default resolve rule references after initialization. This also applies the collected
        # filters. It can be disabled by passing resolve_references=False as an init-only parameter.
        if resolve_references:
            self.resolve_rule_references()

    def apply_filters(self: Self, filters: list[SigmaFilter]) -> None:
        """
        Apply filters on each rule and replace the rule with the filtered rule
        """
        self.rules = [
            reduce(
                lambda r, f: f.apply_on_rule(r) if isinstance(r, SigmaRule) else r,
                filters,
                rule,
            )
            for rule in self.rules
        ]
        # Filtered rule objects replace the previous ones, so any resolved reference state is
        # stale. Invalidate it; the next conversion/matching call resolves the collection again.
        self._invalidate_resolved_references()

    def _invalidate_resolved_references(self: Self) -> None:
        """Mark the collection as unresolved without leaving partially resolved rule objects."""
        for rule in self.rules:
            rule._backreferences = []
            rule._output = True
            if isinstance(rule, SigmaCorrelationRule):
                rule.referenced_rules = []
                for rule_ref in rule.iter_rule_references():
                    if hasattr(rule_ref, "rule"):
                        del rule_ref.rule
                for alias_ref in rule.iter_alias_references():
                    if hasattr(alias_ref, "rule"):
                        del alias_ref.rule
        self.ids_to_rules = {}
        self.names_to_rules = {}
        self._filters_applied = False
        self._references_resolved = False

    @staticmethod
    def _rule_label(rule: SigmaRule | SigmaCorrelationRule) -> str:
        """Stable textual identifier of a rule, used in error messages and reference chains."""
        if rule.name is not None:
            return rule.name
        if rule.id is not None:
            return str(rule.id)
        if rule.source is not None:
            return str(rule.source)
        return rule.title or type(rule).__name__

    @staticmethod
    def _rule_sort_key(rule: SigmaRule | SigmaCorrelationRule) -> tuple[str, str]:
        """Deterministic ordering key independent of file load order."""
        source = str(rule.source.path) if rule.source is not None else ""
        return (SigmaCollection._rule_label(rule), source)

    @staticmethod
    def _describe_rule(rule: SigmaRule | SigmaCorrelationRule) -> str:
        """Describe a rule together with its source location for error messages."""
        description = SigmaCollection._rule_label(rule)
        if rule.source is not None:
            description += f" (at { rule.source })"
        return description

    def _build_identifier_indexes(
        self: Self,
    ) -> tuple[
        dict[UUID, list[SigmaRule | SigmaCorrelationRule]],
        RuleIdentifierIndex,
    ]:
        """
        Build multi-valued id/name indexes. Duplicates are kept here so that they can be reported
        as deterministic errors instead of silently overwriting each other based on load order.
        """
        ids_index: dict[UUID, list[SigmaRule | SigmaCorrelationRule]] = {}
        names_index: RuleIdentifierIndex = {}
        for rule in self.rules:
            if rule.id is not None:
                ids_index.setdefault(rule.id, []).append(rule)
            if rule.name is not None:
                names_index.setdefault(rule.name, []).append(rule)
        return ids_index, names_index

    def _check_identifier_conflicts(
        self: Self,
        ids_index: dict[UUID, list[SigmaRule | SigmaCorrelationRule]],
        names_index: RuleIdentifierIndex,
    ) -> None:
        """
        Fail deterministically on duplicate ids.

        Duplicate rule names are not an error by themselves: the rules may coexist as long as
        nobody refers to the ambiguous name. Name ambiguity is raised when a reference actually
        resolves through the name (see :meth:`_lookup_rule`), so the outcome never depends on
        which of the same-named rules was loaded first.
        """
        for rule_id in sorted(ids_index, key=lambda identifier: str(identifier)):
            rules = ids_index[rule_id]
            if len(rules) > 1:
                raise SigmaDuplicateIdentifierError(
                    f"Duplicate rule id '{ rule_id }' used by: "
                    + "; ".join(self._describe_rule(rule) for rule in rules),
                    reference_chain=[str(rule_id)],
                )

    def _lookup_rule(
        self: Self,
        reference: str,
        ids_index: dict[UUID, list[SigmaRule | SigmaCorrelationRule]],
        names_index: RuleIdentifierIndex,
        chain: list[str],
        source: SigmaRuleLocation | None,
    ) -> SigmaRule | SigmaCorrelationRule | None:
        """Deterministic lookup: UUID references resolve by id, everything else by name."""
        try:
            rule_id = UUID(reference)
        except ValueError:
            candidates = names_index.get(reference)
            if candidates is not None and len(candidates) > 1:
                raise SigmaAmbiguousRuleNameError(
                    f"Rule name '{ reference }' is ambiguous, it is used by: "
                    + "; ".join(self._describe_rule(rule) for rule in candidates),
                    source=source,
                    reference_chain=chain,
                )
        else:
            candidates = ids_index.get(rule_id)
        if not candidates:
            return None
        return candidates[0]

    def _validate_and_plan_references(
        self: Self,
        ids_index: dict[UUID, list[SigmaRule | SigmaCorrelationRule]],
        names_index: RuleIdentifierIndex,
    ) -> tuple[ReferencePlan, ReferencePlan]:
        """
        Resolve every reference of every correlation rule without mutating any rule.

        Detects missing references, references that appear only in field aliases and dependency
        cycles. Forward references are legal because the whole collection is available. Errors
        carry the referencing rule's source location and the full reference chain.
        """
        # Reference string -> rule object; conflicts were checked before, so this is load-order
        # independent.
        resolved: dict[str, SigmaRule | SigmaCorrelationRule] = {}

        def resolve_reference(
            reference: str,
            chain: list[str],
            source: SigmaRuleLocation | None,
        ) -> SigmaRule | SigmaCorrelationRule:
            if reference in resolved:
                return resolved[reference]
            target = self._lookup_rule(reference, ids_index, names_index, chain, source)
            if target is None:
                raise SigmaRuleNotFoundError(
                    f"Rule '{ reference }' not found in rule collection",
                    source=source,
                    reference_chain=chain,
                )
            resolved[reference] = target
            return target

        # First pass: resolve the dependency references of each correlation rule and remember the
        # planned reference -> rule mappings. Alias-only references are detected alongside.
        plan: ReferencePlan = {}
        alias_plan: ReferencePlan = {}
        for correlation in self.rules:
            if not isinstance(correlation, SigmaCorrelationRule):
                continue
            chain_prefix = [self._rule_label(correlation)]
            dependency_strings: set[str] = set()
            correlation_plan: list[
                tuple[SigmaRuleReference, SigmaRule | SigmaCorrelationRule]
            ] = []
            for rule_ref in correlation.iter_rule_references():
                dependency_strings.add(rule_ref.reference)
                target = resolve_reference(
                    rule_ref.reference,
                    chain_prefix + [rule_ref.reference],
                    correlation.source,
                )
                correlation_plan.append((rule_ref, target))
            plan[id(correlation)] = correlation_plan

            correlation_alias_plan: list[
                tuple[SigmaRuleReference, SigmaRule | SigmaCorrelationRule]
            ] = []
            for alias_ref in correlation.iter_alias_references():
                target = resolve_reference(
                    alias_ref.reference,
                    chain_prefix + [alias_ref.reference],
                    correlation.source,
                )
                correlation_alias_plan.append((alias_ref, target))
                if alias_ref.reference not in dependency_strings:
                    raise SigmaAliasReferenceError(
                        f"Rule '{ alias_ref.reference }' is referenced in a field alias of "
                        f"'{ self._rule_label(correlation) }' but not in its rule references",
                        source=correlation.source,
                        reference_chain=chain_prefix + [alias_ref.reference],
                    )
            alias_plan[id(correlation)] = correlation_alias_plan

        self._detect_reference_cycles(plan)
        return plan, alias_plan

    def _detect_reference_cycles(self: Self, plan: ReferencePlan) -> None:
        """
        Detect cycles in the correlation-rule dependency graph using an iterative,
        order-independent DFS. The reported cycle starts from the deterministically smallest
        correlation rule on the cycle.
        """
        graph: dict[int, list[SigmaCorrelationRule]] = {}
        for rule in self.rules:
            if isinstance(rule, SigmaCorrelationRule):
                graph[id(rule)] = [
                    target
                    for _, target in plan.get(id(rule), [])
                    if isinstance(target, SigmaCorrelationRule)
                ]

        state: dict[int, int] = {}  # 0 = unvisited, 1 = on stack, 2 = done
        stack_path: list[SigmaCorrelationRule] = []

        def raise_cycle(cycle_start: SigmaCorrelationRule) -> None:
            start_index = stack_path.index(cycle_start)
            cycle_nodes = stack_path[start_index:] + [cycle_start]
            chain = [self._rule_label(rule) for rule in cycle_nodes]
            raise SigmaCorrelationCycleError(
                "Cyclic rule reference detected: " + " -> ".join(chain),
                source=cycle_start.source,
                reference_chain=chain,
            )

        correlation_roots = [rule for rule in self.rules if id(rule) in graph]
        for root in sorted(correlation_roots, key=self._rule_sort_key):
            if id(root) in state:
                continue
            work: list[tuple[SigmaCorrelationRule, int]] = [(root, 0)]
            state[id(root)] = 1
            stack_path = [root]
            while work:
                node, next_child = work[-1]
                children = graph[id(node)]
                if next_child < len(children):
                    work[-1] = (node, next_child + 1)
                    child = children[next_child]
                    child_state = state.get(id(child))
                    if child_state == 1:
                        raise_cycle(child)
                    elif child_state is None:
                        state[id(child)] = 1
                        stack_path.append(child)
                        work.append((child, 0))
                else:
                    state[id(node)] = 2
                    stack_path.pop()
                    work.pop()

    def resolve_rule_references(self: Self) -> None:
        """
        Resolve rule references in correlation rules to the actual rule objects and order the
        rules so that every rule comes after the rules it refers to.

        Validation is performed for the whole collection first. Only if every reference (rule
        lists, extended correlation conditions and field aliases) is valid, the resolved state is
        applied atomically: a failure never leaves a partially resolved collection behind. The
        result is independent of the order in which the rules were loaded and calling the method
        again on an already resolved collection is a no-op.

        This must be called before referencing rules are converted into queries or events are
        matched.
        """
        # Filters embedded in the rules list have not been applied yet. Filters kept in
        # self.filters were either deferred (load_ruleset/collect_filters) or already applied and
        # retained for inspection; the _filters_applied flag tells the two cases apart.
        pending_filters = (
            []
            if self._filters_applied
            else list(self.filters)
        ) + [
            cast("SigmaFilter", rule) for rule in self.rules if isinstance(rule, SigmaFilter)
        ]
        if self._references_resolved and not pending_filters:
            return

        # Filters are applied to Sigma rules first. They never apply to correlation rules and thus
        # cannot change the reference graph validated below.
        if pending_filters:
            self.rules = [rule for rule in self.rules if not isinstance(rule, SigmaFilter)]
            self.rules = [
                reduce(lambda r, f: f.apply_on_rule(r), pending_filters, rule)
                for rule in self.rules
            ]
            # Keep the applied filters available for inspection (collect_filters semantics) and
            # remember that they must not be applied again.
            self.filters = self.filters + [
                cast("SigmaFilter", rule)
                for rule in pending_filters
                if rule not in self.filters
            ]
            self._filters_applied = True
            self._references_resolved = False

        ids_index, names_index = self._build_identifier_indexes()
        self._check_identifier_conflicts(ids_index, names_index)
        plan, alias_plan = self._validate_and_plan_references(ids_index, names_index)

        # All checks passed: apply the planned resolution. Reset mutable per-rule state first so
        # that re-resolution cannot accumulate duplicate backreferences or leave output disabled.
        for rule in self.rules:
            rule._backreferences = []
            rule._output = True
            if isinstance(rule, SigmaCorrelationRule):
                rule.referenced_rules = []
                for rule_ref in rule.iter_rule_references():
                    if hasattr(rule_ref, "rule"):
                        del rule_ref.rule
                for alias_ref in rule.iter_alias_references():
                    if hasattr(alias_ref, "rule"):
                        del alias_ref.rule

        for correlation in self.rules:
            if not isinstance(correlation, SigmaCorrelationRule):
                continue
            mappings = plan.get(id(correlation), [])
            correlation.referenced_rules = [rule_ref for rule_ref, _ in mappings]
            for rule_ref, target in mappings:
                rule_ref.rule = target
                target.add_backreference(correlation)
                if not correlation.generate:
                    target.disable_output()
            for alias_ref, target in alias_plan.get(id(correlation), []):
                alias_ref.rule = target

        # Order rules so that every rule comes after the rules it refers to
        self.rules = self._referenced_first(self.rules)
        self.ids_to_rules = {
            rule.id: rule for rule in self.rules if rule.id is not None
        }
        self.names_to_rules = {
            rule.name: rule for rule in self.rules if rule.name is not None
        }
        self._references_resolved = True

    @staticmethod
    def _referenced_first(
        rules: list[SigmaRule | SigmaCorrelationRule],
    ) -> list[SigmaRule | SigmaCorrelationRule]:
        """
        Order rules so that every rule comes after the rules it refers to. A referenced rule moves up
        to just before the first rule that refers to it; the order is otherwise kept.

        Sorting by "is referenced by" is not enough: that comparison is only a partial order, and
        a sort leaves e.g. [correlation, unrelated rule, rule referenced by the correlation] as it
        is. The correlation is then converted before the rule it refers to, and conversion fails
        with "Conversion result not available".
        """
        # Backreferences cover every way a rule refers to another (a correlation's rules and the
        # rules named in an extended condition).
        refers_to: dict[int, list[SigmaRule | SigmaCorrelationRule]] = {}
        for rule in rules:
            for referencing in rule._backreferences:
                refers_to.setdefault(id(referencing), []).append(rule)
        ordered: list[SigmaRule | SigmaCorrelationRule] = []
        placed: set[int] = set()

        def place(rule: SigmaRule | SigmaCorrelationRule) -> None:
            if id(rule) in placed:
                return
            placed.add(id(rule))
            for referenced in refers_to.get(id(rule), []):
                place(referenced)
            ordered.append(rule)

        for rule in rules:
            place(rule)
        return ordered

    @classmethod
    def from_dicts(
        cls: type[Self],
        rules: list[NestedDict],
        collect_errors: bool = False,
        source: SigmaRuleLocation | None = None,
        collect_filters: bool = False,
        resolve_references: bool = True,
        policy: "SigmaPolicy | None" = None,
    ) -> Self:
        """
        Generate a rule collection from list of dicts containing parsed YAML content.

        If the collect_errors parameters is set, exceptions are not raised while parsing but collected
        in the errors property individually for each Sigma rule and the whole SigmaCollection.

        If collect_filters is set, filters are only collected in the collection but not yet applied to the rules.
        """
        errors: list[SigmaError] = []
        parsed_rules: list[SigmaRule | SigmaCorrelationRule | SigmaFilter] = list()
        prev_rule = dict()
        global_rule: NestedDict = dict()

        for i, rule in zip(range(1, len(rules) + 1), rules):
            if rule is None:  # empty YAML document, e.g. from a trailing '---'
                continue
            if isinstance(
                rule, SigmaRule
            ):  # Included rules are already parsed, skip collection action processing
                parsed_rules.append(rule)
                rule.source = source
            else:
                try:  # reject alias bombs before global/repeat merging walks the document
                    check_alias_expansion(rule, SigmaCollectionError, source)
                except SigmaCollectionError as expansion_error:
                    if collect_errors:
                        errors.append(expansion_error)
                        continue
                    raise
                action = rule.get("action")
                if action is None:  # no action defined
                    if "correlation" in rule:  # correlation rule - no global rule merge
                        parsed_correlation_rule: SigmaCorrelationRule = (
                            SigmaCorrelationRule.from_dict(
                                rule,
                                collect_errors,
                                source,
                            )
                        )
                        parsed_rules.append(parsed_correlation_rule)
                        errors.extend(parsed_correlation_rule.errors)  # Propagate errors from rule
                    elif "filter" in rule:  # correlation rule - no global rule merge
                        parsed_filter_rule = SigmaFilter.from_dict(
                            rule,
                            collect_errors,
                            source,
                            policy=policy,
                        )
                        parsed_rules.append(parsed_filter_rule)
                        errors.extend(parsed_filter_rule.errors)  # Propagate errors from rule
                    else:  # merge with global rule and parse as simple rule
                        parsed_merged_rule = SigmaRule.from_dict(
                            deep_dict_update(rule, global_rule),
                            collect_errors,
                            source,
                            policy=policy,
                        )
                        parsed_rules.append(parsed_merged_rule)
                        errors.extend(parsed_merged_rule.errors)  # Propagate errors from rule
                        prev_rule = rule
                elif action == "global":  # set global rule template
                    del rule["action"]
                    global_rule = rule
                    prev_rule = global_rule
                elif action == "reset":  # remove global rule
                    global_rule = dict()
                elif (
                    action == "repeat"
                ):  # add content of current rule to previous rule and parse it
                    prev_rule = deep_dict_update(prev_rule, rule)
                    parsed_rule = SigmaRule.from_dict(
                        prev_rule, collect_errors, source, policy=policy
                    )
                    parsed_rules.append(parsed_rule)
                    errors.extend(parsed_rule.errors)  # Propagate errors from rule
                else:
                    exception = SigmaCollectionError(
                        f"Unknown Sigma collection action '{ action }' in rule { i }",
                        source=source,
                    )
                    if collect_errors:
                        errors.append(exception)
                    else:
                        raise exception

        return cls(
            init_rules=parsed_rules,
            errors=errors,
            collect_filters=collect_filters,
            resolve_references=resolve_references,
        )

    @classmethod
    def from_yaml(
        cls: type[Self],
        yaml_str: bytes | str | IO[Any],
        collect_errors: bool = False,
        source: SigmaRuleLocation | None = None,
        collect_filters: bool = False,
        resolve_references: bool = True,
        policy: "SigmaPolicy | None" = None,
    ) -> Self:
        """
        Generate a rule collection from a string containing one or multiple YAML documents.

        If the collect_errors parameters is set, exceptions are not raised while parsing but collected
        in the errors property individually for each Sigma rule and the whole SigmaCollection.

        If collect_filters is set, filters are only collected in the collection but not yet applied to the rules.
        """
        return cls.from_dicts(
            list(yaml.safe_load_all(yaml_str)),
            collect_errors,
            source,
            collect_filters,
            resolve_references,
            policy=policy,
        )

    @classmethod
    def resolve_paths(
        cls: type[Self],
        inputs: list[str | Path],
        recursion_pattern: str = "**/*.yml",
    ) -> Iterable[Path]:
        """
        Resolve list of paths *inputs* that can contain files as well as directories into a flat list of
        files matching *resursion_pattern*.
        """
        paths = (  # Normalize all inputs into paths
            input if isinstance(input, Path) else Path(input) for input in inputs
        )
        paths_recurse = (  # Recurse into directories if provided
            path.glob(recursion_pattern) if path.is_dir() else (path,) for path in paths
        )
        return (subpath for subpaths in paths_recurse for subpath in subpaths)  # Flatten the list

    @classmethod
    def load_ruleset(
        cls: type[Self],
        inputs: list[str | Path],
        collect_errors: bool = False,
        on_beforeload: Callable[[Path], Path | None] | None = None,
        on_load: Callable[[Path, SigmaCollection], SigmaCollection | None] | None = None,
        recursion_pattern: str = "**/*.yml",
        resolve_references: bool = True,
    ) -> Self:
        """
        Load a ruleset from a list of files or directories and construct a :class:`SigmaCollection`
        object.

        :param inputs: List of strings and :class:`pathlib.Path` objects that reference files or
        directories that should be loaded.
        :param collect_errors: parse or verification errors are collected in :class:`SigmaRuleBase`
        objects instead of raising them immediately. Defaults to ``False``.
        :param on_beforeload: Optional function that is called for each path to a Sigma rule before the parsing and
        construction of the :class:`SigmaCollection` object is done. The path returned by this function is
        used as input. A rule path is skipped if ``None`` is returned.
        :param on_load: Optional function that is called after the :class:`SigmaCollection` was
        constructed from the path. The path and the SigmaCollection object are passed to this
        function and it is expected to return a :class:`SigmaCollection` object that is merged in
        the collection of the ruleset or ``None`` if the generated collection should be skipped.
        :param recursion_pattern: Pattern used to recurse into directories, defaults to ``**/*.yml``.

        :return: :class:`SigmaCollection` of all sigma rules contained in given paths.

        """
        if not isinstance(inputs, Iterable) or isinstance(inputs, str):
            raise TypeError(
                "Parameter 'inputs' must be list of strings or pathlib.Path objects, not "
                + str(type(inputs))
            )

        paths = cls.resolve_paths(inputs, recursion_pattern)
        sigma_collections = list()
        for path in paths:
            if (
                on_beforeload is not None
            ):  # replace path with return value of on_beforeload function if provided
                result_path: Path | None = on_beforeload(path)
            else:
                result_path = path
            if result_path is not None:  # Skip if path is None
                # Load per-file collections without resolving references yet. The
                # final resolution will be done after merging all collections below.
                with result_path.open(encoding="utf-8") as fd:
                    sigma_collection = SigmaCollection.from_yaml(
                        fd,
                        collect_errors,
                        source=SigmaRuleLocation(result_path),
                        collect_filters=True,
                        resolve_references=False,
                    )
                if (
                    on_load is not None
                ):  # replace SigmaCollection generated from file content with the return value from on_load function if provided
                    result_sigma_collection = on_load(result_path, sigma_collection)
                else:
                    result_sigma_collection = sigma_collection
                if result_sigma_collection is not None:  # Skip if nothing
                    sigma_collections.append(result_sigma_collection)

        # Finally merge all SigmaCollection's and return the result. Merge without
        # resolving references (we'll do a single resolution pass after merge).
        merged = cls.merge(sigma_collections, resolve_references=False)
        if resolve_references:
            merged.resolve_rule_references()
        return merged

    @classmethod
    def merge(
        cls: type[Self], collections: Iterable[SigmaCollection], resolve_references: bool = True
    ) -> Self:
        """Merge multiple SigmaCollection objects into one and return it."""
        return cls(
            init_rules=[
                rule for collection in collections for rule in collection.rules + collection.filters
            ],
            errors=[error for collection in collections for error in collection.errors],
            resolve_references=resolve_references,
        )

    def get_output_rules(self: Self) -> Iterable[SigmaRuleBase]:
        """Returns an iterator across all rules where the output property is set to true"""
        return (rule for rule in self.rules if rule._output)

    def get_unreferenced_rules(self: Self) -> Iterable[SigmaRuleBase]:
        """Returns an iterator across all rules that are not referenced by any other rule"""
        return (rule for rule in self.rules if not rule._backreferences)

    def __iter__(self: Self) -> Iterator[SigmaRuleBase]:
        return iter(self.rules)

    def __len__(self: Self) -> int:
        return len(self.rules)

    def __getitem__(self: Self, i: int | str | UUID) -> SigmaRule | SigmaCorrelationRule:
        try:
            if isinstance(i, int):  # Index by position
                return self.rules[i]
            elif isinstance(i, UUID):  # Index by UUID
                return self.ids_to_rules[i]
            elif isinstance(i, str):  # Index by UUID or name
                try:  # Try UUID first
                    return self.ids_to_rules[UUID(i)]
                except ValueError:  # Try name if UUID fails
                    return self.names_to_rules[i]
        except IndexError:
            raise SigmaRuleNotFoundError(f"Rule at position { i } not found in rule collection")
        except KeyError:
            raise SigmaRuleNotFoundError(f"Rule '{ i }' not found in rule collection")


def deep_dict_update(dest: dict[Any, Any], src: dict[Any, Any]) -> dict[Any, Any]:
    for k, v in src.items():
        if isinstance(v, dict):
            dest[k] = deep_dict_update(dest.get(k, {}), v)
        else:
            dest[k] = v
    return dest
