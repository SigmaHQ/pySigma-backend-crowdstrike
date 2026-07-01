from sigma.conversion.state import ConversionState
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import (
    ConditionItem,
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
)
from sigma.conversion.deferred import (
    DeferredQueryExpression,
    DeferredTextQueryExpression,
)
from sigma.types import (
    SigmaCompareExpression,
    SigmaRegularExpressionFlag,
    SpecialChars,
    SigmaString,
)
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.correlations import (
    SigmaCorrelationRule,
    SigmaCorrelationType,
    SigmaCorrelationTypeLiteral,
    SigmaCorrelationCondition,
)
import sigma
import re
from typing import ClassVar, Dict, Tuple, Pattern, Optional, Union


class LogScaleDeferredEqualsOperator(DeferredTextQueryExpression):
    template = "{field}{op}/{value}/i"
    operators = {
        True: "!=",
        False: "=",
    }


class LogScaleDeferredTestOperator(DeferredQueryExpression):
    template = "test({field1}=={field2})"


class LogScaleDeferredInOperator(DeferredTextQueryExpression):
    template = "{op}in({field}, ignoreCase=true, values=[{value}])"
    operators = {
        True: "!",
        False: "",
    }


class LogScaleDeferredCIDRExpression(DeferredTextQueryExpression):
    template = "{op}cidr({field}, subnet={value})"
    operators = {
        True: "!",
        False: "",
    }


class LogScaleDeferredRegularExpression(DeferredTextQueryExpression):
    template = "{op}regex(field={field},{value})"
    operators = {True: "!", False: ""}


class LogScaleBackend(TextQueryBackend):
    """CrowdStrike LogScale backend."""

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name: ClassVar[str] = "CrowdStrike LogScale backend"
    formats: Dict[str, str] = {
        "default": "CrowdStrike LogScale queries",
    }
    requires_pipeline: bool = True

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionOR,
        ConditionAND,
    )
    group_expression: ClassVar[str] = "({expr})"

    # Generated query tokens
    token_separator: str = " "
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = " "
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[str] = "="

    # String output
    ## Fields
    ### Quoting
    field_quote: ClassVar[str] = '"'
    field_quote_pattern: ClassVar[Pattern] = re.compile(
        r"^[@|#]?[\w.]+$"
    )  # Some logscale fields start with # or @
    field_quote_pattern_negation: ClassVar[bool] = True

    ### Escaping
    # fields in LogScale are defined directly by CrowdStrike so this is probably unnecessary but let's do it anyway
    field_escape: ClassVar[str] = "\\"
    field_escape_quote: ClassVar[bool] = True

    ## Values
    ## This is unused by the backend because {field}={value} is case sensitive in logscale. All values are treated as regular expressions
    ## https://library.humio.com/data-analysis/writing-queries-operations.html#writing-queries-operations-strings-case-insensitive
    str_quote: ClassVar[str] = (
        '"'  # string quoting character (added as escaping character)
    )
    str_quote_pattern_negation = False
    escape_char: ClassVar[str] = (
        "\\"  # Escaping character for special characrers inside string
    )
    wildcard_multi: ClassVar[str] = ".*"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "."  # Character used as single-character wildcard
    add_escaped: ClassVar[str] = (
        "\\"  # Characters quoted in addition to wildcards and string quote
    )
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[Dict[bool, str]] = (
        {  # Values to which boolean values are mapped.
            True: "true",
            False: "false",
        }
    )

    ## Special Regex Values for LogScale
    str_quote_re: ClassVar[str] = ""
    escape_char_re: ClassVar[str] = "\\"
    wildcard_multi_re: ClassVar[str] = ".*"
    wildcard_single_re: ClassVar[str] = "."
    add_escaped_re: ClassVar[str] = "*$^.|?()[]+/{}"
    filter_chars_re: ClassVar[str] = ""
    bool_values_re: ClassVar[Dict[bool, str]] = {
        True: "true",
        False: "false",
    }

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression: ClassVar[str] = "{field}=/{regex}/{flag_i}{flag_m}{flag_s}"
    re_exact_match: ClassVar[str] = "{field}=/^{regex}$/{flag_i}{flag_m}{flag_s}"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = '"'
    re_escape_escape_char: bool = False
    re_flag_prefix: bool = False
    re_flags: Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
        SigmaRegularExpressionFlag.MULTILINE: "m",
        SigmaRegularExpressionFlag.DOTALL: "s",
    }

    # case sensitive match is just {field}={value} in logscale
    case_sensitive_match_expression: ClassVar[str] = "{field}={value}"

    # wildcards could have been used here as well but we went with the regex format without the case insensitivity flag
    case_sensitive_startswith_expression: ClassVar[str] = "{field}=/^{value}/"
    case_sensitive_endswith_expression: ClassVar[str] = "{field}=/{value}$/"
    case_sensitive_contains_expression: ClassVar[str] = "{field}=/{value}/"

    # also handled as regex. Look at the convert_condition_field_eq_val_str method
    startswith_expression: ClassVar[str] = "{field}=/^{regex}/{flag_i}{flag_m}{flag_s}"
    endswith_expression: ClassVar[str] = "{field}=/{regex}$/{flag_i}{flag_m}{flag_s}"
    contains_expression: ClassVar[str] = "{field}=/{regex}/{flag_i}{flag_m}{flag_s}"

    # https://library.humio.com/data-analysis/functions-cidr.html
    # Convert method is overloaded below
    cidr_expression: ClassVar[Optional[str]] = "{value}"

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = (
        "{field}{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    )
    # https://library.humio.com/data-analysis/syntax-operators.html
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    # https://library.humio.com/kb/kb-empty-fields.html
    field_null_expression: ClassVar[str] = (
        "{field}!=*"  # Expression for field has null value as format string with {field} placeholder for field name
    )

    # Field existence condition expressions.
    # I dont think humio can do the below
    # field_exists_expression : ClassVar[str] = "exists({field})"             # Expression for field existence as format string with {field} placeholder for field name
    # field_not_exists_expression : ClassVar[str] = "notexists({field})"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    # https://library.humio.com/data-analysis/functions-in.html """
    # Logscale does not support 'or' with in statements so we decided not to use it. However the logic is here if this changes
    convert_or_as_in: ClassVar[bool] = False  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = (
        True  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    )

    field_in_list_expression: ClassVar[str] = (
        "{list}"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    )
    or_in_operator: ClassVar[str] = (
        "in"  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    )
    list_separator: ClassVar[str] = ", "  # List element separator

    # Value not bound to a field
    # We want these to be case insensivitive so use the regex representation again
    unbound_value_str_expression: ClassVar[str] = (
        "/{value}/i"  # Expression for string value not bound to a field as format string with placeholder {value}
    )
    unbound_value_num_expression: ClassVar[str] = (
        "/{value}/i"  # Expression for number value not bound to a field as format string with placeholder {value}
    )
    unbound_value_re_expression: ClassVar[str] = (
        "/{value}/{flag_i}{flag_m}{flag_s}"  # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression
    )

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[str] = (
        "| "  # String used as separator between main query and deferred parts
    )
    deferred_separator: ClassVar[str] = (
        "| "  # String used to join multiple deferred query parts
    )
    deferred_only_query: ClassVar[str] = (
        ""  # String used as query if final query only contains deferred expression
    )

    # Correlation rule support
    # CrowdStrike LogScale (Humio) natively provides the aggregation and event
    # typing primitives required by Sigma correlation rules:
    #   * event_count / value_count      -> bucket() with count() / count(distinct=true)
    #   * value_sum / value_avg          -> bucket() with sum() / avg()
    #   * value_percentile / value_median-> bucket() with percentile() (+ rename)
    #   * temporal                       -> case{} event typing + distinct event_type count
    #   * temporal (boolean condition)   -> collect() the fired rules + array:contains() tests
    # bucket() divides the search interval into fixed windows (span) and groups by
    # the fields passed to its field= parameter, mirroring Splunk's
    # "bin _time span=... | stats ... by _time <fields>". The aggregated rows are
    # then filtered on the computed metric with test().
    # temporal_ordered is not supported (LogScale has no template-friendly ordered
    # sequence primitive) and raises NotImplementedError.
    # https://library.humio.com/data-analysis/functions-bucket.html
    # The backend exposes a single correlation method named "default".
    correlation_methods: ClassVar[Dict[str, str]] = {
        "default": "CrowdStrike LogScale correlation using bucket() aggregation",
    }
    default_correlation_method: ClassVar[str] = "default"

    # Query frame shared by all supported correlation types. The search phase emits
    # the matching expression (a single rule query or a case{} typing block for
    # multi-rule temporal correlations), followed by the time-bucketed aggregation
    # and the final threshold filter.
    default_correlation_query: ClassVar[Dict[str, str]] = {
        "default": "{search}\n{aggregate}\n{condition}",
    }

    # Search phase
    # Single referenced rule (event_count/value_count): emit its query verbatim.
    # Optional because convert_correlation_search temporarily unsets it to force
    # the multi-rule typing path for single-rule temporal correlations.
    correlation_search_single_rule_expression: ClassVar[Optional[str]] = "{query}"
    # Multiple referenced rules (temporal): wrap each rule query in a case{} clause
    # that tags matching events with their originating rule via the event_type
    # field. LogScale drops events matching none of the clauses (no wildcard clause
    # is emitted), which bounds the correlation to the referenced rules.
    # https://library.humio.com/data-analysis/syntax-conditional.html
    correlation_search_multi_rule_expression: ClassVar[str] = "case {{\n{queries}\n}}"
    correlation_search_multi_rule_query_expression: ClassVar[str] = (
        '{query} | event_type := "{ruleid}"{normalization}'
    )
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = ";\n"

    # Field normalisation (aliases): rename each referenced field to the shared
    # alias field so that group-by works across rules with differing field names.
    correlation_search_field_normalization_expression: ClassVar[str] = (
        " | {alias} := {field}"
    )
    correlation_search_field_normalization_expression_joiner: ClassVar[str] = ""

    # Aggregation phase: bucket() windows the search interval by {timespan} and
    # aggregates per group. Sigma's group-by fields are passed to bucket()'s
    # field= array parameter (see groupby_* templates below). limit=max raises
    # bucket()'s default series cap (10) to the maximum so group-by correlations
    # are not silently truncated to the ten highest-count groups.
    event_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| bucket(span={timespan}, limit=max{groupby}, function=count(as=event_count))",
    }
    value_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| bucket(span={timespan}, limit=max{groupby}, function=count(field={field}, distinct=true, as=value_count))",
    }
    temporal_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| bucket(span={timespan}, limit=max{groupby}, function=count(field=event_type, distinct=true, as=event_type_count))",
    }
    # Metric aggregations over a numeric {field}.
    value_sum_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| bucket(span={timespan}, limit=max{groupby}, function=sum({field}, as=value_sum))",
    }
    value_avg_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| bucket(span={timespan}, limit=max{groupby}, function=avg({field}, as=value_avg))",
    }
    # percentile()/median() name their output field with a numeric suffix
    # (e.g. value_percentile_95), so the result is renamed to a fixed field the
    # condition phase can reference without knowing the percentile.
    value_percentile_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| bucket(span={timespan}, limit=max{groupby}, function=percentile({field}, percentiles=[{percentile}], as=value_percentile))\n| rename(value_percentile_{percentile}, as=value_percentile)",
    }
    value_median_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| bucket(span={timespan}, limit=max{groupby}, function=percentile({field}, percentiles=[50], as=value_median))\n| rename(value_median_50, as=value_median)",
    }
    # Extended (boolean) temporal correlation: collect the distinct set of rules
    # that fired per group into an array, then filter with the boolean condition.
    # collect() yields a newline-joined string, so it is split back into an
    # indexable array that array:contains() can test in the condition phase.
    temporal_extended_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": '| bucket(span={timespan}, limit=max{groupby}, function=collect([event_type], as=event_types))\n| splitString(field=event_types, by="\\n", as=matched)',
    }

    # Sigma timespan units map onto LogScale relative-time abbreviations directly
    # for s/m/h/d/w/y; only the Sigma month unit ("M") needs translation, as
    # LogScale spells months "mon" and reads "m" as minutes.
    timespan_mapping: ClassVar[Dict[str, str]] = {"M": "mon"}

    # Group-by rendered as bucket()'s field= array parameter. When the correlation
    # rule omits group-by, no field= parameter is emitted (bucket by time only).
    groupby_expression: ClassVar[Dict[str, str]] = {"default": ", field=[{fields}]"}
    groupby_field_expression: ClassVar[Dict[str, str]] = {"default": "{field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str]] = {"default": ", "}
    groupby_expression_nofield: ClassVar[Dict[str, str]] = {"default": ""}

    # Condition phase: filter aggregated rows on the computed metric. The default
    # correlation_condition_mapping (<, <=, >, >=, ==, !=) is inherited unchanged;
    # all operators are valid inside test().
    event_count_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| test(event_count {op} {count})",
    }
    value_count_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| test(value_count {op} {count})",
    }
    temporal_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| test(event_type_count {op} {count})",
    }
    value_sum_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| test(value_sum {op} {count})",
    }
    value_avg_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| test(value_avg {op} {count})",
    }
    value_percentile_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| test(value_percentile {op} {count})",
    }
    value_median_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| test(value_median {op} {count})",
    }
    # Extended temporal condition: the parsed boolean expression, with each rule
    # reference rendered as an array membership test. and/or/not are combined
    # using the backend's boolean tokens (space / or / not).
    temporal_extended_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| {extended_condition}",
    }
    extended_correlation_condition_rule_reference_expression: ClassVar[
        Dict[str, str]
    ] = {
        "default": 'array:contains(array="matched[]", value="{ruleid}")',
    }

    def __init__(
        self,
        processing_pipeline: Optional[
            "sigma.processing.pipeline.ProcessingPipeline"
        ] = None,
        collect_errors: bool = False,
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)

    def convert_correlation_search(self, rule: SigmaCorrelationRule, **kwargs) -> str:
        """Embed the referenced rule query in a correlation search.

        Two adjustments are made on top of the base implementation:

        * Temporal correlations must tag every matched event with its
          originating rule via the multi-rule ``case{}`` typing. The base
          single-rule search expression omits that tag, so a temporal rule that
          happens to reference a single rule would produce a query that never
          matches. Force the multi-rule path for temporal correlations (it
          renders a correct one-clause ``case{}`` when only one rule is
          referenced).
        * A referenced rule whose query consists solely of deferred parts (e.g.
          a rule matching only on ``fieldX|cidr``) is emitted with a leading
          ``deferred_start`` pipe. That leading pipe is spurious once the query
          is placed at the start of a correlation query, so it is stripped.
        """
        if rule.type == SigmaCorrelationType.TEMPORAL:
            # Instance attribute temporarily shadows the class variable to force
            # the base multi-rule (case{} typing) search path.
            single_rule_expression = self.correlation_search_single_rule_expression
            self.correlation_search_single_rule_expression = None  # type: ignore[misc]
            try:
                search = super().convert_correlation_search(rule, **kwargs)
            finally:
                self.correlation_search_single_rule_expression = (  # type: ignore[misc]
                    single_rule_expression
                )
        else:
            search = super().convert_correlation_search(rule, **kwargs)
        return search.removeprefix(self.deferred_start)

    def convert_correlation_search_multi_rule_query_postprocess(
        self, query: str
    ) -> str:
        """Strip the leading deferred pipe from a temporal case clause query.

        Without this, a fully-deferred referenced rule would produce a case
        clause starting with a bare ``| ...`` which is not valid LogScale.
        """
        return query.removeprefix(self.deferred_start)

    def convert_correlation_aggregation_from_template(
        self,
        rule: SigmaCorrelationRule,
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
        search: str,
    ) -> str:
        """Escape/quote the value_* condition field like group-by fields.

        The framework passes the condition field reference through verbatim,
        whereas group-by fields are escaped and quoted. This normalises the two
        so a condition field containing whitespace or special characters (e.g.
        ``field: "user name"``) produces valid LogScale. A list of fields is
        rejected, since a scalar aggregation over multiple fields is undefined.
        """
        condition = rule.condition
        if (
            not isinstance(condition, SigmaCorrelationCondition)
            or condition.fieldref is None
        ):
            return super().convert_correlation_aggregation_from_template(
                rule, correlation_type, method, search
            )
        if not isinstance(condition.fieldref, str):
            raise SigmaFeatureNotSupportedByBackendError(
                "Correlation condition field must be a single field name",
                source=rule.source,
            )
        original_fieldref = condition.fieldref
        condition.fieldref = self.escape_and_quote_field(original_fieldref)
        try:
            return super().convert_correlation_aggregation_from_template(
                rule, correlation_type, method, search
            )
        finally:
            condition.fieldref = original_fieldref

    def convert_condition_field_eq_val_cidr(
        self,
        cond: ConditionFieldEqualsValueExpression,
        state: ConversionState,
    ) -> LogScaleDeferredCIDRExpression:
        """Defer CIDR network range matching to pipelined where cidrmatch command after main search expression."""
        if cond.parent_condition_chain_contains(ConditionOR):
            raise SigmaFeatureNotSupportedByBackendError(
                "ORing CIDR matching is not yet supported by LogScale backend",
                source=cond.source,
            )
        return LogScaleDeferredCIDRExpression(
            state, cond.field, super().convert_condition_field_eq_val_cidr(cond, state)
        ).postprocess(None, cond)

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions. In logscale we handle everything as regexs"""
        try:
            if (  # contains: string starts and ends with wildcard
                self.contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
            ):
                expr = self.contains_expression
                value = cond.value[1:-1]
            elif (  # Same as above but for 'endswith' operator: string starts with wildcard
                self.endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
            ):
                expr = self.endswith_expression
                value = cond.value[1:]

            elif (  # Same as above but for 'startswith' operator: string ends with wildcard
                self.startswith_expression
                is not None  # 'startswith' operator is defined in backend
                and cond.value.endswith(
                    SpecialChars.WILDCARD_MULTI
                )
            ):
                expr = self.startswith_expression
                # If all conditions are fulfilled, use 'startswith' operator instead of equal token
                value = cond.value[:-1]
            else:
                expr = self.re_exact_match
                value = cond.value
            return expr.format(
                field=self.escape_and_quote_field(cond.field),
                regex=self.convert_value_str_re(value, state),
                flag_i="i",
                flag_m="",
                flag_s="",
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Field equals string value expressions with strings are not supported by the backend."
            )

    def convert_value_str_re(self, s: SigmaString, state: ConversionState) -> str:
        converted = s.convert(
            escape_char=self.escape_char_re,
            wildcard_multi=self.wildcard_multi_re,
            wildcard_single=self.wildcard_single_re,
            add_escaped=self.str_quote_re + self.add_escaped_re + self.escape_char_re,
            filter_chars=self.filter_chars_re,
        )
        return converted
