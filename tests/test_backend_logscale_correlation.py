import pytest
from sigma.collection import SigmaCollection
from sigma.backends.crowdstrike import LogScaleBackend
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError


@pytest.fixture
def logscale_backend():
    return LogScaleBackend()


# A single reusable base rule referenced by the count-based correlation rules.
EVENT_COUNT_BASE = """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
"""

# Two base rules referenced by the temporal correlation rules.
TEMPORAL_BASE = """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
        fieldB: value4
    condition: selection
---
"""


def test_crowdstrikelogscale_event_count_correlation(
    logscale_backend: LogScaleBackend,
):
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                EVENT_COUNT_BASE
                + """
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
        - fieldD
    timespan: 15m
    condition:
        gte: 10
"""
            )
        )
        == [
            "fieldA=/^value1$/i fieldB=/^value2$/i\n"
            "| bucket(span=15m, limit=max, field=[fieldC, fieldD], function=count(as=event_count))\n"
            "| test(event_count >= 10)"
        ]
    )


def test_crowdstrikelogscale_event_count_correlation_no_groupby(
    logscale_backend: LogScaleBackend,
):
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                EVENT_COUNT_BASE
                + """
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    timespan: 1h
    condition:
        gte: 5
"""
            )
        )
        == [
            "fieldA=/^value1$/i fieldB=/^value2$/i\n"
            "| bucket(span=1h, limit=max, function=count(as=event_count))\n"
            "| test(event_count >= 5)"
        ]
    )


def test_crowdstrikelogscale_value_count_correlation(
    logscale_backend: LogScaleBackend,
):
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                EVENT_COUNT_BASE
                + """
title: Distinct values of base event
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        lt: 10
        field: fieldD
"""
            )
        )
        == [
            "fieldA=/^value1$/i fieldB=/^value2$/i\n"
            "| bucket(span=15m, limit=max, field=[fieldC], function=count(field=fieldD, distinct=true, as=value_count))\n"
            "| test(value_count < 10)"
        ]
    )


@pytest.mark.parametrize(
    ("condition", "expected_op"),
    [
        ("gt: 3", ">"),
        ("gte: 3", ">="),
        ("lt: 3", "<"),
        ("lte: 3", "<="),
        ("eq: 3", "=="),
    ],
)
def test_crowdstrikelogscale_event_count_correlation_operators(
    logscale_backend: LogScaleBackend, condition: str, expected_op: str
):
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                EVENT_COUNT_BASE
                + f"""
title: Operator test
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 5m
    condition:
        {condition}
"""
            )
        )
        == [
            "fieldA=/^value1$/i fieldB=/^value2$/i\n"
            "| bucket(span=5m, limit=max, field=[fieldC], function=count(as=event_count))\n"
            f"| test(event_count {expected_op} 3)"
        ]
    )


def test_crowdstrikelogscale_temporal_correlation(
    logscale_backend: LogScaleBackend,
):
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                TEMPORAL_BASE
                + """
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 15m
"""
            )
        )
        == [
            "case {\n"
            'fieldA=/^value1$/i fieldB=/^value2$/i | event_type := "base_rule_1";\n'
            'fieldA=/^value3$/i fieldB=/^value4$/i | event_type := "base_rule_2"\n'
            "}\n"
            "| bucket(span=15m, limit=max, field=[fieldC], function=count(field=event_type, distinct=true, as=event_type_count))\n"
            "| test(event_type_count >= 2)"
        ]
    )


def test_crowdstrikelogscale_temporal_correlation_with_aliases(
    logscale_backend: LogScaleBackend,
):
    """Field aliases normalise differently-named fields to a shared alias field."""
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                TEMPORAL_BASE
                + """
title: Temporal correlation rule with aliases
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    aliases:
        field:
            base_rule_1: fieldC
            base_rule_2: fieldD
    group-by:
        - fieldC
    timespan: 15m
"""
            )
        )
        == [
            "case {\n"
            'fieldA=/^value1$/i fieldB=/^value2$/i | event_type := "base_rule_1" | field := fieldC;\n'
            'fieldA=/^value3$/i fieldB=/^value4$/i | event_type := "base_rule_2" | field := fieldD\n'
            "}\n"
            "| bucket(span=15m, limit=max, field=[fieldC], function=count(field=event_type, distinct=true, as=event_type_count))\n"
            "| test(event_type_count >= 2)"
        ]
    )


def test_crowdstrikelogscale_temporal_correlation_no_groupby(
    logscale_backend: LogScaleBackend,
):
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                TEMPORAL_BASE
                + """
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    timespan: 1d
"""
            )
        )
        == [
            "case {\n"
            'fieldA=/^value1$/i fieldB=/^value2$/i | event_type := "base_rule_1";\n'
            'fieldA=/^value3$/i fieldB=/^value4$/i | event_type := "base_rule_2"\n'
            "}\n"
            "| bucket(span=1d, limit=max, function=count(field=event_type, distinct=true, as=event_type_count))\n"
            "| test(event_type_count >= 2)"
        ]
    )


def test_crowdstrikelogscale_correlation_field_with_whitespace(
    logscale_backend: LogScaleBackend,
):
    """Group-by field names are escaped/quoted with the backend's field rules."""
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                EVENT_COUNT_BASE
                + """
title: Whitespace group-by
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - field name
    timespan: 5m
    condition:
        gte: 2
"""
            )
        )
        == [
            "fieldA=/^value1$/i fieldB=/^value2$/i\n"
            '| bucket(span=5m, limit=max, field=["field name"], function=count(as=event_count))\n'
            "| test(event_count >= 2)"
        ]
    )


def test_crowdstrikelogscale_correlation_omits_referenced_rules(
    logscale_backend: LogScaleBackend,
):
    """Only the correlation query is emitted; referenced rules are subqueries."""
    result = logscale_backend.convert(
        SigmaCollection.from_yaml(
            EVENT_COUNT_BASE
            + """
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        gte: 10
"""
        )
    )
    assert len(result) == 1


def test_crowdstrikelogscale_temporal_correlation_three_rules(
    logscale_backend: LogScaleBackend,
):
    """The temporal threshold equals the number of referenced rules."""
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value2
    condition: selection
---
title: Base rule 3
name: base_rule_3
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
    condition: selection
---
title: Temporal correlation over three rules
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
        - base_rule_3
    group-by:
        - host
    timespan: 5m
"""
            )
        )
        == [
            "case {\n"
            'fieldA=/^value1$/i | event_type := "base_rule_1";\n'
            'fieldA=/^value2$/i | event_type := "base_rule_2";\n'
            'fieldA=/^value3$/i | event_type := "base_rule_3"\n'
            "}\n"
            "| bucket(span=5m, limit=max, field=[host], function=count(field=event_type, distinct=true, as=event_type_count))\n"
            "| test(event_type_count >= 3)"
        ]
    )


def test_crowdstrikelogscale_event_count_correlation_neq(
    logscale_backend: LogScaleBackend,
):
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                EVENT_COUNT_BASE
                + """
title: Not equal occurrences
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 5m
    condition:
        neq: 1
"""
            )
        )
        == [
            "fieldA=/^value1$/i fieldB=/^value2$/i\n"
            "| bucket(span=5m, limit=max, field=[fieldC], function=count(as=event_count))\n"
            "| test(event_count != 1)"
        ]
    )


def test_crowdstrikelogscale_event_count_correlation_deferred_subrule(
    logscale_backend: LogScaleBackend,
):
    """A referenced rule whose query is fully deferred must not leave a
    dangling leading pipe at the start of the correlation query."""
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                """
title: CIDR base rule
name: cidr_base
status: test
logsource:
    category: test
detection:
    selection:
        fieldA|cidr: 10.0.0.0/8
    condition: selection
---
title: Repeated connections from subnet
status: test
correlation:
    type: event_count
    rules:
        - cidr_base
    group-by:
        - host
    timespan: 5m
    condition:
        gte: 3
"""
            )
        )
        == [
            "cidr(fieldA, subnet=10.0.0.0/8)\n"
            "| bucket(span=5m, limit=max, field=[host], function=count(as=event_count))\n"
            "| test(event_count >= 3)"
        ]
    )


def test_crowdstrikelogscale_temporal_correlation_deferred_subrule(
    logscale_backend: LogScaleBackend,
):
    """A fully-deferred referenced rule must produce a valid case clause
    (no clause may start with a bare pipe)."""
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                """
title: CIDR base rule
name: cidr_base
status: test
logsource:
    category: test
detection:
    selection:
        fieldA|cidr: 10.0.0.0/8
    condition: selection
---
title: Plain base rule
name: plain_base
status: test
logsource:
    category: test
detection:
    selection:
        fieldB: value2
    condition: selection
---
title: Temporal with deferred subrule
status: test
correlation:
    type: temporal
    rules:
        - cidr_base
        - plain_base
    group-by:
        - host
    timespan: 5m
"""
            )
        )
        == [
            "case {\n"
            'cidr(fieldA, subnet=10.0.0.0/8) | event_type := "cidr_base";\n'
            'fieldB=/^value2$/i | event_type := "plain_base"\n'
            "}\n"
            "| bucket(span=5m, limit=max, field=[host], function=count(field=event_type, distinct=true, as=event_type_count))\n"
            "| test(event_type_count >= 2)"
        ]
    )


def test_crowdstrikelogscale_temporal_correlation_group_by_alias(
    logscale_backend: LogScaleBackend,
):
    """Grouping by the alias field co-groups normalised values across rules."""
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                TEMPORAL_BASE
                + """
title: Temporal correlation grouped by alias
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    aliases:
        user:
            base_rule_1: fieldC
            base_rule_2: fieldD
    group-by:
        - user
    timespan: 15m
"""
            )
        )
        == [
            "case {\n"
            'fieldA=/^value1$/i fieldB=/^value2$/i | event_type := "base_rule_1" | user := fieldC;\n'
            'fieldA=/^value3$/i fieldB=/^value4$/i | event_type := "base_rule_2" | user := fieldD\n'
            "}\n"
            "| bucket(span=15m, limit=max, field=[user], function=count(field=event_type, distinct=true, as=event_type_count))\n"
            "| test(event_type_count >= 2)"
        ]
    )


def test_crowdstrikelogscale_single_rule_temporal_tags_event_type(
    logscale_backend: LogScaleBackend,
):
    """A temporal rule referencing a single rule still tags event_type via case{}."""
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
---
title: Single-rule temporal
status: test
correlation:
    type: temporal
    rules:
        - base_rule
    group-by:
        - host
    timespan: 15m
"""
            )
        )
        == [
            "case {\n"
            'fieldA=/^value1$/i | event_type := "base_rule"\n'
            "}\n"
            "| bucket(span=15m, limit=max, field=[host], function=count(field=event_type, distinct=true, as=event_type_count))\n"
            "| test(event_type_count >= 1)"
        ]
    )


def test_crowdstrikelogscale_value_count_field_with_whitespace(
    logscale_backend: LogScaleBackend,
):
    """The value_count condition field is quoted like group-by fields."""
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                EVENT_COUNT_BASE
                + """
title: Distinct values of a spaced field
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        lt: 10
        field: user name
"""
            )
        )
        == [
            "fieldA=/^value1$/i fieldB=/^value2$/i\n"
            '| bucket(span=15m, limit=max, field=[fieldC], function=count(field="user name", distinct=true, as=value_count))\n'
            "| test(value_count < 10)"
        ]
    )


@pytest.mark.parametrize(
    ("timespan", "expected_span"),
    [
        ("30s", "30s"),
        ("10m", "10m"),
        ("2h", "2h"),
        ("7d", "7d"),
        ("2w", "2w"),
        ("6M", "6mon"),
        ("1y", "1y"),
    ],
)
def test_crowdstrikelogscale_correlation_timespan_units(
    logscale_backend: LogScaleBackend, timespan: str, expected_span: str
):
    """Sigma timespan units render as LogScale relative-time spans (M -> mon)."""
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                EVENT_COUNT_BASE
                + f"""
title: Timespan units
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: {timespan}
    condition:
        gte: 2
"""
            )
        )
        == [
            "fieldA=/^value1$/i fieldB=/^value2$/i\n"
            f"| bucket(span={expected_span}, limit=max, field=[fieldC], function=count(as=event_count))\n"
            "| test(event_count >= 2)"
        ]
    )


def test_crowdstrikelogscale_value_sum_correlation(
    logscale_backend: LogScaleBackend,
):
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                EVENT_COUNT_BASE
                + """
title: Sum of a numeric field
status: test
correlation:
    type: value_sum
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        gte: 1000
        field: Amount
"""
            )
        )
        == [
            "fieldA=/^value1$/i fieldB=/^value2$/i\n"
            "| bucket(span=15m, limit=max, field=[fieldC], function=sum(Amount, as=value_sum))\n"
            "| test(value_sum >= 1000)"
        ]
    )


def test_crowdstrikelogscale_value_avg_correlation(
    logscale_backend: LogScaleBackend,
):
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                EVENT_COUNT_BASE
                + """
title: Average of a numeric field
status: test
correlation:
    type: value_avg
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        gt: 500
        field: Amount
"""
            )
        )
        == [
            "fieldA=/^value1$/i fieldB=/^value2$/i\n"
            "| bucket(span=15m, limit=max, field=[fieldC], function=avg(Amount, as=value_avg))\n"
            "| test(value_avg > 500)"
        ]
    )


def test_crowdstrikelogscale_value_percentile_correlation(
    logscale_backend: LogScaleBackend,
):
    """percentile()'s numeric-suffixed output field is renamed to a fixed name."""
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                EVENT_COUNT_BASE
                + """
title: 95th percentile of a numeric field
status: test
correlation:
    type: value_percentile
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        gte: 100
        field: Amount
        percentile: 95
"""
            )
        )
        == [
            "fieldA=/^value1$/i fieldB=/^value2$/i\n"
            "| bucket(span=15m, limit=max, field=[fieldC], function=percentile(Amount, percentiles=[95], as=value_percentile))\n"
            "| rename(value_percentile_95, as=value_percentile)\n"
            "| test(value_percentile >= 100)"
        ]
    )


def test_crowdstrikelogscale_value_median_correlation(
    logscale_backend: LogScaleBackend,
):
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                EVENT_COUNT_BASE
                + """
title: Median of a numeric field
status: test
correlation:
    type: value_median
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        gte: 100
        field: Amount
"""
            )
        )
        == [
            "fieldA=/^value1$/i fieldB=/^value2$/i\n"
            "| bucket(span=15m, limit=max, field=[fieldC], function=percentile(Amount, percentiles=[50], as=value_median))\n"
            "| rename(value_median_50, as=value_median)\n"
            "| test(value_median >= 100)"
        ]
    )


def test_crowdstrikelogscale_temporal_extended_correlation(
    logscale_backend: LogScaleBackend,
):
    """Boolean temporal conditions collect the fired rules and test membership."""
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                TEMPORAL_BASE
                + """
title: Extended temporal condition
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 15m
    condition: base_rule_1 and not base_rule_2
"""
            )
        )
        == [
            "case {\n"
            'fieldA=/^value1$/i fieldB=/^value2$/i | event_type := "base_rule_1";\n'
            'fieldA=/^value3$/i fieldB=/^value4$/i | event_type := "base_rule_2"\n'
            "}\n"
            "| bucket(span=15m, limit=max, field=[fieldC], function=collect([event_type], as=event_types))\n"
            '| splitString(field=event_types, by="\\n", as=matched)\n'
            '| array:contains(array="matched[]", value="base_rule_1")   '
            'not array:contains(array="matched[]", value="base_rule_2")'
        ]
    )


def test_crowdstrikelogscale_temporal_extended_correlation_or(
    logscale_backend: LogScaleBackend,
):
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                TEMPORAL_BASE
                + """
title: Extended temporal OR condition
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 15m
    condition: base_rule_1 or base_rule_2
"""
            )
        )
        == [
            "case {\n"
            'fieldA=/^value1$/i fieldB=/^value2$/i | event_type := "base_rule_1";\n'
            'fieldA=/^value3$/i fieldB=/^value4$/i | event_type := "base_rule_2"\n'
            "}\n"
            "| bucket(span=15m, limit=max, field=[fieldC], function=collect([event_type], as=event_types))\n"
            '| splitString(field=event_types, by="\\n", as=matched)\n'
            '| array:contains(array="matched[]", value="base_rule_1") or '
            'array:contains(array="matched[]", value="base_rule_2")'
        ]
    )


def test_crowdstrikelogscale_temporal_extended_correlation_grouping(
    logscale_backend: LogScaleBackend,
):
    """AND nested inside OR must be parenthesised: in CQL, OR binds tighter than
    AND, so (r1 and r2) or r3 requires explicit parentheses around the AND."""
    assert (
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value2
    condition: selection
---
title: Base rule 3
name: base_rule_3
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
    condition: selection
---
title: Grouped extended temporal
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
        - base_rule_3
    group-by:
        - host
    timespan: 10m
    condition: (base_rule_1 and base_rule_2) or base_rule_3
"""
            )
        )
        == [
            "case {\n"
            'fieldA=/^value1$/i | event_type := "base_rule_1";\n'
            'fieldA=/^value2$/i | event_type := "base_rule_2";\n'
            'fieldA=/^value3$/i | event_type := "base_rule_3"\n'
            "}\n"
            "| bucket(span=10m, limit=max, field=[host], function=collect([event_type], as=event_types))\n"
            '| splitString(field=event_types, by="\\n", as=matched)\n'
            '| (array:contains(array="matched[]", value="base_rule_1")   '
            'array:contains(array="matched[]", value="base_rule_2")) or '
            'array:contains(array="matched[]", value="base_rule_3")'
        ]
    )


def test_crowdstrikelogscale_value_correlation_multiple_fields_unsupported(
    logscale_backend: LogScaleBackend,
):
    """A value_* condition field must be a single field, not a list."""
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="single field"):
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                EVENT_COUNT_BASE
                + """
title: Sum over multiple fields
status: test
correlation:
    type: value_sum
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        gte: 100
        field:
            - fieldD
            - fieldE
"""
            )
        )


def test_crowdstrikelogscale_temporal_ordered_unsupported(
    logscale_backend: LogScaleBackend,
):
    """temporal_ordered has no native template support and raises a clear error."""
    with pytest.raises(NotImplementedError, match="temporal_ordered"):
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                TEMPORAL_BASE
                + """
title: Ordered temporal correlation
status: test
correlation:
    type: temporal_ordered
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 15m
"""
            )
        )
