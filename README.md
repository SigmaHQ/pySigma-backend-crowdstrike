![Tests](https://github.com/SigmaHQ/pySigma-pipeline-crowdstrike/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/46f41e1fcf5eaab808ff5742401ac42d/raw)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma CrowdStrike Backend

This is the CrowdStrike backend for pySigma. It provides the package `sigma.backends.crowdstrike` with the `LogScaleBackend` class.

Further it contains the following processing pipelines under `sigma.pipelines.crowdstrike`:
- `crowdstrike_fdr_pipeline` which was mainly written for the Falcon Data Replicator data but Splunk queries should work in the legacy CrowdStrike Splunk. The pipeline can also be used with other backends in case you ingest Falcon data to a different SIEM.
- `crowdstrike_falcon_pipeline` which was written for data collected by the CrowdStrike Falcon Agent stored natively in CrowdStrike Logscale. It effectively translates rules to the CrowdStrike Query Language used by LogScale. This is designed to be used with the `LogScaleBackend`. 

## Supported Rules
### Falcon Pipeline
The following categories and products are supported by the pipelines:
| category | product | CrowdStrike event_simpleName |
|-|-|-|
|`process_creation` | `windows`, `linux`| ProcessRollup2, SyntheticProcessRollup2 |
|`network_connection` | `windows`| NetworkConnectIP4, NetworkReceiveAcceptIP4 |
|`dns_query` | `windows`| DnsRequest |
|`image_load` | `windows`| ClassifiedModuleLoad |
|`driver_load` | `windows`| DriverLoad |
|`ps_script` | `windows`| CommandHistory, ScriptControlScanTelemetry |

There's likely more windows categories that can be supported by the pipelines; We will be adding support gradually as availability allows. 

## Correlation Rules
The `LogScaleBackend` supports [Sigma correlation rules](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md). Aggregation is expressed with LogScale's [`bucket()`](https://library.humio.com/data-analysis/functions-bucket.html) function, which divides the search interval into fixed windows of the rule's `timespan` and groups by the `group-by` fields. The aggregated rows are then filtered on the computed metric with [`test()`](https://library.humio.com/data-analysis/functions-test.html).

The following correlation types are supported:

| type | LogScale aggregation |
|-|-|
| `event_count` | `count(as=event_count)` |
| `value_count` | `count(field=<field>, distinct=true, as=value_count)` |
| `value_sum` | `sum(<field>, as=value_sum)` |
| `value_avg` | `avg(<field>, as=value_avg)` |
| `value_percentile` | `percentile(<field>, percentiles=[<p>], as=…)` (renamed to a fixed field) |
| `value_median` | `percentile(<field>, percentiles=[50], as=…)` (renamed to a fixed field) |
| `temporal` | `count(field=event_type, distinct=true, as=event_type_count)` over events tagged by a [`case{}`](https://library.humio.com/data-analysis/syntax-conditional.html) statement |
| `temporal` with a boolean condition (`r1 and r2 not r3`) | [`collect()`](https://library.humio.com/data-analysis/functions-collect.html) the fired rules per group, then [`array:contains()`](https://library.humio.com/data-analysis/functions-array-contains.html) membership tests |

For example, the following `event_count` correlation rule:
```yaml
title: Failed logon attempts
name: failed_logon
status: test
logsource:
    category: test
detection:
    selection:
        EventType: failed_logon
    condition: selection
---
title: Multiple failed logons for a single user
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    group-by:
        - UserName
    timespan: 10m
    condition:
        gte: 10
```
is converted to:
```
EventType=/^failed_logon$/i
| bucket(span=10m, limit=max, field=[UserName], function=count(as=event_count))
| test(event_count >= 10)
```

`temporal` correlations reference multiple rules. Each rule's matching events are tagged with an `event_type` in a `case{}` statement (events matching no referenced rule are dropped), and the query fires when the distinct number of matched rules per group reaches the number of referenced rules. Field `aliases` are normalised with `| <alias> := <field>` so that `group-by` works across rules with differing field names.

**Caveats:**
- Only the correlation query is emitted; the referenced rules are used as subqueries and are not returned separately.
- Like Splunk's `bin _time`, `bucket()` uses fixed (tumbling) windows aligned to the timespan boundary, so a burst of events that straddles a window boundary may not reach the threshold within a single window.
- `bucket()` is emitted with `limit=max` to avoid its low default series cap, but it is still bounded (top series by value). Very high-cardinality `group-by` correlations may be truncated, and `lt`/`lte` thresholds are unreliable beyond that cap.
- `value_count` uses LogScale's `distinct=true`, which is an estimate (typical error < 2%); exact distinct counts are not available in LogScale.
- `timespan` units map onto LogScale relative-time spans: `s`, `m`, `h`, `d`, `w`, `y` are emitted verbatim and `M` (month) is translated to `mon` (30-day fixed month).
- `value_percentile` uses LogScale's estimated `percentile()`; `value_median` is computed as the 50th percentile.
- `temporal_ordered` is not supported and raises `NotImplementedError`; LogScale has no template-friendly ordered-sequence primitive.

## Limitations and caveats:
- **Full Paths**: 
Falcon agents do not capture drive names when logging paths. Instead, when drive letters are expected the device path is used. For example, `C:\Windows` results to `\Device\HarddiskVolume3\Windows` in the logs. To account for this, the pipeline replaces any drive letters in fields containing full path with `\Device\HarddiskVolume?\`  (where '?' can be any single character).

- **Parent Name**:
Falcon `process_creation` events do not capture the full path of the parent. Hence, in such cases the transformation is configured to fail.

- **DNS Query Results**:
Falcon `dns_query` events return the IP records of a successful query in [semicolon-separated](https://github.com/CrowdStrike/logscale-community-content/blob/main/CrowdStrike-Query-Language-Map/CrowdStrike-Query-Language/concatArray.md) string. The pipeline handles this by enforcing a "contains" expression on the `QueryResults` field
- **Unsupported fields**:
Falcon does not always capture the same fields as sysmon for the categories supported. In cases where the rule requires unsupported fields, the transformation fails.

- **PS Script Logging**:
There is not a clean equivelant between the events Falcon generates and PowerShell Script Logging. Our transformation is a best-effort approach that contains multiple fields that might contain the value in the field.

## References
- [LogScale Community Content](https://github.com/CrowdStrike/logscale-community-content)

This backend is currently maintained by:

* [Thomas Patzke](https://github.com/thomaspatzke/)
* [Panos Moullotos](https://github.com/moullos)