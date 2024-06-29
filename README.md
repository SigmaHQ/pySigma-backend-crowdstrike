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