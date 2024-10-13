from sigma.pipelines.common import (
    logsource_windows_ps_script,
    logsource_windows_driver_load,
    logsource_windows_dns_query,
    logsource_windows_image_load,
    logsource_windows_process_creation,
    logsource_linux_process_creation,
    logsource_windows_network_connection,
    logsource_windows_network_connection_initiated,
)
from sigma.processing.transformations import (
    ReplaceStringTransformation,
    AddConditionTransformation,
    ChangeLogsourceTransformation,
    DropDetectionItemTransformation,
    FieldMappingTransformation,
    DetectionItemFailureTransformation,
    MapStringTransformation,
)
from sigma.processing.conditions import (
    RuleContainsDetectionItemCondition,
    IncludeFieldCondition,
    MatchStringCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.finalization import ConcatenateQueriesFinalizer


cond_field_parentbasefilename = IncludeFieldCondition(fields=["ParentBaseFileName"])
cond_field_contextbasefilename = IncludeFieldCondition(fields=["ContextBaseFileName"])


def generate_unsupported_process_field_processing_item(field):
    return ProcessingItem(
        identifier=f"cql_fail_process_start_{field}",
        transformation=DetectionItemFailureTransformation(
            f"Crowdstrike Query Language does not support the {field} field"
        ),
        rule_conditions=[logsource_windows_process_creation()],
        field_name_conditions=[IncludeFieldCondition(fields=[field])],
    )


def generate_unsupported_network_field_processing_item(field):
    return ProcessingItem(
        identifier=f"cql_fail_network_event_{field}",
        transformation=DetectionItemFailureTransformation(
            f"CrowdStrike Query Language does not support the {field} field"
        ),
        rule_conditions=[logsource_windows_network_connection()],
        field_name_conditions=[IncludeFieldCondition(fields=[field])],
    )


def generate_unsupported_dns_field_processing_item(field):
    return ProcessingItem(
        identifier=f"cql_fail_dns_event_{field}",
        transformation=DetectionItemFailureTransformation(
            f"CrowdStrike Query Language does not support the {field} field"
        ),
        rule_conditions=[logsource_windows_dns_query()],
        field_name_conditions=[IncludeFieldCondition(fields=[field])],
    )


def generate_unsupported_image_load_field_processing_item(field):
    return ProcessingItem(
        identifier=f"cql_fail_imageload_event_{field}",
        transformation=DetectionItemFailureTransformation(
            f"CrowdStrike Query Language does not support the {field} field"
        ),
        rule_conditions=[logsource_windows_image_load()],
        field_name_conditions=[IncludeFieldCondition(fields=[field])],
    )


def generate_unsupported_driverload_field_processing_item(field):
    return ProcessingItem(
        identifier=f"cql_fail_driverload_event_{field}",
        transformation=DetectionItemFailureTransformation(
            f"CrowdStrike Query Language does not support the {field} field"
        ),
        rule_conditions=[logsource_windows_driver_load()],
        field_name_conditions=[IncludeFieldCondition(fields=[field])],
    )

def common_processing_items():
    return [
       ProcessingItem(
        identifier="cql_win",
        transformation=AddConditionTransformation({"event_platform": "Win"}),
        rule_conditions=[
            logsource_windows_process_creation(),
            logsource_windows_dns_query(),
            logsource_windows_driver_load(),
            logsource_windows_image_load(),
            logsource_windows_ps_script(),
        ],
        rule_condition_linking=any,
        ),
        ProcessingItem(
            identifier="cql_process_creation_nix",
            transformation=AddConditionTransformation({"event_platform": "Lin"}),
            rule_conditions=[
                logsource_linux_process_creation(),
            ],
        ),
        ProcessingItem(
            identifier="cql_process_creation_fieldmaping",
            transformation=FieldMappingTransformation(
                {
                    "Image": "ImageFileName",
                    "ParentImage": "ParentBaseFileName",
                    "User": "UserName",
                    "ProcessId": "RawProcessId",
                    "sha256": "SHA256HashData",
                    "Computer": "ComputerName",
                    "OriginalFileName": "OriginalFilename",
                }
            ),
            rule_conditions=[
                logsource_windows_process_creation(),
                logsource_linux_process_creation(),
            ],
            rule_condition_linking=any,
        ),
        # Handle unsupported process start events
        generate_unsupported_process_field_processing_item("CurrentDirectory"),
        generate_unsupported_process_field_processing_item("imphash"),
        generate_unsupported_process_field_processing_item("md5"),
        generate_unsupported_process_field_processing_item("sha1"),
        generate_unsupported_process_field_processing_item("ParentCommandLine"),
        generate_unsupported_process_field_processing_item("FileVersion"),
        generate_unsupported_process_field_processing_item("Description"),
        generate_unsupported_process_field_processing_item("Product"),
        generate_unsupported_process_field_processing_item("Company"),
        generate_unsupported_process_field_processing_item("LogonGuid"),
        generate_unsupported_process_field_processing_item("ParentProcessGuid"),
        generate_unsupported_process_field_processing_item("ParentProcessId"),
        ProcessingItem(
            identifier="crowdstrike_process_creation_logsource",
            transformation=ChangeLogsourceTransformation(
                category="process_creation",
                product="windows",
                service="crowdstrike",
            ),
            rule_conditions=[
                logsource_windows_process_creation(),
            ],
        ),
        # ParentBaseFileName handling
        ProcessingItem(
            identifier="cql_parentbasefilename_fail_completepath",
            transformation=DetectionItemFailureTransformation(
                "Only file name of parent image is available in CrowdStrike Query Language events."
            ),
            field_name_conditions=[
                cond_field_parentbasefilename,
            ],
            detection_item_conditions=[
                MatchStringCondition(
                    cond="any",
                    pattern="^\\*\\\\?[^\\\\]+$",
                    negate=True,
                ),
            ],
        ),
        ProcessingItem(
            identifier="cql_parentbasefilename_executable_only",
            transformation=ReplaceStringTransformation(
                regex="^\\*\\\\([^\\\\]+)$",
                replacement="\\1",
            ),
            field_name_conditions=[
                cond_field_parentbasefilename,
            ],
        ),
        # IntegrityLevel handling
        ProcessingItem(
            identifier="cql_imagefilename_unknown_integrity_level",
            transformation=DetectionItemFailureTransformation(
                "Integrity Level needs to be one of Protected,System,High,Medium_Plus,Medium,Low,Untrusted"
            ),
            field_name_conditions=[
                IncludeFieldCondition(fields=["IntegrityLevel"])
            ],
            rule_conditions=[
                RuleContainsDetectionItemCondition(
                    field="IntegrityLevel", value="Protected"
                ),
                RuleContainsDetectionItemCondition(
                    field="IntegrityLevel", value="System"
                ),
                RuleContainsDetectionItemCondition(
                    field="IntegrityLevel", value="High"
                ),
                RuleContainsDetectionItemCondition(
                    field="IntegrityLevel", value="Medium_Plus"
                ),
                RuleContainsDetectionItemCondition(
                    field="IntegrityLevel", value="Medium"
                ),
                RuleContainsDetectionItemCondition(
                    field="IntegrityLevel", value="Low"
                ),
                RuleContainsDetectionItemCondition(
                    field="IntegrityLevel", value="Untrusted"
                ),
            ],
            rule_condition_linking=any,
            rule_condition_negation=True,
        ),
        ProcessingItem(
            identifier="cql_imagefilename_replace_integrity_level",
            transformation=MapStringTransformation(
                {
                    "Protected": "20480",
                    "System": "16384",
                    "High": "12288",
                    "Medium_Plus": "8448",
                    "Medium": "8192",
                    "Low": "4096",
                    "Untrusted": "0",
                }
            ),
            field_name_conditions=[
                IncludeFieldCondition(fields=["IntegrityLevel"])
            ],
        ),
        # Network Connection Common Processing Items
        ProcessingItem(
            identifier="cql_network_connection_fieldmapping",
            transformation=FieldMappingTransformation(
                {
                    "DestinationIp": "RemoteAddressIP4",
                    "DestinationPort": "RemotePort",
                    "Image": "ContextBaseFileName",
                    "SourcePort": "LocalPort",
                }
            ),
            rule_conditions=[
                logsource_windows_network_connection(),
            ],
        ),
        ProcessingItem(
            identifier="cql_network_connection_drop_initiated",
            transformation=DropDetectionItemTransformation(),
            rule_conditions=[
                logsource_windows_network_connection(),
            ],
            field_name_conditions=[
                IncludeFieldCondition(fields=["Initiated"]),
            ],
        ),
        ProcessingItem(
            identifier="crowdstrike_network_connection_logsource",
            transformation=ChangeLogsourceTransformation(
                category="network_connection",
                product="windows",
                service="crowdstrike",
            ),
            rule_conditions=[
                logsource_windows_network_connection(),
            ],
        ),
        generate_unsupported_network_field_processing_item('DetectionHostName'),
        # DNS Request Common Processing Items
        ProcessingItem(
            identifier="cql_dns_query_fieldmapping",
            transformation=FieldMappingTransformation(
                {
                    "QueryName": "DomainName",
                    "record_type": "RequestType",
                    "Image": "ContextBaseFileName",
                    "QueryResults": ["IP4Records", "IP6Records"],
                }
            ),
            rule_conditions=[
                logsource_windows_dns_query(),
            ],
        ),
        ProcessingItem(
            identifier="cql_dns_query_logsource",
            transformation=ChangeLogsourceTransformation(
                category="dns_query",
                product="windows",
                service="crowdstrike",
            ),
            rule_conditions=[
                logsource_windows_dns_query(),
            ],
        ),
        # Request Type handling
        ProcessingItem(
            identifier="cql_dns_unknown_request_type",
            transformation=DetectionItemFailureTransformation(
                "record_type needs to be one of A,NS,CNAME,PTR,MX,TXT,AAAA,ANY"
            ),
            field_name_conditions=[IncludeFieldCondition(fields=["RequestType"])],
            rule_conditions=[
                RuleContainsDetectionItemCondition(field="RequestType", value="A"),
                RuleContainsDetectionItemCondition(field="RequestType", value="NS"),
                RuleContainsDetectionItemCondition(
                    field="RequestType", value="CNAME"
                ),
                RuleContainsDetectionItemCondition(
                    field="RequestType", value="PTR"
                ),
                RuleContainsDetectionItemCondition(field="RequestType", value="MX"),
                RuleContainsDetectionItemCondition(
                    field="RequestType", value="TXT"
                ),
                RuleContainsDetectionItemCondition(
                    field="RequestType", value="AAAA"
                ),
                RuleContainsDetectionItemCondition(
                    field="RequestType", value="ANY"
                ),
            ],
            rule_condition_linking=any,
            rule_condition_negation=True,
        ),
        ProcessingItem(
            identifier="cql_dns_replace_request_type",
            transformation=MapStringTransformation(
                {
                    "A": "1",
                    "NS": "2",
                    "CNAME": "5",
                    "PTR": "12",
                    "MX": "15",
                    "TXT": "16",
                    "AAAA": "28",
                    "ANY": "255",
                }
            ),
            field_name_conditions=[IncludeFieldCondition(fields=["RequestType"])],
            field_name_condition_linking=any,
        ),
        # Query Results Handling
        # We wanna handle Query Results to always be evaluated as contains
        # This is because CrowdStrike returns the results in a semicolor seperated string
        ProcessingItem(
            identifier="cql_dns_wildcard_query_results",
            transformation=ReplaceStringTransformation(
                regex="(.*)", replacement="*\\1"
            ),
            field_name_conditions=[
                IncludeFieldCondition(fields="IP4Records"),
                IncludeFieldCondition(fields="IP6Records"),
            ],
            field_name_condition_linking=any,
            rule_conditions=[logsource_windows_dns_query()],
            rule_condition_linking=any,
        ),
        # Handle unsupported DNS query fields
        generate_unsupported_dns_field_processing_item("ProcessId"),
        generate_unsupported_dns_field_processing_item("QueryStatus"),
        generate_unsupported_dns_field_processing_item("answer"),
        # Image Load Common Processing Items
        ProcessingItem(
            identifier="cql_imageload_fieldmapping",
            transformation=FieldMappingTransformation(
                {
                    "Image": "TargetImageFileName",
                    "ImageLoaded": "ImageFileName",
                    "sha256": "SHA256HashData",
                    "md5": "MD5HashData",
                }
            ),
            rule_conditions=[
                logsource_windows_image_load(),
            ],
        ),
        generate_unsupported_image_load_field_processing_item("OriginalFileName"),
        generate_unsupported_image_load_field_processing_item("Description"),
        generate_unsupported_image_load_field_processing_item(
            "Signed"
        ),  # partially supported but not consistently
        generate_unsupported_image_load_field_processing_item("Imphash"),
        generate_unsupported_image_load_field_processing_item("CommandLine"),
        # Driver Load Common Processing Items
        ProcessingItem(
            identifier="cql_driverload_fieldmapping",
            transformation=FieldMappingTransformation(
                {
                    "ImageLoaded": "ImageFileName",
                    "sha256": "SHA256HashData",
                    "md5": "MD5HashData",
                    "OriginalFileName": "OriginalFilename",
                }
            ),
            rule_conditions=[
                logsource_windows_driver_load(),
            ],
        ),
        generate_unsupported_driverload_field_processing_item("Hashes"),
        generate_unsupported_driverload_field_processing_item("Imphash"),
        generate_unsupported_driverload_field_processing_item("Image"),
        # PowerShell Scripts Common Processing Items
        ProcessingItem(
            identifier="cql_powershell_script_fieldmapping",
            transformation=FieldMappingTransformation(
                {
                    "Payload": ["CommandHistory", "ScriptContent"],
                    "ScriptBlockText": ["CommandHistory", "ScriptContent"],
                }
            ),
            rule_conditions=[logsource_windows_ps_script()],
            rule_condition_linking=any,
        ),
        # ContextBaseFileName handling
        ProcessingItem(
            identifier="cql_contextbasefilename_fail_completepath",
            transformation=DetectionItemFailureTransformation(
                "Only file name of image is available in CrowdStrike Query Language events."
            ),
            field_name_conditions=[
                cond_field_contextbasefilename,
            ],
            detection_item_conditions=[
                MatchStringCondition(
                    cond="any",
                    pattern="^\\*\\\\?[^\\\\]+$",
                    negate=True,
                ),
            ],
        ),
        ProcessingItem(
            identifier="cql_contextbasefilename_executable_only",
            transformation=ReplaceStringTransformation(
                regex="^\\*\\\\([^\\\\]+)$",
                replacement="\\1",
            ),
            field_name_conditions=[
                cond_field_contextbasefilename,
            ],
        ),
        # ImageFileName full path handling
        ProcessingItem(
            identifier="cql_imagefilename_replace_disk_name",
            transformation=ReplaceStringTransformation(
                regex="[C-Z]:", replacement="\\\\Device\\\\HarddiskVolume?", skip_special=True, interpret_special=True
            ),
            field_name_conditions=[
                IncludeFieldCondition(fields=["ImageFileName"]),
                IncludeFieldCondition(fields=["TargetImageFileName"]),
            ],
            field_name_condition_linking=any,
        ),
        ProcessingItem(
            identifier="cql_imagefilename_replace_disk_name",
            transformation=ReplaceStringTransformation(regex=":", replacement="", skip_special=True),
            field_name_conditions=[
                IncludeFieldCondition(fields=["ImageFileName"]),
                IncludeFieldCondition(fields=["TargetImageFileName"]),
            ],
            field_name_condition_linking=any,
        ),
    ]

def crowdstrike_fdr_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Generic Log Sources to CrowdStrike Falcon Data Replicator (FDR) Transformation",
        priority=10,
        items=[
            # Process Creation
            ProcessingItem(
                identifier="cs_process_creation_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": [
                            "ProcessRollup2",
                            "SyntheticProcessRollup2",
                        ],
                    }
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ],
            ),
            # DNS Request
            ProcessingItem(
                identifier="cql_dns_query_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": "DnsRequest",
                    }
                ),
                rule_conditions=[logsource_windows_dns_query()],
            ),
            # Network Connections
            ProcessingItem(
                identifier="cql_network_connection_eventtype_connect",
                transformation=AddConditionTransformation(
                    {"event_simpleName": "NetworkConnectIP4"}
                ),
                rule_conditions=[
                    logsource_windows_network_connection(),
                    logsource_windows_network_connection_initiated(True),
                ],
            ),
            ProcessingItem(
                identifier="cql_network_connection_eventtype_accept",
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": "NetworkReceiveAcceptIP4",
                    }
                ),
                rule_conditions=[
                    logsource_windows_network_connection(),
                    logsource_windows_network_connection_initiated(False),
                ],
            ),
            # Driver Load
            ProcessingItem(
                identifier="cql_driverload_eventtype",
                transformation=AddConditionTransformation(
                    {"event_simpleName": "DriverLoad"}
                ),
                rule_conditions=[logsource_windows_driver_load()],
            ),
            # Image Load
            ProcessingItem(
                identifier="cql_imageload_eventtype",
                transformation=AddConditionTransformation(
                    {"event_simpleName": "ClassifiedModuleLoad"}
                ),
                rule_conditions=[logsource_windows_image_load()],
                rule_condition_linking=any,
            ),
            # Powershell Scripting
            ProcessingItem(
                identifier="cql_powershell_script_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": [
                            "CommandHistory",
                            "ScriptControlScanTelemetry",
                        ]
                    }
                ),
                rule_conditions=[
                    logsource_windows_ps_script(),
                ],
            ),
        ] + common_processing_items(),
    )

def crowdstrike_falcon_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="CrowdStrike Falcon Pipeline",
        priority=10,
        items=[
            # Process Creation
            ProcessingItem(
                identifier="cql_process_creation_eventtype",
                transformation=AddConditionTransformation(
                    {"#event_simpleName": ["ProcessRollup2", "SyntheticProcessRollup2"]}
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
            ),
            # DNS Request
            ProcessingItem(
                identifier="cql_dns_query_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "#event_simpleName": "DnsRequest",
                    }
                ),
                rule_conditions=[logsource_windows_dns_query()],
            ),
            # Network Connections
            ProcessingItem(
                identifier="cql_network_connection_eventtype_connect",
                transformation=AddConditionTransformation(
                    {"#event_simpleName": "NetworkConnectIP4"}
                ),
                rule_conditions=[
                    logsource_windows_network_connection(),
                    logsource_windows_network_connection_initiated(True),
                ],
            ),
            ProcessingItem(
                identifier="cql_network_connection_eventtype_accept",
                transformation=AddConditionTransformation(
                    {
                        "#event_simpleName": "NetworkReceiveAcceptIP4",
                    }
                ),
                rule_conditions=[
                    logsource_windows_network_connection(),
                    logsource_windows_network_connection_initiated(False),
                ],
            ),
            # Driver Load
            ProcessingItem(
                identifier="cql_driverload_eventtype",
                transformation=AddConditionTransformation(
                    {"#event_simpleName": "DriverLoad"}
                ),
                rule_conditions=[logsource_windows_driver_load()],
            ),
            # Image Load
            ProcessingItem(
                identifier="cql_imageload_eventtype",
                transformation=AddConditionTransformation(
                    {"#event_simpleName": "ClassifiedModuleLoad"}
                ),
                rule_conditions=[logsource_windows_image_load()],
                rule_condition_linking=any,
            ),
            # Powershell Scripting
            ProcessingItem(
                identifier="cql_powershell_script_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "#event_simpleName": [
                            "CommandHistory",
                            "ScriptControlScanTelemetry",
                        ]
                    }
                ),
                rule_conditions=[
                    logsource_windows_ps_script(),
                ],
            ), 
        ] + common_processing_items(),
        finalizers=[ConcatenateQueriesFinalizer()],
    )
