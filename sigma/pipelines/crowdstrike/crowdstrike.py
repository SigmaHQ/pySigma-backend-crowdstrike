from sigma.pipelines.common import (
    logsource_windows_ps_script,
    logsource_windows_driver_load,
    logsource_windows_dns_query,
    logsource_windows_image_load,
    logsource_windows_process_creation,
    logsource_linux_process_creation,
    logsource_windows_network_connection,
    logsource_windows_network_connection_initiated,
    logsource_macos_process_creation,
    logsource_windows_file_event,
    logsource_windows_registry_event,
    logsource_windows_registry_add,
    logsource_windows_registry_set,
    logsource_windows_registry_delete,
)
from sigma.exceptions import SigmaTransformationError
from sigma.modifiers import (
    SigmaContainsModifier,
    SigmaEndswithModifier,
    SigmaExistsModifier,
    SigmaFieldReferenceModifier,
)
from sigma.conditions import (
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.types import SigmaNull, SigmaString, SpecialChars
from sigma.processing.transformations.base import DetectionItemTransformation
from sigma.processing.transformations import (
    RuleFailureTransformation,
    ReplaceStringTransformation,
    AddConditionTransformation,
    ChangeLogsourceTransformation,
    DropDetectionItemTransformation,
    FieldMappingTransformation,
    DetectionItemFailureTransformation,
    Transformation,
    MapStringTransformation,
)
from sigma.processing.conditions import (
    LogsourceCondition,
    RuleContainsDetectionItemCondition,
    IncludeFieldCondition,
    MatchStringCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.condition_expressions import parse_condition_expression
from sigma.processing.finalization import ConcatenateQueriesFinalizer


def cond_field_parentbasefilename():
    return IncludeFieldCondition(fields=["ParentBaseFileName"])


def cond_field_contextbasefilename():
    return IncludeFieldCondition(fields=["ContextBaseFileName"])


MACOS_PROCESS_FIELDS = ["Image", "CommandLine", "ParentImage", "sha256"]
# plus ParentImage as already renamed by an earlier pipeline
MACOS_CHECKED_FIELDS = MACOS_PROCESS_FIELDS + ["ParentBaseFileName"]


class MacOSUnsupportedField(Transformation):
    """Fail every rule-written macOS process_creation field outside the allow list.

    The allow list is based on which ProcessRollup2 fields Falcon was observed to
    populate on a macOS host; other fields would convert into queries that silently
    miss events. Conditions that an AddConditionTransformation of the pipeline added
    (the platform and event conditions, or host scoping from a companion pipeline) are
    recognized by provenance: their items carry the identifier of the processing item
    that added them, which a rule author cannot forge. An earlier pipeline that renames
    Image or sha256 makes rules fail here (a false failure, not a bypass).
    """

    def apply(self, rule):
        if isinstance(rule, SigmaCorrelationRule):
            self._check_correlation(rule)
        if not isinstance(rule, SigmaRule):
            return
        added_by = {
            item.identifier
            for item in self._pipeline.items
            if isinstance(item.transformation, AddConditionTransformation)
        }
        for detection in rule.detection.detections.values():
            self._check(detection, added_by)

    def _check_correlation(self, rule):
        """Check the group-by names and the condition field (alias use fails elsewhere)."""
        supported = MACOS_CHECKED_FIELDS
        condition_field = getattr(rule.condition, "fieldref", None)
        if isinstance(condition_field, str):
            condition_field = [condition_field]
        for name in (rule.group_by or []) + (condition_field or []):
            if name not in supported:
                raise SigmaTransformationError(
                    f"Crowdstrike Query Language does not support the {name} field on macOS; "
                    f"supported fields: {', '.join(supported)}",
                    source=rule.source,
                )

    def _check(self, detection, added_by):
        for item in detection.detection_items:
            if hasattr(item, "detection_items"):
                self._check(item, added_by)
            elif item.applied_processing_items & added_by:
                continue
            elif item.field is None:
                raise SigmaTransformationError(
                    "Keyword search isn't supported for macOS process_creation; "
                    f"use one of the fields: {', '.join(MACOS_PROCESS_FIELDS)}",
                    source=item.source,
                )
            # ParentBaseFileName: ParentImage as already renamed by an earlier pipeline
            elif item.field not in MACOS_CHECKED_FIELDS:
                raise SigmaTransformationError(
                    f"Crowdstrike Query Language does not support the {item.field} field on macOS; "
                    f"supported fields: {', '.join(MACOS_PROCESS_FIELDS)}",
                    source=item.source,
                )


def has_backslash(value):
    """True for a string value containing a backslash (macOS paths use forward slashes)."""
    return isinstance(value, SigmaString) and "\\" in "".join(
        p for p in value.s if isinstance(p, str)
    )


class MacOSCorrelationAliasGuard(Transformation):
    """Fail a correlation that uses aliases and references a macOS process_creation rule.

    The references are followed through chained correlations down to the base rules.
    Aliases would carry field names past the macOS field allow list.
    """

    def apply(self, rule):
        if (
            isinstance(rule, SigmaCorrelationRule)
            and rule.aliases.aliases
            and self._references_macos(rule, set())
        ):
            raise SigmaTransformationError(
                "aliases are not supported for macOS correlations; group by a supported field name",
                source=rule.source,
            )

    def _references_macos(self, rule, seen):
        if id(rule) in seen:
            return False
        seen.add(id(rule))
        for referenced in rule.referenced_rules or []:
            ref_rule = getattr(referenced, "rule", None)
            if isinstance(ref_rule, SigmaCorrelationRule):
                if self._references_macos(ref_rule, seen):
                    return True
            elif isinstance(ref_rule, SigmaRule) and (
                logsource_macos_process_creation().match(ref_rule)
            ):
                return True
        return False


class MacOSExistsGuard(DetectionItemTransformation):
    """Reject |exists on every macOS field in the Falcon pipeline: this package's LogScaleBackend cannot express it."""

    def apply_detection_item(self, detection_item):
        if SigmaExistsModifier in detection_item.modifiers:
            raise SigmaTransformationError(
                f"{detection_item.field}|exists is not supported on macOS: the LogScaleBackend "
                "of this package cannot express exists",
                source=detection_item.source,
            )


class MacOSParentImageGuard(DetectionItemTransformation):
    """Accept only ParentImage values that can be matched on the parent's basename.

    Falcon only records the basename of the parent process (ParentBaseFileName), so
    any directory in the value cannot be honored (stripping it would widen the match,
    and a negated filter would exclude every process with that name). Accepted:
    - endswith a literal name, optionally `/name` (or `*/name`): wildcards in the
      name could span directories in Sigma's path semantics, and the
      case-sensitivity of `cased` is lost in the rewrite;
    - contains a literal without `/` or wildcards, only where the detection is never
      referenced under a NOT (see MacOSParentImageContainsNegationGuard);
    - null (a missing parent).
    Other modifiers and value types (numbers, booleans, regular expressions,
    field references) cannot be expressed. A literal that isn't the basename of the usual
    app binary (for example the bundle directory `Terminal.app`, not `Terminal`) is accepted
    but never matches.
    """

    def _fail(self, detection_item, message):
        raise SigmaTransformationError(message, source=detection_item.source)

    def apply_detection_item(self, detection_item):
        modifiers = detection_item.modifiers
        if SigmaFieldReferenceModifier in modifiers:
            self._fail(
                detection_item,
                "Field references (fieldref) involving ParentImage are not supported on macOS: "
                "ParentBaseFileName holds only the file name of the parent image",
            )
        unsupported = [
            m.__name__
            for m in modifiers
            if m not in (SigmaEndswithModifier, SigmaContainsModifier)
        ]
        if unsupported:
            self._fail(
                detection_item,
                f"ParentImage modifier(s) {unsupported} not supported on macOS: only the file "
                "name of the parent image is available, so only endswith and contains work",
            )
        contains = SigmaContainsModifier in modifiers
        for value in detection_item.value:
            if isinstance(value, SigmaNull):
                continue
            if not isinstance(value, SigmaString):
                self._fail(
                    detection_item,
                    f"ParentImage value '{value}' is a {type(value).__name__}; only string "
                    "values (and null) are supported on macOS",
                )
            parts = value.s
            if has_backslash(value):
                self._fail(
                    detection_item,
                    f"ParentImage value '{value}' contains a backslash; macOS paths use forward slashes",
                )
            if contains:
                # Exactly: wildcard, a literal without "/", wildcard.
                valid = (
                    len(parts) == 3
                    and parts[0] == SpecialChars.WILDCARD_MULTI
                    and isinstance(parts[1], str)
                    and "/" not in parts[1]
                    and parts[2] == SpecialChars.WILDCARD_MULTI
                )
                hint = "contains needs a literal without '/' or wildcards"
            else:
                # Exactly: leading wildcard, then a literal name without wildcards,
                # optionally preceded by one "/" (a bare literal endswith is the same
                # on a basename).
                name = parts[1] if len(parts) == 2 and isinstance(parts[1], str) else ""
                valid = (
                    len(parts) == 2
                    and parts[0] == SpecialChars.WILDCARD_MULTI
                    and name.removeprefix("/") != ""
                    and "/" not in name.removeprefix("/")
                )
                hint = "use endswith with a literal file name, optionally as '/name' (no wildcards, no directories)"
            if not valid:
                self._fail(
                    detection_item,
                    f"ParentImage value '{value}' is not supported on macOS: only the file name "
                    f"of the parent image is available, so {hint}",
                )


class MacOSParentImageContainsNegationGuard(Transformation):
    """Reject ParentImage|contains in any detection the condition references under a NOT.

    On a basename, contains can only narrow a positive selection, but under a NOT (or
    a nested NOT, as in `sel and not (a and not b)`) narrowing becomes widening: the
    value `Terminal.app` is not the basename of the usual app binary, so the exclusion built on it
    stops excluding what the full path excluded.
    """

    def apply(self, rule):
        if not isinstance(rule, SigmaRule):
            return
        # Map each value object to the detection item it came from: in the parsed
        # condition tree a leaf's parent can be an OR/AND node (several values or
        # fields in one detection), so the identity of the value is the reliable link.
        origin = {}

        def collect(detection):
            for item in detection.detection_items:
                if hasattr(item, "detection_items"):
                    collect(item)
                else:
                    for value in item.value:
                        origin[id(value)] = item

        for detection in rule.detection.detections.values():
            collect(detection)
        for condition in rule.detection.parsed_condition:
            self._walk(condition.parsed, False, origin)

    def _walk(self, node, negated, origin):
        if isinstance(node, ConditionFieldEqualsValueExpression):
            item = origin.get(id(node.value))
            if (
                negated
                and item is not None
                # ParentBaseFileName: already renamed by a pipeline that ran earlier
                and item.field in ("ParentImage", "ParentBaseFileName")
                and SigmaContainsModifier in item.modifiers
            ):
                raise SigmaTransformationError(
                    "ParentImage|contains is not supported on macOS in a detection used "
                    "under 'not': it matches only the parent's file name, which would "
                    "widen the exclusion; use endswith with a file name",
                    source=item.source,
                )
            return
        negated = negated or isinstance(node, ConditionNOT)
        for arg in getattr(node, "args", []):
            self._walk(arg, negated, origin)


class MacOSImageBackslashGuard(DetectionItemTransformation):
    """Reject Image values with a backslash: macOS paths use forward slashes."""

    def apply_detection_item(self, detection_item):
        for value in detection_item.value:
            if has_backslash(value):
                raise SigmaTransformationError(
                    f"Image value '{value}' contains a backslash; macOS paths use forward slashes",
                    source=detection_item.source,
                )


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


def generate_unsupported_file_event_field_processing_item(field):
    return ProcessingItem(
        identifier=f"cql_fail_file_event_{field}",
        transformation=DetectionItemFailureTransformation(
            f"CrowdStrike Query Language does not support the {field} field"
        ),
        rule_conditions=[logsource_windows_file_event()],
        field_name_conditions=[IncludeFieldCondition(fields=[field])],
    )


def generate_unsupported_registry_event_field_processing_item(field):
    return ProcessingItem(
        identifier=f"cql_fail_registry_event_{field}",
        transformation=DetectionItemFailureTransformation(
            f"CrowdStrike Query Language does not support the {field} field"
        ),
        rule_conditions=[
            logsource_windows_registry_event(),
            logsource_windows_registry_add(),
            logsource_windows_registry_set(),
            logsource_windows_registry_delete(),
        ],
        rule_condition_linking=any,
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
            logsource_windows_file_event(),
            logsource_windows_registry_event(),
            logsource_windows_registry_add(),
            logsource_windows_registry_set(),
            logsource_windows_registry_delete(),
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
            identifier="cql_process_creation_mac",
            transformation=AddConditionTransformation({"event_platform": "Mac"}),
            rule_conditions=[
                logsource_macos_process_creation(),
            ],
        ),
        # macOS: only fields observed populated are allowed; checked before the field mapping
        ProcessingItem(
            identifier="cql_macos_correlation_alias",
            transformation=MacOSCorrelationAliasGuard(),
        ),
        ProcessingItem(
            identifier="cql_macos_unsupported_field",
            transformation=MacOSUnsupportedField(),
            rule_conditions=[logsource_macos_process_creation()],
        ),
        ProcessingItem(
            identifier="cql_macos_parentimage_contains_negation",
            transformation=MacOSParentImageContainsNegationGuard(),
            rule_conditions=[logsource_macos_process_creation()],
        ),
        ProcessingItem(
            identifier="cql_macos_image_backslash",
            transformation=MacOSImageBackslashGuard(),
            rule_conditions=[logsource_macos_process_creation()],
            field_name_conditions=[IncludeFieldCondition(fields=["Image"])],
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
                logsource_macos_process_creation(),
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
        # macOS supports process_creation only
        ProcessingItem(
            identifier="cql_macos_unsupported_category",
            transformation=RuleFailureTransformation(
                "Only the process_creation category is supported for macOS"
            ),
            rule_conditions={
                "macos": LogsourceCondition(product="macos"),
                "process_creation": logsource_macos_process_creation(),
            },
            rule_condition_expression=parse_condition_expression(
                "macos and not process_creation"
            ),
        ),
        # Falcon only records the basename of the macOS parent process
        ProcessingItem(
            identifier="cql_macos_parentbasefilename_guard",
            transformation=MacOSParentImageGuard(),
            rule_conditions=[logsource_macos_process_creation()],
            field_name_conditions=[cond_field_parentbasefilename()],
        ),
        ProcessingItem(
            identifier="cql_macos_parentbasefilename_executable_only",
            transformation=ReplaceStringTransformation(
                regex="^.*/",
                replacement="",
            ),
            rule_conditions=[logsource_macos_process_creation()],
            field_name_conditions=[cond_field_parentbasefilename()],
        ),
        # ParentBaseFileName handling
        ProcessingItem(
            identifier="cql_parentbasefilename_fail_completepath",
            transformation=DetectionItemFailureTransformation(
                "Only file name of parent image is available in CrowdStrike Query Language events."
            ),
            rule_conditions=[logsource_macos_process_creation()],
            rule_condition_negation=True,
            field_name_conditions=[
                cond_field_parentbasefilename(),
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
            rule_conditions=[logsource_macos_process_creation()],
            rule_condition_negation=True,
            field_name_conditions=[
                cond_field_parentbasefilename(),
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
        # File Event Common Processing Items
        ProcessingItem(
            identifier="cql_file_event_fieldmapping",
            transformation=FieldMappingTransformation(
                {
                    "TargetFilename": "TargetFileName",
                    "Image": "ContextBaseFileName",
                    "User": "UserName",
                    "ProcessId": "RawProcessId",
                    "Computer": "ComputerName",
                    "sha256": "SHA256HashData",
                    "md5": "MD5HashData",
                }
            ),
            rule_conditions=[
                logsource_windows_file_event(),
            ],
        ),
        ProcessingItem(
            identifier="crowdstrike_file_event_logsource",
            transformation=ChangeLogsourceTransformation(
                category="file_event",
                product="windows",
                service="crowdstrike",
            ),
            rule_conditions=[
                logsource_windows_file_event(),
            ],
        ),
        # Handle unsupported file event fields
        generate_unsupported_file_event_field_processing_item("Hashes"),
        generate_unsupported_file_event_field_processing_item("Imphash"),
        generate_unsupported_file_event_field_processing_item("sha1"),
        generate_unsupported_file_event_field_processing_item("CommandLine"),
        generate_unsupported_file_event_field_processing_item("ParentImage"),
        # Registry Event Common Processing Items
        ProcessingItem(
            identifier="cql_registry_event_fieldmapping",
            transformation=FieldMappingTransformation(
                {
                    "TargetObject": "RegObjectName",
                    "Details": ["RegStringValue", "RegNumericValue", "RegBinaryValue"],
                    "Image": "ContextBaseFileName",
                    "User": "UserName",
                    "ProcessId": "RawProcessId",
                    "Computer": "ComputerName",
                }
            ),
            rule_conditions=[
                logsource_windows_registry_event(),
                logsource_windows_registry_add(),
                logsource_windows_registry_set(),
                logsource_windows_registry_delete(),
            ],
            rule_condition_linking=any,
        ),
        ProcessingItem(
            identifier="crowdstrike_registry_event_logsource",
            transformation=ChangeLogsourceTransformation(
                category="registry_event",
                product="windows",
                service="crowdstrike",
            ),
            rule_conditions=[
                logsource_windows_registry_event(),
                logsource_windows_registry_add(),
                logsource_windows_registry_set(),
                logsource_windows_registry_delete(),
            ],
            rule_condition_linking=any,
        ),
        # Handle unsupported registry event fields
        generate_unsupported_registry_event_field_processing_item("EventType"),
        generate_unsupported_registry_event_field_processing_item("NewName"),
        generate_unsupported_registry_event_field_processing_item("Hashes"),
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
                cond_field_contextbasefilename(),
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
                cond_field_contextbasefilename(),
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
                IncludeFieldCondition(fields=["TargetFileName"]),
            ],
            rule_conditions=[logsource_macos_process_creation()],
            rule_condition_negation=True,
            field_name_condition_linking=any,
        ),
        ProcessingItem(
            identifier="cql_imagefilename_remove_colon",
            transformation=ReplaceStringTransformation(regex=":", replacement="", skip_special=True),
            field_name_conditions=[
                IncludeFieldCondition(fields=["ImageFileName"]),
                IncludeFieldCondition(fields=["TargetImageFileName"]),
                IncludeFieldCondition(fields=["TargetFileName"]),
            ],
            rule_conditions=[logsource_macos_process_creation()],
            rule_condition_negation=True,
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
                    logsource_macos_process_creation(),
                ],
                rule_condition_linking=any,
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
            ProcessingItem(
                identifier="cql_network_connection_eventtype_both",
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": [
                            "NetworkConnectIP4",
                            "NetworkReceiveAcceptIP4",
                        ]
                    }
                ),
                rule_conditions={
                    "logsource": logsource_windows_network_connection(),
                    "init_true": logsource_windows_network_connection_initiated(True),
                    "init_false": logsource_windows_network_connection_initiated(False),
                },
                rule_condition_expression=parse_condition_expression(
                    "logsource and not (init_true or init_false)"
                ),
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
            # File Event
            ProcessingItem(
                identifier="cql_file_event_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": [
                            "PEFileWritten",
                            "NewExecutableWritten",
                            "NewExecutableRenamed",
                            "PNGFileWritten",
                            "OleFileWritten",
                            "RtfFileWritten",
                            "LnkFileWritten",
                            "ScriptFileWritten",
                            "PdfFileWritten",
                            "MsiFileWritten",
                            "IsoFileWritten",
                            "JavaScriptFileWritten",
                            "HtmlFileWritten",
                            "JarFileWritten",
                            "OfficeFileWritten",
                            "SettingsContentFileWritten",
                            "MachOFileWritten",
                            "ZipFileWritten",
                        ]
                    }
                ),
                rule_conditions=[
                    logsource_windows_file_event(),
                ],
            ),
            # Registry Event
            ProcessingItem(
                identifier="cql_registry_event_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "event_simpleName": [
                            "RegistryOperationDetectInfo",
                            "AsepValueUpdate",
                            "AsepKeyUpdate",
                            "RegSystemConfigValueUpdate",
                            "RegBinaryValueUpdate",
                            "RegStringValueUpdate",
                            "RegMultiStringValueUpdate",
                            "RegDwordValueUpdate",
                            "RegQwordValueUpdate",
                            "RegLinkValueUpdate",
                            "RegGenericValueUpdate",
                            "RegKeyCreated",
                            "RegKeyDeleted",
                            "RegValueDeleted",
                        ]
                    }
                ),
                rule_conditions=[
                    logsource_windows_registry_event(),
                    logsource_windows_registry_add(),
                    logsource_windows_registry_set(),
                    logsource_windows_registry_delete(),
                ],
                rule_condition_linking=any,
            ),
        ] + common_processing_items(),
    )

def crowdstrike_falcon_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="CrowdStrike Falcon Pipeline",
        priority=10,
        items=[
            # Falcon only: the FDR pipeline is also used with backends that can express exists.
            ProcessingItem(
                identifier="cql_macos_exists",
                transformation=MacOSExistsGuard(),
                rule_conditions=[logsource_macos_process_creation()],
            ),
            # Process Creation
            ProcessingItem(
                identifier="cql_process_creation_eventtype",
                transformation=AddConditionTransformation(
                    {"#event_simpleName": ["ProcessRollup2", "SyntheticProcessRollup2"]}
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                    logsource_macos_process_creation(),
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
            ProcessingItem(
                identifier="cql_network_connection_eventtype_both",
                transformation=AddConditionTransformation(
                    {
                        "#event_simpleName": [
                            "NetworkConnectIP4",
                            "NetworkReceiveAcceptIP4",
                        ]
                    }
                ),
                rule_conditions={
                    "logsource": logsource_windows_network_connection(),
                    "init_true": logsource_windows_network_connection_initiated(True),
                    "init_false": logsource_windows_network_connection_initiated(False),
                },
                rule_condition_expression=parse_condition_expression(
                    "logsource and not (init_true or init_false)"
                ),
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
            # File Event
            ProcessingItem(
                identifier="cql_file_event_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "#event_simpleName": [
                            "PEFileWritten",
                            "NewExecutableWritten",
                            "NewExecutableRenamed",
                            "PNGFileWritten",
                            "OleFileWritten",
                            "RtfFileWritten",
                            "LnkFileWritten",
                            "ScriptFileWritten",
                            "PdfFileWritten",
                            "MsiFileWritten",
                            "IsoFileWritten",
                            "JavaScriptFileWritten",
                            "HtmlFileWritten",
                            "JarFileWritten",
                            "OfficeFileWritten",
                            "SettingsContentFileWritten",
                            "MachOFileWritten",
                            "ZipFileWritten",
                        ]
                    }
                ),
                rule_conditions=[
                    logsource_windows_file_event(),
                ],
            ),
            # Registry Event
            ProcessingItem(
                identifier="cql_registry_event_eventtype",
                transformation=AddConditionTransformation(
                    {
                        "#event_simpleName": [
                            "RegistryOperationDetectInfo",
                            "AsepValueUpdate",
                            "AsepKeyUpdate",
                            "RegSystemConfigValueUpdate",
                            "RegBinaryValueUpdate",
                            "RegStringValueUpdate",
                            "RegMultiStringValueUpdate",
                            "RegDwordValueUpdate",
                            "RegQwordValueUpdate",
                            "RegLinkValueUpdate",
                            "RegGenericValueUpdate",
                            "RegKeyCreated",
                            "RegKeyDeleted",
                            "RegValueDeleted",
                        ]
                    }
                ),
                rule_conditions=[
                    logsource_windows_registry_event(),
                    logsource_windows_registry_add(),
                    logsource_windows_registry_set(),
                    logsource_windows_registry_delete(),
                ],
                rule_condition_linking=any,
            ),
        ] + common_processing_items(),
        finalizers=[ConcatenateQueriesFinalizer()],
    )
