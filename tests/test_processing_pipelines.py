from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError, SigmaTransformationError
from sigma.backends.test import TextQueryTestBackend
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
    ValueListPlaceholderTransformation,
)
from sigma.pipelines.crowdstrike import (
    crowdstrike_fdr_pipeline,
    crowdstrike_falcon_pipeline,
)
from sigma.backends.crowdstrike import LogScaleBackend
import pytest

unsupported_process_creation_fields = [
    "CurrentDirectory",
    "imphash",
    "md5",
    "sha1",
    "ParentCommandLine",
    "FileVersion",
    "Description",
    "Product",
    "Company",
    "LogonGuid",
    "ParentProcessGuid",
    "ParentProcessId",
]


@pytest.fixture
def resolver():
    return ProcessingPipelineResolver(
        {
            "crowdstrike_fdr": crowdstrike_fdr_pipeline,
            "crowdstrike_falcon": crowdstrike_falcon_pipeline,
        }
    )


@pytest.fixture
def process_creation_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                Image: "*\\\\test.exe"
            condition: sel
        """
    )


@pytest.fixture
def process_creation_sigma_rule_all_fields():
    return SigmaCollection.from_yaml(
        """
        title: Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Image: test
                User: test
                Image: test
                ProcessId: test
                sha256: test
                Computer: test
            condition: sel
        """
    )


@pytest.fixture
def process_creation_sigma_rule_all_fields_nix():
    return SigmaCollection.from_yaml(
        """
        title: Test
        status: test
        logsource:
            category: process_creation
            product: linux
        detection:
            sel:
                Image: test
                User: test
                Image: test
                ProcessId: test
                sha256: test
                Computer: test
            condition: sel
        """
    )


@pytest.fixture
def process_creation_sigma_rule_parentimage():
    return SigmaCollection.from_yaml(
        """
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                ParentImage: "*\\\\parent.exe"
            condition: sel
        """
    )


@pytest.fixture
def process_creation_sigma_rule_integrity_level():
    return SigmaCollection.from_yaml(
        """
        title: Integrity Level Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                IntegrityLevel: System

            condition: sel
        """
    )


@pytest.fixture
def process_creation_sigma_rule_unknown_integrity_level():
    return SigmaCollection.from_yaml(
        """
        title: Integrity Level Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                IntegrityLevel: NonExistant
            condition: sel
        """
    )


@pytest.fixture
def process_creation_sigma_rule_parentimage_without_slash():
    return SigmaCollection.from_yaml(
        """
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                ParentImage: "*parent.exe"
            condition: sel
        """
    )


@pytest.fixture
def process_creation_sigma_rule_parentimage_path():
    return SigmaCollection.from_yaml(
        """
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                ParentImage: "*\\\\Windows\\\\System32\\\\parent.exe"
            condition: sel
        """
    )


@pytest.fixture
def process_creation_sigma_rule_fullimage_path():
    return SigmaCollection.from_yaml(
        """
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                Image: "C:\\\\Windows\\\\System32\\\\cmd.exe"
            condition: sel
        """
    )


@pytest.fixture
def process_creation_sigma_rule_disk_name_colon():
    return SigmaCollection.from_yaml(
        """
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                Image|endswith: ":\\\\Windows\\\\System32\\\\cmd.exe"
            condition: sel
        """
    )

@pytest.fixture
def process_creation_sigma_rule_disk_name_contains():
    return SigmaCollection.from_yaml(
        """
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                Image|contains: "C:\\\\Windows\\\\System32\\\\cmd.exe"
            condition: sel
        """
    )

@pytest.fixture
def process_creation_sigma_rule_disk_name_startswith():
    return SigmaCollection.from_yaml(
        """
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                Image|startswith: "C:\\\\Windows\\\\System32\\\\cmd.exe"
            condition: sel
        """
    )

@pytest.fixture
def process_creation_sigma_rule_disk_name_endswith():
    return SigmaCollection.from_yaml(
        """
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                Image|endswith: "C:\\\\Windows\\\\System32\\\\cmd.exe"
            condition: sel
        """
    )

@pytest.fixture
def process_creation_sigma_rule_unsupported_field(field):
    return SigmaCollection.from_yaml(
        f"""
        title: Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                {field}: test
            condition: sel
        """
    )


@pytest.fixture
def network_connection_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Network Connection Test
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
               Initiated: "true"
               DestinationIp: "1.2.3.4"
            condition: sel
        """
    )


@pytest.fixture
def incoming_network_connection_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Incoming Network Connection Test
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
               Initiated: "false"
               DestinationIp: "1.2.3.4"
            condition: sel
        """
    )


@pytest.fixture
def network_connection_no_initiated_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Network Connection Test Without Initiated
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
                Image|contains: '$Recycle.Bin'
            condition: sel
        """
    )


@pytest.fixture
def dns_query_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: DNS Query Test
        status: test
        logsource:
            category: dns_query
            product: windows
        detection:
            sel:
                QueryName: test.invalid
                record_type: 
                    - A
                    - NS
                    - CNAME
                    - PTR
                    - MX
                    - TXT
                    - AAAA
                    - ANY
                QueryResults : 1.1.1.1
                Image: "*\\\\parent.exe"
            condition: sel
        """
    )


@pytest.fixture
def dns_query_sigma_rule_invalid_request():
    return SigmaCollection.from_yaml(
        """
        title: DNS Query Test
        status: test
        logsource:
            category: dns_query
            product: windows
        detection:
            sel:
                QueryName: test.invalid
                record_type: NonValid
                QueryResults : 1.1.1.1
            condition: sel
        """
    )


@pytest.fixture
def dns_query_sigma_rule_full_image_path():
    return SigmaCollection.from_yaml(
        """
        title: DNS Query Test
        status: test
        logsource:
            category: dns_query
            product: windows
        detection:
            sel:
                QueryName: test.invalid
                record_type: A
                Image: "*\\\\Windows\\\\System32\\\\parent.exe"
            condition: sel
        """
    )


@pytest.fixture
def driver_load_sigma_rule_simple():
    return SigmaCollection.from_yaml(
        """
        title: Driver Load Test
        status: test
        logsource:
            category: driver_load
            product: windows
        detection:
            sel:
                ImageLoaded: imageloaded.exe
                sha256: test
                md5: test
            condition: sel
        """
    )


@pytest.fixture
def driver_load_sigma_rule_driver_load_full_path():
    return SigmaCollection.from_yaml(
        """
        title: Driver Load Test
        status: test
        logsource:
            category: driver_load
            product: windows
        detection:
            sel:
                ImageLoaded: C:\\Windows\\test.sys
                sha256: test
                md5: test
            condition: sel
        """
    )


@pytest.fixture
def image_load_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Image Load Test
        status: test
        logsource:
            category: image_load
            product: windows
        detection:
            sel:
                ImageLoaded: C:\\Windows\\test.sys
                Image: C:\\Windows\\test.exe
                sha256: test
                md5: test
            condition: sel
        """
    )


@pytest.fixture
def ps_script_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Image Load Test
        status: test
        logsource:
            category: ps_script
            product: windows
        detection:
            sel:
                ScriptBlockText|contains: 'test'
            condition: sel
        """
    )


def convert_falcon(rule: SigmaCollection, resolver):
    pipeline = resolver.resolve_pipeline("crowdstrike_falcon")
    backend = LogScaleBackend(pipeline)
    return backend.convert(rule)


### FALCON TESTS ###
def test_crowdstrike_falcon_pipeline_process_creation(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule
):
    assert (
        convert_falcon(process_creation_sigma_rule, resolver)
        == "event_platform=/^Win$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) CommandLine=/^test\\.exe foo bar$/i ImageFileName=/\\\\test\\.exe$/i"
    )

def test_crowdstrike_falcon_image_with_placeholder(resolver : ProcessingPipelineResolver):
    sigma_rule = SigmaCollection.from_yaml("""
        title: Image with Placeholder Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Image|expand: "%var%"
            condition: sel
    """)
    pipeline = resolver.resolve_pipeline("crowdstrike_falcon") + ProcessingPipeline(
        items=[
            ProcessingItem(transformation=ValueListPlaceholderTransformation())
        ],
        vars={"var": ["foo.exe", "bar.exe", "test.exe"]},
    )
    backend = LogScaleBackend(pipeline)
    assert backend.convert(sigma_rule) == "event_platform=/^Win$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) (ImageFileName=/^foo\\.exe$/i or ImageFileName=/^bar\\.exe$/i or ImageFileName=/^test\\.exe$/i)"

def test_crowdstrike_falcon_image_contains_with_trailing_backslash(resolver : ProcessingPipelineResolver):
    sigma_rule = SigmaCollection.from_yaml("""
        title: Image with Placeholder Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Image|contains: ":\\\\Windows\\\\System32\\\\"
            condition: sel
    """)
    pipeline = resolver.resolve_pipeline("crowdstrike_falcon")
    backend = LogScaleBackend(pipeline)
    assert "ImageFileName=/\\\\Windows\\\\System32\\\\/i" in backend.convert(sigma_rule)


def test_crowdstrike_falcon_pipeline_parentimage(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_parentimage
):
    assert (
        convert_falcon(process_creation_sigma_rule_parentimage, resolver)
        == "event_platform=/^Win$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) CommandLine=/^test\\.exe foo bar$/i ParentBaseFileName=/^parent\\.exe$/i"
    )


def test_crowdstrike_falcon_pipeline_process_creation_all_fields(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_all_fields
):
    assert (
        convert_falcon(process_creation_sigma_rule_all_fields, resolver)
        == "event_platform=/^Win$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) ImageFileName=/^test$/i UserName=/^test$/i RawProcessId=/^test$/i SHA256HashData=/^test$/i ComputerName=/^test$/i"
    )


def test_crowdstrike_falcon_pipeline_process_creation_all_fields_nix(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_all_fields_nix
):
    assert (
        convert_falcon(process_creation_sigma_rule_all_fields_nix, resolver)
        == "event_platform=/^Lin$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) ImageFileName=/^test$/i UserName=/^test$/i RawProcessId=/^test$/i SHA256HashData=/^test$/i ComputerName=/^test$/i"
    )


def test_crowdstrike_falcon_pipeline_integrity_level(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_integrity_level
):
    assert (
        convert_falcon(process_creation_sigma_rule_integrity_level, resolver)
        == "event_platform=/^Win$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) IntegrityLevel=/^16384$/i"
    )


def test_crowdstrike_falcon_pipeline_unknown_integrity_level(
    resolver: ProcessingPipelineResolver,
    process_creation_sigma_rule_unknown_integrity_level,
):
    with pytest.raises(
        SigmaTransformationError,
        match="Integrity Level needs to be one of Protected,System,High,Medium_Plus,Medium,Low,Untrusted",
    ):
        convert_falcon(process_creation_sigma_rule_unknown_integrity_level, resolver)


def test_crowdstrike_falcon_pipeline_parentimage_path(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_parentimage_path
):
    with pytest.raises(
        SigmaTransformationError,
        match="Only file name of parent image is available in CrowdStrike Query Language events.",
    ):
        convert_falcon(process_creation_sigma_rule_parentimage_path, resolver)


def test_crowdstrike_falcon_pipeline_replace_disk_name(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_fullimage_path
):
    assert (
        convert_falcon(process_creation_sigma_rule_fullimage_path, resolver)
        == "event_platform=/^Win$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) CommandLine=/^test\\.exe foo bar$/i ImageFileName=/^\\\\Device\\\\HarddiskVolume.\\\\Windows\\\\System32\\\\cmd\\.exe$/i"
    )


def test_crowdstrike_falcon_pipeline_replace_disk_name_colon(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_disk_name_colon
):
    assert (
        convert_falcon(process_creation_sigma_rule_disk_name_colon, resolver)
        == "event_platform=/^Win$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) CommandLine=/^test\\.exe foo bar$/i ImageFileName=/\\\\Windows\\\\System32\\\\cmd\\.exe$/i"
    )

def test_crowdstrike_falcon_pipeline_replace_disk_name_contains(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_disk_name_contains
):
    assert (
        convert_falcon(process_creation_sigma_rule_disk_name_contains, resolver)
        == "event_platform=/^Win$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) CommandLine=/^test\\.exe foo bar$/i ImageFileName=/\\\\Device\\\\HarddiskVolume.\\\\Windows\\\\System32\\\\cmd\\.exe/i"
    )

def test_crowdstrike_falcon_pipeline_replace_disk_name_startswith(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_disk_name_startswith
):
    assert (
        convert_falcon(process_creation_sigma_rule_disk_name_startswith, resolver)
        == "event_platform=/^Win$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) CommandLine=/^test\\.exe foo bar$/i ImageFileName=/^\\\\Device\\\\HarddiskVolume.\\\\Windows\\\\System32\\\\cmd\\.exe/i"
    )

def test_crowdstrike_falcon_pipeline_replace_disk_name_endswith(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_disk_name_endswith
):
    assert (
        convert_falcon(process_creation_sigma_rule_disk_name_endswith, resolver)
        == "event_platform=/^Win$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) CommandLine=/^test\\.exe foo bar$/i ImageFileName=/\\\\Device\\\\HarddiskVolume.\\\\Windows\\\\System32\\\\cmd\\.exe$/i"
    )

@pytest.mark.parametrize("field", unsupported_process_creation_fields)
def test_crowdstrike_falcon_pipeline_unsupported_field(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_unsupported_field
):
    with pytest.raises(
        SigmaTransformationError,
        match="Crowdstrike Query Language does not support the",
    ):
        convert_falcon(process_creation_sigma_rule_unsupported_field, resolver)


def test_crowdstrike_falcon_pipeline_network_connect(
    resolver: ProcessingPipelineResolver, network_connection_sigma_rule
):
    assert (
        convert_falcon(network_connection_sigma_rule, resolver)
        == "#event_simpleName=/^NetworkConnectIP4$/i RemoteAddressIP4=/^1\\.2\\.3\\.4$/i"
    )


def test_crowdstrike_falcon_pipeline_network_incoming_connect(
    resolver: ProcessingPipelineResolver, incoming_network_connection_sigma_rule
):
    assert (
        convert_falcon(incoming_network_connection_sigma_rule, resolver)
        == "#event_simpleName=/^NetworkReceiveAcceptIP4$/i RemoteAddressIP4=/^1\\.2\\.3\\.4$/i"
    )


def test_crowdstrike_falcon_pipeline_network_incoming_connect(
    resolver: ProcessingPipelineResolver, incoming_network_connection_sigma_rule
):
    assert (
        convert_falcon(incoming_network_connection_sigma_rule, resolver)
        == "#event_simpleName=/^NetworkReceiveAcceptIP4$/i RemoteAddressIP4=/^1\\.2\\.3\\.4$/i"
    )


def test_crowdstrike_falcon_pipeline_network_no_initiated(
    resolver: ProcessingPipelineResolver, network_connection_no_initiated_sigma_rule
):
    assert (
        convert_falcon(network_connection_no_initiated_sigma_rule, resolver)
        == "(#event_simpleName=/^NetworkConnectIP4$/i or #event_simpleName=/^NetworkReceiveAcceptIP4$/i) ContextBaseFileName=/\\$Recycle\\.Bin/i"
    )


def test_crowdstrike_falcon_dns_query(
    resolver: ProcessingPipelineResolver, dns_query_sigma_rule
):
    assert (
        convert_falcon(dns_query_sigma_rule, resolver)
        == "event_platform=/^Win$/i #event_simpleName=/^DnsRequest$/i DomainName=/^test\\.invalid$/i (RequestType=/^1$/i or RequestType=/^2$/i or RequestType=/^5$/i or RequestType=/^12$/i or RequestType=/^15$/i or RequestType=/^16$/i or RequestType=/^28$/i or RequestType=/^255$/i) (IP4Records=/1\\.1\\.1\\.1/i or IP6Records=/1\\.1\\.1\\.1/i) ContextBaseFileName=/^parent\\.exe$/i"
    )


def test_crowdstrike_falcon_dns_invalid_request_type(
    resolver: ProcessingPipelineResolver, dns_query_sigma_rule_invalid_request
):
    with pytest.raises(
        SigmaTransformationError,
        match="record_type needs to be one of A,NS,CNAME,PTR,MX,TXT,AAAA,ANY",
    ):
        convert_falcon(dns_query_sigma_rule_invalid_request, resolver)


def test_crowdstrike_falcon_dns_invalid_request_type(
    resolver: ProcessingPipelineResolver, dns_query_sigma_rule_full_image_path
):
    with pytest.raises(SigmaTransformationError, match="file name of image"):
        convert_falcon(dns_query_sigma_rule_full_image_path, resolver)


def test_crowdstrike_falcon_pipeline_driver_load_simple(
    resolver: ProcessingPipelineResolver, driver_load_sigma_rule_simple
):
    assert (
        convert_falcon(driver_load_sigma_rule_simple, resolver)
        == "event_platform=/^Win$/i #event_simpleName=/^DriverLoad$/i ImageFileName=/^imageloaded\\.exe$/i SHA256HashData=/^test$/i MD5HashData=/^test$/i"
    )


def test_crowdstrike_falcon_pipeline_driver_load_full_path(
    resolver: ProcessingPipelineResolver, driver_load_sigma_rule_driver_load_full_path
):
    assert (
        convert_falcon(driver_load_sigma_rule_driver_load_full_path, resolver)
        == "event_platform=/^Win$/i #event_simpleName=/^DriverLoad$/i ImageFileName=/^\\\\Device\\\\HarddiskVolume.\\\\Windows\\\\test\\.sys$/i SHA256HashData=/^test$/i MD5HashData=/^test$/i"
    )


def test_crowdstrike_falcon_pipeline_driver_load_image_full_path(
    resolver: ProcessingPipelineResolver, driver_load_sigma_rule_driver_load_full_path
):
    assert (
        convert_falcon(driver_load_sigma_rule_driver_load_full_path, resolver)
        == "event_platform=/^Win$/i #event_simpleName=/^DriverLoad$/i ImageFileName=/^\\\\Device\\\\HarddiskVolume.\\\\Windows\\\\test\\.sys$/i SHA256HashData=/^test$/i MD5HashData=/^test$/i"
    )


def test_crowdstrike_falcon_pipeline_image_load_full_path(
    resolver: ProcessingPipelineResolver, image_load_sigma_rule
):
    assert (
        convert_falcon(image_load_sigma_rule, resolver)
        == "event_platform=/^Win$/i #event_simpleName=/^ClassifiedModuleLoad$/i ImageFileName=/^\\\\Device\\\\HarddiskVolume.\\\\Windows\\\\test\\.sys$/i TargetImageFileName=/^\\\\Device\\\\HarddiskVolume.\\\\Windows\\\\test\\.exe$/i SHA256HashData=/^test$/i MD5HashData=/^test$/i"
    )


def test_crowdstrike_falcon_pipeline_ps_script(
    resolver: ProcessingPipelineResolver, ps_script_sigma_rule
):
    assert (
        convert_falcon(ps_script_sigma_rule, resolver)
        == "event_platform=/^Win$/i (#event_simpleName=/^CommandHistory$/i or #event_simpleName=/^ScriptControlScanTelemetry$/i) (CommandHistory=/test/i or ScriptContent=/test/i)"
    )


### FDR TESTS ###
def test_crowdstrike_fdr_pipeline_parentimage(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_parentimage
):
    pipeline = resolver.resolve_pipeline("crowdstrike_fdr")
    backend = TextQueryTestBackend(pipeline)
    assert (
        backend.convert(process_creation_sigma_rule_parentimage)
        == 'event_platform="Win" and (event_simpleName in ("ProcessRollup2", "SyntheticProcessRollup2")) and CommandLine="test.exe foo bar" and ParentBaseFileName="parent.exe"'
    )


def test_crowdstrike_fdr_pipeline_process_creation(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule
):
    pipeline = resolver.resolve_pipeline("crowdstrike_fdr")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(process_creation_sigma_rule) == [
        'event_platform="Win" and (event_simpleName in ("ProcessRollup2", "SyntheticProcessRollup2")) and CommandLine="test.exe foo bar" and ImageFileName endswith "\\test.exe"'
    ]


def test_crowdstrike_fdr_pipeline_parentimage(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_parentimage
):
    pipeline = resolver.resolve_pipeline("crowdstrike_fdr")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(process_creation_sigma_rule_parentimage) == [
        'event_platform="Win" and (event_simpleName in ("ProcessRollup2", "SyntheticProcessRollup2")) and CommandLine="test.exe foo bar" and ParentBaseFileName="parent.exe"'
    ]


def test_crowdstrike_fdr_pipeline_parentimage_without_slash(
    resolver: ProcessingPipelineResolver,
    process_creation_sigma_rule_parentimage_without_slash,
):
    pipeline = resolver.resolve_pipeline("crowdstrike_fdr")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(process_creation_sigma_rule_parentimage_without_slash) == [
        'event_platform="Win" and (event_simpleName in ("ProcessRollup2", "SyntheticProcessRollup2")) and CommandLine="test.exe foo bar" and ParentBaseFileName endswith "parent.exe"'
    ]


def test_crowdstrike_fdr_pipeline_parentimage_path(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_parentimage_path
):
    pipeline = resolver.resolve_pipeline("crowdstrike_fdr")
    backend = TextQueryTestBackend(pipeline)
    with pytest.raises(SigmaTransformationError, match="CrowdStrike"):
        backend.convert(process_creation_sigma_rule_parentimage_path)


def test_crowdstrike_fdr_network_connect(
    resolver: ProcessingPipelineResolver, network_connection_sigma_rule
):
    pipeline = resolver.resolve_pipeline("crowdstrike_fdr")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(network_connection_sigma_rule) == [
        'event_simpleName="NetworkConnectIP4" and RemoteAddressIP4="1.2.3.4"'
    ]


def test_crowdstrike_fdr_network_connect_incoming(
    resolver: ProcessingPipelineResolver, incoming_network_connection_sigma_rule
):
    pipeline = resolver.resolve_pipeline("crowdstrike_fdr")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(incoming_network_connection_sigma_rule) == [
        'event_simpleName="NetworkReceiveAcceptIP4" and RemoteAddressIP4="1.2.3.4"'
    ]


def test_crowdstrike_fdr_network_no_initiated(
    resolver: ProcessingPipelineResolver, network_connection_no_initiated_sigma_rule
):
    pipeline = resolver.resolve_pipeline("crowdstrike_fdr")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(network_connection_no_initiated_sigma_rule) == [
        '(event_simpleName in ("NetworkConnectIP4", "NetworkReceiveAcceptIP4")) and ContextBaseFileName contains "$Recycle.Bin"'
    ]


def test_crowdstrike_fdr_dns_query(
    resolver: ProcessingPipelineResolver, dns_query_sigma_rule
):
    pipeline = resolver.resolve_pipeline("crowdstrike_fdr")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(dns_query_sigma_rule) == [
        'event_platform="Win" and event_simpleName="DnsRequest" and DomainName="test.invalid" and (RequestType in ("1", "2", "5", "12", "15", "16", "28", "255")) and (IP4Records contains "1.1.1.1" or IP6Records contains "1.1.1.1") and ContextBaseFileName="parent.exe"'
    ]


### MACOS TESTS ###
def macos_rule(detection: str, category: str = "process_creation"):
    return SigmaCollection.from_yaml(
        f"""
        title: macOS Test
        status: test
        logsource:
            category: {category}
            product: macos
        detection:
            sel:
{detection}
            condition: sel
        """
    )


MACOS_PROCESS = """
                Image|endswith: /osascript
                CommandLine|contains: display dialog
"""


def test_crowdstrike_falcon_pipeline_macos_process_creation(resolver):
    assert (
        convert_falcon(macos_rule(MACOS_PROCESS), resolver)
        == "event_platform=/^Mac$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) ImageFileName=/\\/osascript$/i CommandLine=/display dialog/i"
    )


def test_crowdstrike_fdr_pipeline_macos_process_creation(resolver):
    backend = TextQueryTestBackend(resolver.resolve_pipeline("crowdstrike_fdr"))
    assert backend.convert(macos_rule(MACOS_PROCESS)) == [
        'event_platform="Mac" and (event_simpleName in ("ProcessRollup2", "SyntheticProcessRollup2")) and ImageFileName endswith "/osascript" and CommandLine contains "display dialog"'
    ]


@pytest.mark.parametrize(
    "parent, falcon_value",
    [
        ("ParentImage|endswith: /python3", "python3"),
        ("ParentImage: '*/python3'", "python3"),
        ("ParentImage|endswith: /Terminal", "Terminal"),
    ],
)
def test_crowdstrike_macos_parentimage_basename(resolver, parent, falcon_value):
    assert (
        convert_falcon(macos_rule(f"                {parent}"), resolver)
        == f"event_platform=/^Mac$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) ParentBaseFileName=/^{falcon_value}$/i"
    )
    backend = TextQueryTestBackend(resolver.resolve_pipeline("crowdstrike_fdr"))
    assert backend.convert(macos_rule(f"                {parent}")) == [
        f'event_platform="Mac" and (event_simpleName in ("ProcessRollup2", "SyntheticProcessRollup2")) and ParentBaseFileName="{falcon_value}"'
    ]


@pytest.mark.parametrize(
    "parent",
    [
        "ParentImage|contains: usr/bin",
        "ParentImage|contains: p*y",
        "ParentImage|contains: py?",
        "ParentImage|contains: '\\x'",
        "ParentImage|startswith: /usr/bin",
        "ParentImage|re: .*python3",
        "ParentImage|contains|all: [usr, python3]",
        "ParentImage: /usr/bin/",
        "ParentImage|endswith: /",
        "ParentImage: /usr/*",
        "ParentImage: '*'",
        "ParentImage: ''",
        "ParentImage: '*\\x.exe'",
        "ParentImage|endswith: '\\x.exe'",
        "ParentImage: python3",
        "ParentImage|endswith|cased: /XPC",
        "ParentImage|endswith: /py*",
        "ParentImage: '*/Users*'",
        "ParentImage|endswith: /p?thon3",
    ],
)
@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_parentimage_unsupported(resolver, pipeline, parent):
    backend = TextQueryTestBackend(resolver.resolve_pipeline(pipeline))
    with pytest.raises(SigmaTransformationError, match="ParentImage"):
        backend.convert(macos_rule(f"                {parent}"))


@pytest.mark.parametrize("field", unsupported_process_creation_fields)
@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_unsupported_field(resolver, pipeline, field):
    backend = TextQueryTestBackend(resolver.resolve_pipeline(pipeline))
    with pytest.raises(SigmaTransformationError, match="does not support the"):
        backend.convert(macos_rule(f"                {field}: test"))


@pytest.mark.parametrize("category", ["file_event", "network_connection", "dns_query"])
@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_unsupported_category(resolver, pipeline, category):
    backend = TextQueryTestBackend(resolver.resolve_pipeline(pipeline))
    with pytest.raises(
        SigmaTransformationError,
        match="Only the process_creation category is supported for macOS",
    ):
        backend.convert(macos_rule("                Image: test", category=category))


def test_crowdstrike_falcon_windows_parentimage_unchanged(
    resolver, process_creation_sigma_rule_parentimage
):
    assert (
        convert_falcon(process_creation_sigma_rule_parentimage, resolver)
        == "event_platform=/^Win$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) CommandLine=/^test\\.exe foo bar$/i ParentBaseFileName=/^parent\\.exe$/i"
    )


def test_crowdstrike_fdr_windows_parentimage_unchanged(
    resolver, process_creation_sigma_rule_parentimage
):
    backend = TextQueryTestBackend(resolver.resolve_pipeline("crowdstrike_fdr"))
    assert backend.convert(process_creation_sigma_rule_parentimage) == [
        'event_platform="Win" and (event_simpleName in ("ProcessRollup2", "SyntheticProcessRollup2")) and CommandLine="test.exe foo bar" and ParentBaseFileName="parent.exe"'
    ]


FALCON_MAC = "event_platform=/^Mac$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i)"
FDR_MAC = 'event_platform="Mac" and (event_simpleName in ("ProcessRollup2", "SyntheticProcessRollup2"))'


def convert_fdr(rule, resolver):
    backend = TextQueryTestBackend(resolver.resolve_pipeline("crowdstrike_fdr"))
    return backend.convert(rule)


@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
@pytest.mark.parametrize(
    "parent",
    [
        "ParentImage: /usr/libexec/xpcproxy",
        "ParentImage: /bin/py*",
        "ParentImage: /xpcproxy",
        "ParentImage|endswith: /usr/libexec/xpcproxy",
        "ParentImage: '*/libexec/xpcproxy'",
        "ParentImage|endswith: libexec/xpcproxy",
        "ParentImage|endswith: /usr/b?n/python3",
    ],
)
def test_crowdstrike_macos_parentimage_multi_component_rejected(
    resolver, pipeline, parent
):
    backend = TextQueryTestBackend(resolver.resolve_pipeline(pipeline))
    with pytest.raises(SigmaTransformationError, match="not supported on macOS"):
        backend.convert(macos_rule(f"                {parent}"))


def test_crowdstrike_macos_parentimage_negated_filter(resolver):
    def rule(parent):
        return SigmaCollection.from_yaml(
            f"""
            title: macOS Negated Filter
            status: test
            logsource:
                category: process_creation
                product: macos
            detection:
                sel:
                    Image|endswith: /sh
                filter:
                    {parent}
                condition: sel and not filter
            """
        )

    # Stripping the directory would also exclude /tmp/xpcproxy, so multi-component
    # values (exact or endswith) are rejected.
    for parent in (
        "ParentImage: /usr/libexec/xpcproxy",
        "ParentImage|endswith: /usr/libexec/xpcproxy",
    ):
        with pytest.raises(SigmaTransformationError, match="not supported on macOS"):
            convert_falcon(rule(parent), resolver)
        with pytest.raises(SigmaTransformationError, match="not supported on macOS"):
            convert_fdr(rule(parent), resolver)
    assert (
        convert_falcon(rule("ParentImage|endswith: /xpcproxy"), resolver)
        == FALCON_MAC + " ImageFileName=/\\/sh$/i not ParentBaseFileName=/^xpcproxy$/i"
    )
    assert convert_fdr(rule("ParentImage|endswith: /xpcproxy"), resolver) == [
        FDR_MAC
        + ' and ImageFileName endswith "/sh" and not ParentBaseFileName="xpcproxy"'
    ]


def test_crowdstrike_macos_parentimage_escaped_question_mark(resolver):
    # An escaped question mark is a literal character, not a wildcard.
    assert (
        convert_falcon(
            macos_rule("                ParentImage|endswith: /what\\?"), resolver
        )
        == FALCON_MAC + " ParentBaseFileName=/^what\\?$/i"
    )
    with pytest.raises(SigmaTransformationError, match="not supported on macOS"):
        convert_falcon(macos_rule("                ParentImage|endswith: /?"), resolver)


@pytest.mark.parametrize("exists", ["true", "false"])
@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_parentimage_exists_rejected(resolver, pipeline, exists):
    backend = TextQueryTestBackend(resolver.resolve_pipeline(pipeline))
    # Falcon: the exists guard; FDR: the ParentImage guard (only endswith, contains or null)
    with pytest.raises(SigmaTransformationError, match="ParentImage.*[Ee]xists"):
        backend.convert(macos_rule(f"                ParentImage|exists: {exists}"))


@pytest.mark.parametrize("value", ["0", "true", "1.5"])
@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_parentimage_non_string_rejected(resolver, pipeline, value):
    backend = TextQueryTestBackend(resolver.resolve_pipeline(pipeline))
    with pytest.raises(SigmaTransformationError, match="only string values"):
        backend.convert(macos_rule(f"                ParentImage: {value}"))


def test_crowdstrike_macos_parentimage_null(resolver):
    assert (
        convert_falcon(macos_rule("                ParentImage: null"), resolver)
        == FALCON_MAC + " ParentBaseFileName!=*"
    )


@pytest.mark.parametrize(
    "field",
    [
        "OriginalFileName",
        "IntegrityLevel",
        "Hashes",
        "ParentUser",
        "LogonId",
        "User",
        "ProcessId",
        "ParentProcessId",
        "Computer",
        "TerminalSessionId",
        "ProcessGuid",
    ],
)
@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_field_not_in_allow_list(resolver, pipeline, field):
    backend = TextQueryTestBackend(resolver.resolve_pipeline(pipeline))
    with pytest.raises(
        SigmaTransformationError, match="does not support the .* on macOS"
    ):
        backend.convert(macos_rule(f"                {field}: test"))


def test_crowdstrike_macos_sha256(resolver):
    rule = "                sha256: abc123"
    assert (
        convert_falcon(macos_rule(rule), resolver)
        == FALCON_MAC + " SHA256HashData=/^abc123$/i"
    )
    assert convert_fdr(macos_rule(rule), resolver) == [
        FDR_MAC + ' and SHA256HashData="abc123"'
    ]


def contains_rule(detections: str, condition: str):
    return SigmaCollection.from_yaml(
        f"""
        title: macOS Contains Test
        status: test
        logsource:
            category: process_creation
            product: macos
        detection:
{detections}
            condition: {condition}
        """
    )


CONTAINS_DETECTIONS = """
            sel:
                Image|endswith: /curl
            f_main:
                ParentImage|endswith: /Updater
            f_exc:
                ParentImage|contains: Terminal.app
"""


@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
@pytest.mark.parametrize(
    "condition",
    [
        "sel and not f_exc",
        "sel and not (f_main and not f_exc)",
        "sel and not (1 of f_*)",
        "sel and not (all of f_*)",
        "sel and not (not f_exc)",
    ],
)
def test_crowdstrike_macos_parentimage_contains_under_not_rejected(
    resolver, pipeline, condition
):
    backend = TextQueryTestBackend(resolver.resolve_pipeline(pipeline))
    with pytest.raises(SigmaTransformationError, match="under 'not'"):
        backend.convert(contains_rule(CONTAINS_DETECTIONS, condition))


def test_crowdstrike_macos_parentimage_contains_positive_with_other_not(resolver):
    # The contains detection is not referenced under a NOT, so it converts.
    assert (
        convert_falcon(
            contains_rule(CONTAINS_DETECTIONS, "sel and f_exc and not f_main"),
            resolver,
        )
        == FALCON_MAC
        + " ImageFileName=/\\/curl$/i ParentBaseFileName=/Terminal\\.app/i not ParentBaseFileName=/^Updater$/i"
    )


def test_crowdstrike_macos_image_colon_unchanged(resolver):
    rule = "                Image|endswith: /foo:bar"
    assert (
        convert_falcon(macos_rule(rule), resolver)
        == FALCON_MAC + " ImageFileName=/\\/foo:bar$/i"
    )
    assert convert_fdr(macos_rule(rule), resolver) == [
        FDR_MAC + ' and ImageFileName endswith "/foo\\:bar"'
    ]
    rule = "                Image|startswith: 'C:/x'"
    assert (
        convert_falcon(macos_rule(rule), resolver)
        == FALCON_MAC + " ImageFileName=/^C:\\/x/i"
    )


def test_crowdstrike_linux_process_creation_unchanged(resolver):
    # Pins the existing Linux output, which this change does not touch.
    def rule():
        return SigmaCollection.from_yaml(
            """
            title: Linux Test
            status: test
            logsource:
                category: process_creation
                product: linux
            detection:
                sel:
                    Image|endswith: /sh
                    ParentImage|endswith: /bin/sh
                condition: sel
            """
        )

    assert (
        convert_falcon(rule(), resolver)
        == "event_platform=/^Lin$/i (#event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i) ImageFileName=/\\/sh$/i ParentBaseFileName=/\\/bin\\/sh$/i"
    )
    assert convert_fdr(rule(), resolver) == [
        'event_platform="Lin" and ImageFileName endswith "/sh" and ParentBaseFileName endswith "/bin/sh"'
    ]


def test_crowdstrike_macos_parentimage_contains_literal(resolver):
    # A literal without '/' or wildcards matches the basename and can only narrow.
    rule = "                ParentImage|contains:\n                    - Microsoft Word\n                    - Google Chrome"
    assert (
        convert_falcon(macos_rule(rule), resolver)
        == FALCON_MAC
        + " (ParentBaseFileName=/Microsoft Word/i or ParentBaseFileName=/Google Chrome/i)"
    )
    assert convert_fdr(macos_rule(rule), resolver) == [
        FDR_MAC + ' and (ParentBaseFileName in ("*Microsoft Word*", "*Google Chrome*"))'
    ]


@pytest.mark.parametrize(
    "image",
    ["Image|endswith: '\\bash'", "Image|contains: '\\bash'", "Image: 'C:\\x'"],
)
@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_image_backslash_rejected(resolver, pipeline, image):
    backend = TextQueryTestBackend(resolver.resolve_pipeline(pipeline))
    with pytest.raises(SigmaTransformationError, match="Image value .* backslash"):
        backend.convert(macos_rule(f"                {image}"))


@pytest.mark.parametrize(
    "rule",
    ["Image|fieldref: ParentImage", "ParentImage|fieldref: Image"],
)
@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_parentimage_fieldref_rejected(resolver, pipeline, rule):
    backend = TextQueryTestBackend(resolver.resolve_pipeline(pipeline))
    with pytest.raises(SigmaTransformationError, match="Field references .*fieldref"):
        backend.convert(macos_rule(f"                {rule}"))


@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_parentimage_bare_endswith(resolver, pipeline):
    # On a path this means "file name ends with opencode": neither wider nor narrower.
    rule = "                ParentImage|endswith: opencode"
    if pipeline == "crowdstrike_falcon":
        assert (
            convert_falcon(macos_rule(rule), resolver)
            == FALCON_MAC + " ParentBaseFileName=/opencode$/i"
        )
    else:
        assert convert_fdr(macos_rule(rule), resolver) == [
            FDR_MAC + ' and ParentBaseFileName endswith "opencode"'
        ]


MULTI_DETECTIONS = """
            sel:
                Image|endswith: /curl
            multi_value:
                ParentImage|contains:
                    - Terminal.app
                    - iTerm.app
            multi_field:
                ParentImage|contains: Updater
                Image|endswith: /sh
"""


@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
@pytest.mark.parametrize(
    "condition",
    [
        "sel and not multi_value",
        "sel and not multi_field",
        "sel and not (1 of multi_*)",
        "sel and not (multi_value and not multi_field)",
    ],
)
def test_crowdstrike_macos_parentimage_contains_multi_under_not_rejected(
    resolver, pipeline, condition
):
    backend = TextQueryTestBackend(resolver.resolve_pipeline(pipeline))
    with pytest.raises(SigmaTransformationError, match="under 'not'"):
        backend.convert(contains_rule(MULTI_DETECTIONS, condition))


def test_crowdstrike_macos_parentimage_contains_multi_positive(resolver):
    assert (
        convert_falcon(contains_rule(MULTI_DETECTIONS, "sel and multi_value"), resolver)
        == FALCON_MAC
        + " ImageFileName=/\\/curl$/i (ParentBaseFileName=/Terminal\\.app/i or ParentBaseFileName=/iTerm\\.app/i)"
    )


@pytest.mark.parametrize("field", ["Image", "CommandLine", "ParentImage", "sha256"])
def test_crowdstrike_macos_exists_rejected_on_every_field_falcon(resolver, field):
    backend = TextQueryTestBackend(resolver.resolve_pipeline("crowdstrike_falcon"))
    with pytest.raises(SigmaTransformationError, match="exists is not supported"):
        backend.convert(macos_rule(f"                {field}|exists: true"))


@pytest.mark.parametrize(
    "field,mapped",
    [("Image", "ImageFileName"), ("CommandLine", "CommandLine"), ("sha256", "SHA256HashData")],
)
def test_crowdstrike_macos_exists_converts_on_fdr(resolver, field, mapped):
    # The FDR pipeline is also used with backends that can express exists (Splunk and others).
    backend = TextQueryTestBackend(resolver.resolve_pipeline("crowdstrike_fdr"))
    assert f"exists({mapped})" in backend.convert(macos_rule(f"                {field}|exists: true"))[0]


@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_keyword_detection_rejected(resolver, pipeline):
    backend = TextQueryTestBackend(resolver.resolve_pipeline(pipeline))
    with pytest.raises(
        SigmaTransformationError, match="Keyword search isn't supported"
    ):
        backend.convert(
            SigmaCollection.from_yaml(
                """
                title: macOS Keyword
                status: test
                logsource:
                    category: process_creation
                    product: macos
                detection:
                    keywords:
                        - osascript
                    condition: keywords
                """
            )
        )


def test_crowdstrike_macos_companion_pipeline_conditions_not_rejected(resolver):
    # Host-scoping conditions added by another pipeline are not rule-authored.
    companion = ProcessingPipeline(
        name="companion",
        priority=5,
        items=[
            ProcessingItem(
                identifier="companion_host",
                transformation=AddConditionTransformation(
                    {"aid": "abc123", "ComputerName": "host1"}
                ),
            )
        ],
    )
    backend = LogScaleBackend(
        companion + resolver.resolve_pipeline("crowdstrike_falcon")
    )
    assert (
        backend.convert(macos_rule(MACOS_PROCESS))
        == FALCON_MAC
        + " aid=/^abc123$/i ComputerName=/^host1$/i ImageFileName=/\\/osascript$/i CommandLine=/display dialog/i"
    )
    with pytest.raises(
        SigmaTransformationError, match="does not support the User field"
    ):
        LogScaleBackend(
            companion + resolver.resolve_pipeline("crowdstrike_falcon")
        ).convert(macos_rule("                User: root"))


def noop_pipeline():
    return ProcessingPipeline(name="noop", priority=1, items=[])


def noop_marker_pipeline():
    # Touches every detection item, as a field-mapping pipeline would.
    return ProcessingPipeline(
        name="noop_marker",
        priority=1,
        items=[
            ProcessingItem(
                identifier="noop_marker",
                transformation=FieldMappingTransformation({"NoSuchField": "Other"}),
            )
        ],
    )


@pytest.mark.parametrize("first", [None, noop_pipeline, noop_marker_pipeline])
@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_guards_with_earlier_pipeline(resolver, pipeline, first):
    def backend():
        p = resolver.resolve_pipeline(pipeline)
        return TextQueryTestBackend(first() + p if first else p)

    # A rule-written ParentBaseFileName is the renamed field of an earlier pipeline.
    with pytest.raises(SigmaTransformationError, match="under 'not'"):
        backend().convert(
            contains_rule(
                """
            sel:
                Image|endswith: /curl
            filt:
                ParentBaseFileName|contains: Terminal.app
""",
                "sel and not filt",
            )
        )
    for field in ("User|contains: root", "User: root"):
        with pytest.raises(
            SigmaTransformationError, match="does not support the User field"
        ):
            backend().convert(macos_rule(f"                {field}"))
    # Companion host-scoping conditions still pass.
    companion = ProcessingPipeline(
        name="companion",
        priority=5,
        items=[
            ProcessingItem(
                identifier="companion_host",
                transformation=AddConditionTransformation({"aid": "abc123"}),
            )
        ],
    )
    p = resolver.resolve_pipeline(pipeline)
    stacked = (first() + companion + p) if first else (companion + p)
    assert "aid" in str(
        TextQueryTestBackend(stacked).convert(macos_rule(MACOS_PROCESS))
    )


@pytest.mark.parametrize("first", [None, noop_pipeline, noop_marker_pipeline])
@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
@pytest.mark.parametrize(
    "detection, message",
    [
        ("_cond_x:\n                User: root", "does not support the User field"),
        ("_cond_x:\n                - evil", "Keyword search isn't supported"),
    ],
)
def test_crowdstrike_macos_rule_written_cond_detection_rejected(
    resolver, pipeline, first, detection, message
):
    p = resolver.resolve_pipeline(pipeline)
    backend = TextQueryTestBackend(first() + p if first else p)
    rule = SigmaCollection.from_yaml(
        f"""
        title: macOS Cond Name
        status: test
        logsource:
            category: process_creation
            product: macos
        detection:
            sel:
                Image|endswith: /sh
            {detection}
            condition: sel and _cond_x
        """
    )
    with pytest.raises(SigmaTransformationError, match=message):
        backend.convert(rule)


def macos_correlation(group_by="[Image]", condition="gte: 2", corr_type="event_count"):
    return SigmaCollection.from_yaml(
        f"""
title: macOS Base
name: mac_base
status: test
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: /sh
    condition: selection
---
title: macOS Correlation
name: mac_corr
status: test
correlation:
    type: {corr_type}
    rules:
        - mac_base
    group-by: {group_by}
    timespan: 5m
    condition:
        {condition}
"""
    )


@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
@pytest.mark.parametrize(
    "kwargs",
    [
        {"group_by": "[User]"},
        {"group_by": "[Image, ProcessId]"},
        {"corr_type": "value_count", "condition": "gte: 2\n        field: User"},
    ],
)
def test_crowdstrike_macos_correlation_field_not_in_allow_list(
    resolver, pipeline, kwargs
):
    backend = LogScaleBackend(resolver.resolve_pipeline(pipeline))
    with pytest.raises(
        SigmaTransformationError, match="does not support the .* field on macOS"
    ):
        backend.convert(macos_correlation(**kwargs))


@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_correlation_allowed_fields(resolver, pipeline):
    backend = LogScaleBackend(resolver.resolve_pipeline(pipeline))
    result = backend.convert(
        macos_correlation(
            group_by="[Image]",
            corr_type="value_count",
            condition="gte: 2\n        field: CommandLine",
        )
    )
    text = result if isinstance(result, str) else result[0]
    assert text.endswith(
        "| bucket(span=5m, limit=max, field=[ImageFileName], function=count(field=CommandLine, distinct=true, as=value_count))\n| test(value_count >= 2)"
    )


def test_crowdstrike_macos_correlation_without_rules_does_not_crash(resolver):
    backend = LogScaleBackend(resolver.resolve_pipeline("crowdstrike_falcon"))
    with pytest.raises(SigmaError):
        backend.convert(
            SigmaCollection.from_yaml(
                """
title: Corr without rules
name: corr_no_rules
status: test
correlation:
    type: event_count
    group-by: [User]
    timespan: 5m
    condition:
        gte: 2
"""
            )
        )


def alias_correlation(first_product: str, second_product: str, aliases: bool = True):
    alias_block = (
        """
    aliases:
        proc:
            base_a: Image
            base_b: Image"""
        if aliases
        else ""
    )
    group_by = "proc" if aliases else "Image"
    return SigmaCollection.from_yaml(
        f"""
title: Base A
name: base_a
status: test
logsource:
    category: process_creation
    product: {first_product}
detection:
    selection:
        Image|endswith: /sh
    condition: selection
---
title: Base B
name: base_b
status: test
logsource:
    category: process_creation
    product: {second_product}
detection:
    selection:
        Image|endswith: /sh
    condition: selection
---
title: Alias Correlation
name: alias_corr
status: test
correlation:
    type: event_count
    rules:
        - base_a
        - base_b
    group-by:
        - {group_by}{alias_block}
    timespan: 5m
    condition:
        gte: 2
"""
    )


CHAINED_CORRELATION = """
title: Base
name: chain_base
status: test
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: /sh
    condition: selection
---
title: Inner
name: chain_inner
status: test
correlation:
    type: event_count
    rules:
        - chain_base
    group-by:
        - Image
    timespan: 5m
    condition:
        gte: 2
---
title: Outer
name: chain_outer
status: test
correlation:
    type: temporal
    rules:
        - chain_inner
    group-by:
        - Image
{outer_aliases}
    timespan: 5m
"""


ALIAS_ERROR = (
    "aliases are not supported for macOS correlations; group by a supported field name"
)


@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_correlation_aliases_rejected(resolver, pipeline):
    def backend():
        return LogScaleBackend(resolver.resolve_pipeline(pipeline))

    # Directly over macOS rules, and mixed with a Windows rule.
    for products in (("macos", "macos"), ("macos", "windows"), ("windows", "macos")):
        with pytest.raises(SigmaTransformationError, match=ALIAS_ERROR):
            backend().convert(alias_correlation(*products))
    # Through a chained correlation: aliases on the outer correlation.
    chained = CHAINED_CORRELATION.format(
        outer_aliases="    aliases:\n        proc:\n            chain_inner: Image"
    )
    with pytest.raises(SigmaTransformationError, match=ALIAS_ERROR):
        backend().convert(SigmaCollection.from_yaml(chained))


@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_macos_correlation_without_aliases_converts(resolver, pipeline):
    backend = LogScaleBackend(resolver.resolve_pipeline(pipeline))
    assert "ImageFileName" in str(
        backend.convert(alias_correlation("macos", "macos", aliases=False))
    )


@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
def test_crowdstrike_windows_correlation_with_aliases_unchanged(resolver, pipeline):
    backend = LogScaleBackend(resolver.resolve_pipeline(pipeline))
    result = str(backend.convert(alias_correlation("windows", "windows")))
    assert "event_platform=/^Win$/i" in result and "proc := ImageFileName" in result


INNER_ALIAS_CHAIN = CHAINED_CORRELATION.replace(
    """    group-by:
        - Image
    timespan: 5m
    condition:
        gte: 2
---
title: Outer""",
    """    group-by:
        - proc
    aliases:
        proc:
            chain_base: Image
    timespan: 5m
    condition:
        gte: 2
---
title: Outer""",
)

BY_ID_CORRELATION = """
title: Base
id: 3c6d4c5e-1b2a-4f6e-9a47-0a1b2c3d4e5f
status: test
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: /sh
    condition: selection
---
title: By Id
name: by_id_corr
status: test
correlation:
    type: event_count
    rules:
        - 3c6d4c5e-1b2a-4f6e-9a47-0a1b2c3d4e5f
    group-by:
        - proc
    aliases:
        proc:
            3c6d4c5e-1b2a-4f6e-9a47-0a1b2c3d4e5f: Image
    timespan: 5m
    condition:
        gte: 2
"""


@pytest.mark.parametrize("pipeline", ["crowdstrike_falcon", "crowdstrike_fdr"])
@pytest.mark.parametrize(
    "document",
    [INNER_ALIAS_CHAIN.format(outer_aliases=""), BY_ID_CORRELATION],
    ids=["inner_only_aliases_in_chain", "aliases_with_rule_ids"],
)
def test_crowdstrike_macos_correlation_aliases_rejected_more_cases(
    resolver, pipeline, document
):
    backend = LogScaleBackend(resolver.resolve_pipeline(pipeline))
    with pytest.raises(SigmaTransformationError, match=ALIAS_ERROR):
        backend.convert(SigmaCollection.from_yaml(document))
