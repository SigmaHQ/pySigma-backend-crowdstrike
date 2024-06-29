from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.backends.test import TextQueryTestBackend
from sigma.processing.resolver import ProcessingPipelineResolver
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
        == "event_platform=/^Win$/i #event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i CommandLine=/^test\\.exe foo bar$/i ImageFileName=/\\\\test\\.exe$/i"
    )


def test_crowdstrike_falcon_pipeline_parentimage(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_parentimage
):
    assert (
        convert_falcon(process_creation_sigma_rule_parentimage, resolver)
        == "event_platform=/^Win$/i #event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i CommandLine=/^test\\.exe foo bar$/i ParentBaseFileName=/^parent\\.exe$/i"
    )


def test_crowdstrike_falcon_pipeline_process_creation_all_fields(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_all_fields
):
    assert (
        convert_falcon(process_creation_sigma_rule_all_fields, resolver)
        == "event_platform=/^Win$/i #event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i ImageFileName=/^test$/i UserName=/^test$/i RawProcessId=/^test$/i SHA256HashData=/^test$/i ComputerName=/^test$/i"
    )


def test_crowdstrike_falcon_pipeline_process_creation_all_fields_nix(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_all_fields_nix
):
    assert (
        convert_falcon(process_creation_sigma_rule_all_fields_nix, resolver)
        == "event_platform=/^Lin$/i #event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i ImageFileName=/^test$/i UserName=/^test$/i RawProcessId=/^test$/i SHA256HashData=/^test$/i ComputerName=/^test$/i"
    )


def test_crowdstrike_falcon_pipeline_integrity_level(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_integrity_level
):
    assert (
        convert_falcon(process_creation_sigma_rule_integrity_level, resolver)
        == "event_platform=/^Win$/i #event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i IntegrityLevel=/^16384$/i"
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
        == "event_platform=/^Win$/i #event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i CommandLine=/^test\\.exe foo bar$/i ImageFileName=/^\\\\Device\\\\HarddiskVolume.\\\\Windows\\\\System32\\\\cmd\\.exe$/i"
    )


def test_crowdstrike_falcon_pipeline_replace_disk_name_colon(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_disk_name_colon
):
    assert (
        convert_falcon(process_creation_sigma_rule_disk_name_colon, resolver)
        == "event_platform=/^Win$/i #event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i CommandLine=/^test\\.exe foo bar$/i ImageFileName=/\\\\Windows\\\\System32\\\\cmd\\.exe$/i"
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


def test_crowdstrike_falcon_dns_query(
    resolver: ProcessingPipelineResolver, dns_query_sigma_rule
):
    assert (
        convert_falcon(dns_query_sigma_rule, resolver)
        == "event_platform=/^Win$/i #event_simpleName=/^DnsRequest$/i DomainName=/^test\\.invalid$/i RequestType=/^1$/i or RequestType=/^2$/i or RequestType=/^5$/i or RequestType=/^12$/i or RequestType=/^15$/i or RequestType=/^16$/i or RequestType=/^28$/i or RequestType=/^255$/i IP4Records=/1\\.1\\.1\\.1/i or IP6Records=/1\\.1\\.1\\.1/i ContextBaseFileName=/^parent\\.exe$/i"
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
        == "event_platform=/^Win$/i #event_simpleName=/^CommandHistory$/i or #event_simpleName=/^ScriptControlScanTelemetry$/i CommandHistory=/test/i or ScriptContent=/test/i"
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


def test_crowdstrike_fdr_dns_query(
    resolver: ProcessingPipelineResolver, dns_query_sigma_rule
):
    pipeline = resolver.resolve_pipeline("crowdstrike_fdr")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(dns_query_sigma_rule) == [
        'event_platform="Win" and event_simpleName="DnsRequest" and DomainName="test.invalid" and (RequestType in ("1", "2", "5", "12", "15", "16", "28", "255")) and (IP4Records contains "1.1.1.1" or IP6Records contains "1.1.1.1") and ContextBaseFileName="parent.exe"'
    ]
