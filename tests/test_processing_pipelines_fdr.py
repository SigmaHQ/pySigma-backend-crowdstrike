from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.backends.test import TextQueryTestBackend
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.pipelines.crowdstrike import crowdstrike_fdr_pipeline
import pytest


@pytest.fixture
def resolver():
    return ProcessingPipelineResolver(
        {
            "crowdstrike": crowdstrike_fdr_pipeline,
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
            condition: sel
    """
    )


def test_crowdstrike_pipeline(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule
):
    pipeline = resolver.resolve_pipeline("crowdstrike")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(process_creation_sigma_rule) == [
        '(event_simpleName in ("ProcessRollup2", "SyntheticProcessRollup2")) and CommandLine="test.exe foo bar" and ImageFileName endswith "\\test.exe"'
    ]


def test_crowdstrike_pipeline_parentimage(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_parentimage
):
    pipeline = resolver.resolve_pipeline("crowdstrike")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(process_creation_sigma_rule_parentimage) == [
        '(event_simpleName in ("ProcessRollup2", "SyntheticProcessRollup2")) and CommandLine="test.exe foo bar" and ParentBaseFileName="parent.exe"'
    ]


def test_crowdstrike_pipeline_parentimage_without_slash(
    resolver: ProcessingPipelineResolver,
    process_creation_sigma_rule_parentimage_without_slash,
):
    pipeline = resolver.resolve_pipeline("crowdstrike")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(process_creation_sigma_rule_parentimage_without_slash) == [
        '(event_simpleName in ("ProcessRollup2", "SyntheticProcessRollup2")) and CommandLine="test.exe foo bar" and ParentBaseFileName endswith "parent.exe"'
    ]


def test_crowdstrike_pipeline_parentimage_path(
    resolver: ProcessingPipelineResolver, process_creation_sigma_rule_parentimage_path
):
    pipeline = resolver.resolve_pipeline("crowdstrike")
    backend = TextQueryTestBackend(pipeline)
    with pytest.raises(SigmaTransformationError, match="CrowdStrike"):
        backend.convert(process_creation_sigma_rule_parentimage_path)


def test_crowdstrike_network_connect(
    resolver: ProcessingPipelineResolver, network_connection_sigma_rule
):
    pipeline = resolver.resolve_pipeline("crowdstrike")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(network_connection_sigma_rule) == [
        'event_simpleName="NetworkConnectionIP4" and RemoteAddressIP4="1.2.3.4"'
    ]


def test_crowdstrike_network_connect_incoming(
    resolver: ProcessingPipelineResolver, incoming_network_connection_sigma_rule
):
    pipeline = resolver.resolve_pipeline("crowdstrike")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(incoming_network_connection_sigma_rule) == [
        'event_simpleName="NetworkReceiveAcceptIP4" and RemoteAddressIP4="1.2.3.4"'
    ]


def test_crowdstrike_dns_query(
    resolver: ProcessingPipelineResolver, dns_query_sigma_rule
):
    pipeline = resolver.resolve_pipeline("crowdstrike")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(dns_query_sigma_rule) == [
        'event_simpleName="DnsRequest" and DomainName="test.invalid"'
    ]
