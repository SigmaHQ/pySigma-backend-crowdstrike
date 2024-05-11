import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.backends.crowdstrike import LogScaleBackend
from sigma.pipelines.crowdstrike import crowdstrike_falcon_pipeline

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
    "ParentProcessId"
]


### Process Creation ###
def test_cql_process_creation_event_simple():
    assert (
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
            SigmaCollection.from_yaml(
            f"""
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
        )
    ) == 'event_platform=/^Win$/i #event_simpleName=/^ProcessRollup2$/i ImageFileName=/^test$/i UserName=/^test$/i RawProcessId=/^test$/i SHA256HashData=/^test$/i ComputerName=/^test$/i'

def test_cql_parent_image_not_full_path():
    assert (
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
           SigmaCollection.from_yaml(
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
            """)
        )
    ) == 'event_platform=/^Win$/i #event_simpleName=/^ProcessRollup2$/i CommandLine=/^test\\.exe foo bar$/i ParentBaseFileName=/^parent\\.exe$/i'

def test_cql_process_creation_integrity_level():
    assert (
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
           SigmaCollection.from_yaml(
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
            """)
        )
    ) == 'event_platform=/^Win$/i #event_simpleName=/^ProcessRollup2$/i IntegrityLevel=/^16384$/i'

def test_cql_process_creation_unknown_integrity_level():
    with pytest.raises(SigmaTransformationError,match="Integrity Level needs to be one of Protected,System,High,Medium_Plus,Medium,Low,Untrusted"):
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
           SigmaCollection.from_yaml(
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
            """)
        )

def test_cql_parent_image_full_path():
    with pytest.raises(SigmaTransformationError, match="Only file name of parent image is available in CrowdStrike Query Language events."):
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
           SigmaCollection.from_yaml("""
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
            """)
        )

def test_cql_image_replace_disk_name():
      assert (
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
           SigmaCollection.from_yaml(
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
            """)
        )
    ) == 'event_platform=/^Win$/i #event_simpleName=/^ProcessRollup2$/i CommandLine=/^test\\.exe foo bar$/i ImageFileName=/^\\\\Device\\\\HarddiskVolume.\\\\Windows\\\\System32\\\\cmd\\.exe$/i'

def test_cql_image_replace_disk_name_colon():
      assert (
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
           SigmaCollection.from_yaml(
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
            """)
        )
    ) == 'event_platform=/^Win$/i #event_simpleName=/^ProcessRollup2$/i CommandLine=/^test\\.exe foo bar$/i ImageFileName=/\\\\Windows\\\\System32\\\\cmd\\.exe$/i'

@pytest.mark.parametrize("field",unsupported_process_creation_fields)
def test_cql_process_start_unsupported_field(field):
    with pytest.raises(SigmaTransformationError, match=field):
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
            SigmaCollection.from_yaml(
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
        )

### Network Connect ### 
def test_cql_network_connect():
    assert (
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
            SigmaCollection.from_yaml(
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
                """)
            )
        ) == '#event_simpleName=/^NetworkConnectIP4$/i RemoteAddressIP4=/^1\\.2\\.3\\.4$/i'
    
def test_cql_network_incoming_connect():
    assert (
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
            SigmaCollection.from_yaml(
                """
                title: Network Connection Test
                status: test
                logsource:
                    category: network_connection
                    product: windows
                detection:
                    sel:
                        Initiated: "false"
                        DestinationIp: "1.2.3.4"
                    condition: sel
                """)
            )
        ) == '#event_simpleName=/^NetworkReceiveAcceptIP4$/i RemoteAddressIP4=/^1\\.2\\.3\\.4$/i'

def  test_cql_dns_query_simple():
    assert (
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
            SigmaCollection.from_yaml(
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
                condition: sel
            """
            )
         
        )
    ) == '#event_simpleName=/^DnsRequest$/i event_platform=/^Win$/i DomainName=/^test\\.invalid$/i RequestType=/^1$/i or RequestType=/^2$/i or RequestType=/^5$/i or RequestType=/^12$/i or RequestType=/^15$/i or RequestType=/^16$/i or RequestType=/^28$/i or RequestType=/^255$/i IP4Records=/1\\.1\\.1\\.1/i or IP6Records=/1\\.1\\.1\\.1/i'

def  test_cql_dns_query_invalid_request_type():
    with pytest.raises(SigmaTransformationError, match="Integrity Level needs to be one of A,NS,CNAME,PTR,MX,TXT,AAAA,ANY"):
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
            SigmaCollection.from_yaml(
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
        )

def test_cql_contextbasefilename_full_path():
    with pytest.raises(SigmaTransformationError, match="file name of image"):
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
            SigmaCollection.from_yaml(
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
         
        )

def test_cql_contextbasefilename_not_full_path():
     assert (
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
           SigmaCollection.from_yaml(
            """
            title: DNS Query Test
            status: test
            logsource:
                category: dns_query
                product: windows
            detection:
                sel:
                    Image: "*\\\\parent.exe"
                condition: sel
            """)
        )
    ) == '#event_simpleName=/^DnsRequest$/i event_platform=/^Win$/i ContextBaseFileName=/^parent\\.exe$/i'
     
def test_cql_driver_load_simple():
         assert (
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
           SigmaCollection.from_yaml(
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
            """)
        )
    ) == '#event_simpleName=/^DriverLoad$/i event_platform=/^Win$/i ImageFileName=/^imageloaded\\.exe$/i SHA256HashData=/^test$/i MD5HashData=/^test$/i'
         
def test_cql_driver_load_full_path():
    assert (
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
           SigmaCollection.from_yaml(
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
            """)
        )
    ) == '#event_simpleName=/^DriverLoad$/i event_platform=/^Win$/i ImageFileName=/^\\\\Device\\\\HarddiskVolume.\\\\Windows\\\\test\\.sys$/i SHA256HashData=/^test$/i MD5HashData=/^test$/i'
         
def test_cql_image_load_full_path():
    assert (
        LogScaleBackend(processing_pipeline=crowdstrike_falcon_pipeline()).convert(
           SigmaCollection.from_yaml(
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
            """)
        )
    ) == '#event_simpleName=/^ClassifiedModuleLoad$/i event_platform=/^Win$/i ImageFileName=/^\\\\Device\\\\HarddiskVolume.\\\\Windows\\\\test\\.sys$/i TargetImageFileName=/^\\\\Device\\\\HarddiskVolume.\\\\Windows\\\\test\\.exe$/i SHA256HashData=/^test$/i MD5HashData=/^test$/i'