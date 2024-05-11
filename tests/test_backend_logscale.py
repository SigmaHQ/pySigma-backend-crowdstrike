import pytest
from sigma.collection import SigmaCollection
from sigma.backends.crowdstrike import LogScaleBackend
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

@pytest.fixture
def logscale_backend():
    return LogScaleBackend()

def test_crowdstrikelogscale_and_expression(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ['fieldA=/^valueA$/i fieldB=/^valueB$/i']


def test_crowdstrikelogscale_special_chars(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA*$^.|?()[]+
                condition: sel
        """)
    ) == ['fieldA=/^valueA.*\\$\\^\\.\\|.\\(\\)\\[\\]\\+$/i']

def test_crowdstrikelogscale_escaped_wildcards(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA\\?
                    fieldB: valueB\\*
                condition: sel
        """)
    ) == ['fieldA=/^valueA\\?$/i fieldB=/^valueB\\*$/i']

def test_crowdstrikelogscale_and_expression_startswith(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: valueA
                    fieldB|endswith: valueB
                    fieldC|contains: valueC
                    fieldD: valueD
                condition: sel
        """)
    ) == ['fieldA=/^valueA/i fieldB=/valueB$/i fieldC=/valueC/i fieldD=/^valueD$/i']

def test_crowdstrikelogscale_or_expression(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ['fieldA=/^valueA$/i or fieldB=/^valueB$/i']

def test_crowdstrikelogscale_and_or_expression(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['fieldA=/^valueA1$/i or fieldA=/^valueA2$/i fieldB=/^valueB1$/i or fieldB=/^valueB2$/i']

def test_crowdstrikelogscale_or_and_expression(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ['(fieldA=/^valueA1$/i fieldB=/^valueB1$/i) or (fieldA=/^valueA2$/i fieldB=/^valueB2$/i)']

def test_crowdstrikelogscale_or_and_expression_with_dots(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1.exe
                    fieldB: valueB1.exe
                sel2:
                    fieldA: valueA2.exe
                    fieldB: valueB2.exe
                condition: 1 of sel*
        """)
    ) == ['(fieldA=/^valueA1\\.exe$/i fieldB=/^valueB1\\.exe$/i) or (fieldA=/^valueA2\\.exe$/i fieldB=/^valueB2\\.exe$/i)']


def test_crowdstrikelogscale_and_wildcard(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - value*A
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['fieldA=/^value.*A$/i or fieldA=/^valueB$/i or fieldA=/^valueC/i']

def test_crowdstrikelogscale_expression_with_dots(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA.exe
                        - valueB.exe
                        - valueC*.exe
                condition: sel
        """)
    ) == ['fieldA=/^valueA\\.exe$/i or fieldA=/^valueB\\.exe$/i or fieldA=/^valueC.*\\.exe$/i']

def test_crowdstrikelogscale_expression_with_or(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA:
                        - valueA1
                        - valueA2
                sel2:
                    fieldB: 
                        - valueB1
                        - valueB2 
                condition: 1 of sel*
        """)
    ) == ['fieldA=/^valueA1$/i or fieldA=/^valueA2$/i or fieldB=/^valueB1$/i or fieldB=/^valueB2$/i']

def test_crowdstrikelogscale_regex_query(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ['fieldA=/foo.*bar/ fieldB=/^foo$/i']

def test_crowdstrikelogscale_regex_query_special_characters(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar\\d
                    fieldB: foo
                condition: sel
        """)
    ) == ['fieldA=/foo.*bar\\d/ fieldB=/^foo$/i']

def test_crowdstrikelogscale_cidr_or(logscale_backend: LogScaleBackend):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="ORing"):
        logscale_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|cidr:
                            - 192.168.0.0/16
                            - 10.0.0.0/8
                        fieldB: foo
                        fieldC: bar
                    condition: sel
            """
            )
        )

def test_crowdstrikelogscale_cidr_query(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['| cidr(fieldA, subnet=192.168.0.0/16)']

def test_crowdstrikelogscale_field_name_with_whitespace(logscale_backend : LogScaleBackend):
    assert logscale_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == ['"field name"=/^value$/i']




