import pytest
from unittest.mock import patch, MagicMock

#import contextlib
import time, copy, json, jwt
from api import app

from tests.pytest.util.config_handler import load_config

from api.util.issuer_handler import extract_access_token
from api.util.issuer_handler import get_samedevice_redirect_url
from api.util.issuer_handler import decode_token_with_jwk

from api.exceptions.issuer_exception import IssuerException

# Get AS config
as_config = load_config("tests/config/as.yml", app)
app.config['as'] = as_config

# Dummy access token
ACCESS_TOKEN = 'gfgarhgrfha'

# JWKS endpoint
verifier_uri = as_config['issuer']['verifierUri']
jwks_path = as_config['issuer']['jwksPath']
JWKS_ENDPOINT = "{}{}".format(verifier_uri, jwks_path)

# Response from JWKS endpoint
JWKS_RESPONSE = {
    "keys": [
        {
            "crv": "P-256",
            "kid": "HiS0NXOmYke6dTM7wZGrSwCE_VM0ntqIBMCpFFgEaOU",
            "kty": "EC",
            "x": "INKfEjYEr7Y2fIOKC30LseENEDLZxf9ZzKtdnz4wXi8",
            "y": "aYFyPJhJpwM99SMeYBNJJadJh1RcYbIIaj12x-Jcj8U"
        }
    ]}

# VP token
VC_TOKEN = "eyJhbGciOiJFUzI1NiIsImtpZCI6IkhpUzBOWE9tWWtlNmRUTTd3WkdyU3dDRV9WTTBudHFJQk1DcEZGZ0VhT1UiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsidmVyaWZpZXItcGRjLmRzYmEuZml3YXJlLmRldiJdLCJjbGllbnRfaWQiOiJkaWQ6d2ViOnBhY2tldGRlbGl2ZXJ5LmRzYmEuZml3YXJlLmRldjpkaWQiLCJleHAiOjE2ODczNDY5OTUsImlzcyI6ImRpZDp3ZWI6cGFja2V0ZGVsaXZlcnkuZHNiYS5maXdhcmUuZGV2OmRpZCIsImtpZCI6IkhpUzBOWE9tWWtlNmRUTTd3WkdyU3dDRV9WTTBudHFJQk1DcEZGZ0VhT1UiLCJzdWIiOiJkaWQ6ZXhhbXBsZTpob2xkZXIiLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdzNpZC5vcmcvc2VjdXJpdHkvc3VpdGVzL2p3cy0yMDIwL3YxIl0sImNyZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vRklXQVJFLU9wcy9pNHRydXN0LXByb3ZpZGVyL21haW4vZG9jcy9zY2hlbWEuanNvbiIsInR5cGUiOiJGdWxsSnNvblNjaGVtYVZhbGlkYXRvcjIwMjEifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZW1haWwiOiJtYXJrZXRwbGFjZUBteW1haWwuY29tIiwiaWQiOiIwYjg3NjAwMC0zNmM3LTQ3ZWQtYjg5Ni01YjVlYzE2MzY2M2EiLCJyb2xlcyI6W3sibmFtZXMiOlsiQ1JFQVRFX0lTU1VFUiJdLCJ0YXJnZXQiOiJkaWQ6d2ViOnBhY2tldGRlbGl2ZXJ5LmRzYmEuZml3YXJlLmRldjpkaWQifV19LCJleHBpcmF0aW9uRGF0ZSI6IjIwMzItMTItMDhUMTM6MDU6MDZaIiwiaWQiOiJ1cm46dXVpZDpjN2U3ZDRhMS03NTc5LTQwYTMtYjQxOC01OWY2YTlmMmY2YjEiLCJpc3N1YW5jZURhdGUiOiIyMDIzLTA2LTA3VDA3OjQ1OjA2WiIsImlzc3VlZCI6IjIwMjMtMDYtMDdUMDc6NDU6MDZaIiwiaXNzdWVyIjoiZGlkOndlYjptYXJrZXRwbGFjZS5kc2JhLmZpd2FyZS5kZXY6ZGlkIiwicHJvb2YiOnsiY3JlYXRlZCI6IjIwMjMtMDYtMDdUMDc6NDU6MDZaIiwiY3JlYXRvciI6ImRpZDp3ZWI6bWFya2V0cGxhY2UuZHNiYS5maXdhcmUuZGV2OmRpZCIsImp3cyI6ImV5SmlOalFpT21aaGJITmxMQ0pqY21sMElqcGJJbUkyTkNKZExDSmhiR2NpT2lKUVV6STFOaUo5Li5UaFNKVjR2VmhseFlVM043T1NrNi10bkt2ZEFDZlk5bWhScUNWSWYwZUxDQ1Nia0V5WVY0c2V2ZDdBQy1IR1lKMktXbU15SlRtLS1nTm9ndDVJdVRhYTUtb1RlZ1lCVHlSSWNfdGhaZ3hKNDRfN1dmcE8td0FZNHV5dUt6dC1UWVZoUVNXUTVsQV9DcFQ5bUw3Mk5BR1A0dm5Ob1Z2U2tYaElDQl9nN2EyS3FsNHhzUi13WjZodFY4VzRiZURldmh1M2FqTy1RNjVLWFFQWndJbm9VcFdoMXJjckVpeVJKejlwSTMxNDZkNzZpa2pMRGUwclFTTU1rbTBiRFE4Nm9zbmN1Ry1IWUlid1ZGOXhLaWViNldfTXVwbVdhWlJVbnZld2ptMV9aUUNGckt3M1VDTDZKZVNoZG83TEpwTV9iUmtYY0lORVBYQldKcDc3NHl2MWl5aUEiLCJ0eXBlIjoiSnNvbldlYlNpZ25hdHVyZTIwMjAiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6d2ViOm1hcmtldHBsYWNlLmRzYmEuZml3YXJlLmRldjpkaWQjNmY0YzEyNTVmNGE1NDA5MGJjOGZmNzM2NWIxM2E5YjcifSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkFjdGl2YXRpb25TZXJ2aWNlIl0sInZhbGlkRnJvbSI6IjIwMjMtMDYtMDdUMDc6NDU6MDZaIn19.a5aFIrDK3P2FJv-Pk3EI7Jn06tZ9RN5JwV8LmLTvXMNG8vVXwXWVUUkahzTB8fqNHeR4RNP3W80O1GSy3JzpGw"
#VP_TOKEN = "ewogICJ0eXBlIiA6IFsgIlZlcmlmaWFibGVDcmVkZW50aWFsIiwgIkFjdGl2YXRpb25TZXJ2aWNlIiBdLAogICJAY29udGV4dCIgOiBbICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsICJodHRwczovL3czaWQub3JnL3NlY3VyaXR5L3N1aXRlcy9qd3MtMjAyMC92MSIgXSwKICAiaWQiIDogInVybjp1dWlkOmM3ZTdkNGExLTc1NzktNDBhMy1iNDE4LTU5ZjZhOWYyZjZiMSIsCiAgImlzc3VlciIgOiAiZGlkOndlYjptYXJrZXRwbGFjZS5kc2JhLmZpd2FyZS5kZXY6ZGlkIiwKICAiaXNzdWFuY2VEYXRlIiA6ICIyMDIzLTA2LTA3VDA3OjQ1OjA2WiIsCiAgImlzc3VlZCIgOiAiMjAyMy0wNi0wN1QwNzo0NTowNloiLAogICJ2YWxpZEZyb20iIDogIjIwMjMtMDYtMDdUMDc6NDU6MDZaIiwKICAiZXhwaXJhdGlvbkRhdGUiIDogIjIwMzItMTItMDhUMTM6MDU6MDZaIiwKICAiY3JlZGVudGlhbFNjaGVtYSIgOiB7CiAgICAiaWQiIDogImh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9GSVdBUkUtT3BzL2k0dHJ1c3QtcHJvdmlkZXIvbWFpbi9kb2NzL3NjaGVtYS5qc29uIiwKICAgICJ0eXBlIiA6ICJGdWxsSnNvblNjaGVtYVZhbGlkYXRvcjIwMjEiCiAgfSwKICAiY3JlZGVudGlhbFN1YmplY3QiIDogewogICAgImlkIiA6ICIwYjg3NjAwMC0zNmM3LTQ3ZWQtYjg5Ni01YjVlYzE2MzY2M2EiLAogICAgInJvbGVzIiA6IFsgewogICAgICAibmFtZXMiIDogWyAiQ1JFQVRFX0lTU1VFUiIgXSwKICAgICAgInRhcmdldCIgOiAiZGlkOndlYjpwYWNrZXRkZWxpdmVyeS5kc2JhLmZpd2FyZS5kZXY6ZGlkIgogICAgfSBdLAogICAgImVtYWlsIiA6ICJtYXJrZXRwbGFjZUBteW1haWwuY29tIgogIH0sCiAgInByb29mIiA6IHsKICAgICJ0eXBlIiA6ICJKc29uV2ViU2lnbmF0dXJlMjAyMCIsCiAgICAiY3JlYXRvciIgOiAiZGlkOndlYjptYXJrZXRwbGFjZS5kc2JhLmZpd2FyZS5kZXY6ZGlkIiwKICAgICJjcmVhdGVkIiA6ICIyMDIzLTA2LTA3VDA3OjQ1OjA2WiIsCiAgICAidmVyaWZpY2F0aW9uTWV0aG9kIiA6ICJkaWQ6d2ViOm1hcmtldHBsYWNlLmRzYmEuZml3YXJlLmRldjpkaWQjNmY0YzEyNTVmNGE1NDA5MGJjOGZmNzM2NWIxM2E5YjciLAogICAgImp3cyIgOiAiZXlKaU5qUWlPbVpoYkhObExDSmpjbWwwSWpwYkltSTJOQ0pkTENKaGJHY2lPaUpRVXpJMU5pSjkuLlRoU0pWNHZWaGx4WVUzTjdPU2s2LXRuS3ZkQUNmWTltaFJxQ1ZJZjBlTENDU2JrRXlZVjRzZXZkN0FDLUhHWUoyS1dtTXlKVG0tLWdOb2d0NUl1VGFhNS1vVGVnWUJUeVJJY190aFpneEo0NF83V2ZwTy13QVk0dXl1S3p0LVRZVmhRU1dRNWxBX0NwVDltTDcyTkFHUDR2bk5vVnZTa1hoSUNCX2c3YTJLcWw0eHNSLXdaNmh0VjhXNGJlRGV2aHUzYWpPLVE2NUtYUVBad0lub1VwV2gxcmNyRWl5Ukp6OXBJMzE0NmQ3NmlrakxEZTByUVNNTWttMGJEUTg2b3NuY3VHLUhZSWJ3VkY5eEtpZWI2V19NdXBtV2FaUlVudmV3am0xX1pRQ0ZyS3czVUNMNkplU2hkbzdMSnBNX2JSa1hjSU5FUFhCV0pwNzc0eXYxaXlpQSIKICB9Cn0="
VP_TOKEN = {
    "aud": [
        "verifier-pdc.dsba.fiware.dev"
    ],
    "client_id": "did:web:packetdelivery.dsba.fiware.dev:did",
    "exp": 1687346995,
    "iss": "did:web:packetdelivery.dsba.fiware.dev:did",
    "kid": "HiS0NXOmYke6dTM7wZGrSwCE_VM0ntqIBMCpFFgEaOU",
    "sub": "did:example:holder",
    "verifiableCredential": {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "credentialSchema": {
            "id": "https://raw.githubusercontent.com/FIWARE-Ops/i4trust-provider/main/docs/schema.json",
            "type": "FullJsonSchemaValidator2021"
        },
        "credentialSubject": {
            "email": "marketplace@mymail.com",
            "id": "0b876000-36c7-47ed-b896-5b5ec163663a",
            "roles": [
                {
                    "names": [
                        "CREATE_ISSUER"
                    ],
                    "target": "did:web:packetdelivery.dsba.fiware.dev:did"
                }
            ]
        },
        "expirationDate": "2032-12-08T13:05:06Z",
        "id": "urn:uuid:c7e7d4a1-7579-40a3-b418-59f6a9f2f6b1",
        "issuanceDate": "2023-06-07T07:45:06Z",
        "issued": "2023-06-07T07:45:06Z",
        "issuer": "did:web:marketplace.dsba.fiware.dev:did",
        "proof": {
            "created": "2023-06-07T07:45:06Z",
            "creator": "did:web:marketplace.dsba.fiware.dev:did",
            "jws": "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJQUzI1NiJ9..ThSJV4vVhlxYU3N7OSk6-tnKvdACfY9mhRqCVIf0eLCCSbkEyYV4sevd7AC-HGYJ2KWmMyJTm--gNogt5IuTaa5-oTegYBTyRIc_thZgxJ44_7WfpO-wAY4uyuKzt-TYVhQSWQ5lA_CpT9mL72NAGP4vnNoVvSkXhICB_g7a2Kql4xsR-wZ6htV8W4beDevhu3ajO-Q65KXQPZwInoUpWh1rcrEiyRJz9pI3146d76ikjLDe0rQSMMkm0bDQ86osncuG-HYIbwVF9xKieb6W_MupmWaZRUnvewjm1_ZQCFrKw3UCL6JeShdo7LJpM_bRkXcINEPXBWJp774yv1iyiA",
            "type": "JsonWebSignature2020",
            "verificationMethod": "did:web:marketplace.dsba.fiware.dev:did#6f4c1255f4a54090bc8ff7365b13a9b7"
        },
        "type": [
            "VerifiableCredential",
            "ActivationService"
        ],
        "validFrom": "2023-06-07T07:45:06Z"
    }
}

# Tests for function extract_access_token(request)
class TestExtractAccessToken:

    @pytest.fixture
    def mock_request_ok(self, mocker):
        def headers_get(attr):
            if attr == "Authorization": return "Bearer " + ACCESS_TOKEN
            else: return None
        request = mocker.Mock()
        request.headers.get.side_effect = headers_get
        return request

    @pytest.fixture
    def mock_request_empty_token(self, mocker):
        def headers_get(attr):
            if attr == "Authorization": return "Bearer "
            else: return None
        request = mocker.Mock()
        request.headers.get.side_effect = headers_get
        return request

    @pytest.fixture
    def mock_request_invalid_header(self, mocker):
        def headers_get(attr):
            if attr == "Authorization": return "Bearer " + ACCESS_TOKEN + " invalid"
            else: return None
        request = mocker.Mock()
        request.headers.get.side_effect = headers_get
        return request

    @pytest.fixture
    def mock_request_no_bearer(self, mocker):
        def headers_get(attr):
            if attr == "Authorization": return ACCESS_TOKEN
            else: return None
        request = mocker.Mock()
        request.headers.get.side_effect = headers_get
        return request

    @pytest.fixture
    def mock_request_no_headers(self, mocker):
        def headers_get(attr):
            return None
        request = mocker.Mock()
        request.headers.get.side_effect = headers_get
        return request

    @pytest.mark.ok
    @pytest.mark.it('should successfully extract access token')
    def test_extract_ok(self, mock_request_ok):
        
        # Call function with request mock
        token = extract_access_token(mock_request_ok)
        assert token == ACCESS_TOKEN, "should return correct access token"

    @pytest.mark.ok
    @pytest.mark.it('should return None due to missing Authorization header')
    def test_extract_missing_header(self, mock_request_no_headers):
        
        # Call function with request mock
        token = extract_access_token(mock_request_no_headers)
        assert token is None, "return value should be None"

    @pytest.mark.failure
    @pytest.mark.it('should fail due to missing Bearer in Authorization header')
    def test_extract_missing_bearer(self, mock_request_no_bearer):
        
        # Call function with request mock
        with pytest.raises(IssuerException, match=r'Invalid Authorization header'):
            token = extract_access_token(mock_request_no_bearer)

    @pytest.mark.failure
    @pytest.mark.it('should fail due to invalid Authorization header')
    def test_extract_invalid_header(self, mock_request_invalid_header):
        
        # Call function with request mock
        with pytest.raises(IssuerException, match=r'Invalid Authorization header'):
            token = extract_access_token(mock_request_invalid_header)

    @pytest.mark.failure
    @pytest.mark.it('should fail due to empty_token')
    def test_extract_empty_token(self, mock_request_empty_token):
        
        # Call function with request mock
        with pytest.raises(IssuerException, match=r'Invalid Authorization header, empty token'):
            token = extract_access_token(mock_request_empty_token)


# Tests for function get_samedevice_redirect_url(conf)
class TestGetSamedeviceRedirectURL:

    @pytest.mark.ok
    @pytest.mark.it('should return redirect URL')
    def test_redirect_url_ok(self):
        
        # Call function
        url = get_samedevice_redirect_url(as_config)
        assert "https://verifier.packetdelivery.net/api/v1/samedevice?state=" in url, "URL should contain correct host and endpoint"
        assert "client_id=some-id" in url, "URL should contain client_id"


# Tests for decode_token_with_jwk(token, conf)
class TestDecodeTokenWithJwk:

    @pytest.mark.ok
    @pytest.mark.it('should successfully decode the token and return the payload')
    @patch('urllib.request.urlopen')
    def test_token_ok(self, mock_urlopen, mocker):

        # Mock call to JWKS endpoint
        cm = MagicMock()
        cm.getcode.return_value = 200
        cm.read.return_value = json.dumps(JWKS_RESPONSE)
        cm.__enter__.return_value = cm
        mock_urlopen.return_value = cm

        # Mock decoding of vp_token
        mocker.patch('jwt.decode', return_value=VP_TOKEN) 
        
        # Call function
        payload = decode_token_with_jwk(VC_TOKEN, as_config)

        # Asserts
        assert payload['client_id'] == "did:web:packetdelivery.dsba.fiware.dev:did", "should return correct client_id"
        assert payload['verifiableCredential']['issuer'] == "did:web:marketplace.dsba.fiware.dev:did", "should return correct issuer of credential"
