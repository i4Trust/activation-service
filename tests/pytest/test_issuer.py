import pytest
from unittest.mock import patch, MagicMock

import os
import ast
import json
from api import app

from tests.pytest.util.config_handler import load_config

# Valid API-Key
VALID_API_KEY = "eb4675ed-860e-4de1-a9a7-3e2e4356d08d"

# Get AS config
as_config = load_config("tests/config/as.yml", app)
app.config['as'] = as_config

# Endpoint of /issuer
ISSUER_ENDPOINT = "{}/issuer".format(as_config['issuer']['tilUri'])
ISSUER_HOST = as_config['issuer']['tilUri']

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

# Issuer template
TEMPLATE_ISSUER = {
    "did": "did:web:happypets.dsba.fiware.dev:did",
    "credentials": [
        {
            "validFor": {
                "from": '2023-02-13T08:15:30Z',
                "to": '2023-12-24T20:10:40Z'
            },
            "credentialsType": "PacketDeliveryService",
            "claims": [
                {
                    "name": "roles",
                    "allowedValues": ["GOLD_CUSTOMER", "STANDARD_CUSTOMER"]
                }
            ]
        }
    ]
}

# CREATE_ISSUER template
TEMPLATE_CREATE_ISSUER = {
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

# Decoded VP token
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
                },
                {
                    "names": [
                        "UPDATE_ISSUER"
                    ],
                    "target": "did:web:packetdelivery.dsba.fiware.dev:did"
                },
                {
                    "names": [
                        "DELETE_ISSUER"
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

VP_TOKEN_ENCODED = "ewogICJ0eXBlIiA6IFsgIlZlcmlmaWFibGVDcmVkZW50aWFsIiwgIkFjdGl2YXRpb25TZXJ2aWNlIiBdLAogICJAY29udGV4dCIgOiBbICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsICJodHRwczovL3czaWQub3JnL3NlY3VyaXR5L3N1aXRlcy9qd3MtMjAyMC92MSIgXSwKICAiaWQiIDogInVybjp1dWlkOmM3ZTdkNGExLTc1NzktNDBhMy1iNDE4LTU5ZjZhOWYyZjZiMSIsCiAgImlzc3VlciIgOiAiZGlkOndlYjptYXJrZXRwbGFjZS5kc2JhLmZpd2FyZS5kZXY6ZGlkIiwKICAiaXNzdWFuY2VEYXRlIiA6ICIyMDIzLTA2LTA3VDA3OjQ1OjA2WiIsCiAgImlzc3VlZCIgOiAiMjAyMy0wNi0wN1QwNzo0NTowNloiLAogICJ2YWxpZEZyb20iIDogIjIwMjMtMDYtMDdUMDc6NDU6MDZaIiwKICAiZXhwaXJhdGlvbkRhdGUiIDogIjIwMzItMTItMDhUMTM6MDU6MDZaIiwKICAiY3JlZGVudGlhbFNjaGVtYSIgOiB7CiAgICAiaWQiIDogImh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9GSVdBUkUtT3BzL2k0dHJ1c3QtcHJvdmlkZXIvbWFpbi9kb2NzL3NjaGVtYS5qc29uIiwKICAgICJ0eXBlIiA6ICJGdWxsSnNvblNjaGVtYVZhbGlkYXRvcjIwMjEiCiAgfSwKICAiY3JlZGVudGlhbFN1YmplY3QiIDogewogICAgImlkIiA6ICIwYjg3NjAwMC0zNmM3LTQ3ZWQtYjg5Ni01YjVlYzE2MzY2M2EiLAogICAgInJvbGVzIiA6IFsgewogICAgICAibmFtZXMiIDogWyAiQ1JFQVRFX0lTU1VFUiIgXSwKICAgICAgInRhcmdldCIgOiAiZGlkOndlYjpwYWNrZXRkZWxpdmVyeS5kc2JhLmZpd2FyZS5kZXY6ZGlkIgogICAgfSBdLAogICAgImVtYWlsIiA6ICJtYXJrZXRwbGFjZUBteW1haWwuY29tIgogIH0sCiAgInByb29mIiA6IHsKICAgICJ0eXBlIiA6ICJKc29uV2ViU2lnbmF0dXJlMjAyMCIsCiAgICAiY3JlYXRvciIgOiAiZGlkOndlYjptYXJrZXRwbGFjZS5kc2JhLmZpd2FyZS5kZXY6ZGlkIiwKICAgICJjcmVhdGVkIiA6ICIyMDIzLTA2LTA3VDA3OjQ1OjA2WiIsCiAgICAidmVyaWZpY2F0aW9uTWV0aG9kIiA6ICJkaWQ6d2ViOm1hcmtldHBsYWNlLmRzYmEuZml3YXJlLmRldjpkaWQjNmY0YzEyNTVmNGE1NDA5MGJjOGZmNzM2NWIxM2E5YjciLAogICAgImp3cyIgOiAiZXlKaU5qUWlPbVpoYkhObExDSmpjbWwwSWpwYkltSTJOQ0pkTENKaGJHY2lPaUpRVXpJMU5pSjkuLlRoU0pWNHZWaGx4WVUzTjdPU2s2LXRuS3ZkQUNmWTltaFJxQ1ZJZjBlTENDU2JrRXlZVjRzZXZkN0FDLUhHWUoyS1dtTXlKVG0tLWdOb2d0NUl1VGFhNS1vVGVnWUJUeVJJY190aFpneEo0NF83V2ZwTy13QVk0dXl1S3p0LVRZVmhRU1dRNWxBX0NwVDltTDcyTkFHUDR2bk5vVnZTa1hoSUNCX2c3YTJLcWw0eHNSLXdaNmh0VjhXNGJlRGV2aHUzYWpPLVE2NUtYUVBad0lub1VwV2gxcmNyRWl5Ukp6OXBJMzE0NmQ3NmlrakxEZTByUVNNTWttMGJEUTg2b3NuY3VHLUhZSWJ3VkY5eEtpZWI2V19NdXBtV2FaUlVudmV3am0xX1pRQ0ZyS3czVUNMNkplU2hkbzdMSnBNX2JSa1hjSU5FUFhCV0pwNzc0eXYxaXlpQSIKICB9Cn0="

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_post_issuer_empty_response(requests_mock):
    return requests_mock.post(ISSUER_ENDPOINT,
                              json={ },
                              status_code=201)

# Test: Successfully returned redirect 302
@pytest.mark.ok
@pytest.mark.it('should successfully return a 302 redirect')
def test_issuer_redirect_ok(client):

    # Invoke request
    response = client.post("/issuer",
                           json=TEMPLATE_ISSUER,
                           headers={
                               'AS-API-KEY': VALID_API_KEY
                           })
    
    # Asserts on response
    assert response.status_code == 302, "should return code 302"

    dict_str = list(response.response)[0].decode("UTF-8")
    assert "https://verifier.packetdelivery.net/api/v1/samedevice?state=" in dict_str, "response should contain redirect URL"
    assert "client_id=some-id" in dict_str, "response should contain client_id"

# Test: Successfully create issuer
@pytest.mark.ok
@pytest.mark.it('should successfully create the issuer')
@patch('urllib.request.urlopen')
def test_issuer_create_ok(mock_urlopen, client, mock_post_issuer_empty_response, mocker):

    # Mock call to JWKS endpoint
    cm = MagicMock()
    cm.getcode.return_value = 200
    cm.read.return_value = json.dumps(JWKS_RESPONSE)
    cm.__enter__.return_value = cm
    mock_urlopen.return_value = cm
    
    # Mock decoding of vp_token
    mocker.patch('api.issuer.decode_token_with_jwk', return_value=VP_TOKEN)
    
    # Invoke request
    response = client.post("/issuer",
                           json=TEMPLATE_ISSUER,
                           headers={
                               'AS-API-KEY': VALID_API_KEY,
                               'Authorization': "Bearer {}".format(VP_TOKEN_ENCODED)
                           })
    
    # Asserts on response
    assert response.status_code == 201, "should return status code 201"
