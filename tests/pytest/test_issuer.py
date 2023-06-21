import pytest
import os
import ast
from api import app

from tests.pytest.util.config_handler import load_config

# Valid API-Key
VALID_API_KEY = "eb4675ed-860e-4de1-a9a7-3e2e4356d08d"

# Get AS config
as_config = load_config("tests/config/as.yml", app)
app.config['as'] = as_config

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

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client



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
    print(dict_str)
    assert "https://verifier.packetdelivery.net/api/v1/samedevice?state=" in dict_str, "response should contain redirect URL"
    assert "client_id=some-id" in dict_str, "response should contain client_id"
