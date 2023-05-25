import requests
import time, os
import jwt
import uuid
from requests.exceptions import HTTPError

from api.exceptions.create_policy_exception import CreatePolicyException

# ENV for PRIVATE_KEY
ENV_PRIVATE_KEY = "AS_KEY"

# ENV for certificate chain
ENV_CERTIFICATES = "AS_CERTS"

# Obtain private key from yaml or ENV
def _get_private_key(config):
    return os.environ.get(ENV_PRIVATE_KEY, config['key'])

# Obtain certificate chains from yaml or ENV
def _get_certificates(config):
    return os.environ.get(ENV_CERTIFICATES, config['crt'])

# Create iSHARE JWT
def _build_token(params):
        def getCAChain(cert):

            sp = cert.split('-----BEGIN CERTIFICATE-----\n')
            sp = sp[1:]

            ca_chain = []
            for ca in sp:
                ca_sp = ca.split('\n-----END CERTIFICATE-----')
                ca_chain.append(ca_sp[0])

            return ca_chain

        iat = int(str(time.time()).split('.')[0])
        exp = iat + 30

        token = {
            "jti": str(uuid.uuid4()),
            "iss": params['client_id'],
            "sub": params['client_id'],
            "aud": params['ar_id'],
            "iat": iat,
            "nbf": iat,
            "exp": exp
        }

        return jwt.encode(token, params['key'], algorithm="RS256", headers={
            'x5c': getCAChain(params['cert'])
        })

# delegationEvidence template allowing to create policys
def _get_delegation_evidence_template(issuer, eori):
    return {
        'delegationRequest': {
            'policyIssuer': issuer,
            'target': {
                'accessSubject': eori
            },
            'policySets': [
                {
                    'policies': [
                        {
                            'target': {
                                'resource': {
                                    'type': "delegationEvidence",
                                    'identifiers': ["*"],
                                    'attributes': ["*"]
                                },
                                'actions': ["POST"]
                            },
                            'rules': [
                                {
                                    'effect': "Permit"
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    }

# Analyse request header and extract access token
def extract_access_token(request):

    # Get header
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        message = "Missing Authorization header"
        raise CreatePolicyException(message, 400, message)

    # Split Bearer/token
    if not auth_header.startswith("Bearer"):
        message = "Invalid Authorization header"
        raise CreatePolicyException(message, 400, message)
    split_header = auth_header.split(" ")
    if len(split_header) != 2:
        message = "Invalid Authorization header"
        raise CreatePolicyException(message, 400, message)

    # Token
    token = split_header[1]
    if not token or len(token) < 1:
        message = "Invalid Authorization header"
        raise CreatePolicyException(message, 400, message)

    return token

# Get token from AR as AS
def get_ar_token(conf):

    # Generate iSHARE JWT
    token = _build_token({
        'client_id': conf['client']['id'],
        'ar_id': conf['ar']['id'],
        'key': _get_private_key(conf['client']),
        'cert': _get_certificates(conf['client'])
    })

    # Retrieve token from AR
    url = conf['ar']['token']
    auth_params = {
        'grant_type': 'client_credentials',
        'scope': 'iSHARE',
        'client_id': conf['client']['id'],
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': token
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=auth_params, headers=headers)
    try:
        response.raise_for_status()
    except HTTPError as e:
        message = "Error when AS is retrieving token from AR"
        internal_message = "Error retrieving token from AR: {}".format(e)
        if response.json():
            internal_message += ", received JSON response: {}".format(response.json())
        raise CreatePolicyException(message, 400, internal_message)

    auth_data = response.json()
    if (not 'access_token' in auth_data) or (not 'expires_in' in auth_data):
        message = "AS received invalid response from AR when obtaining token"
        internal_message = "AS received invalid response from AR when obtaining token: {}".format(auth_data)
        raise CreatePolicyException(message, 400, internal_message)

    return auth_data['access_token']

# Check if sender is allowed to create policies (delegationEvidence)
def check_create_delegation_evidence(conf, eori, access_token):
    
    # Get delegationEvidence template for query
    payload = _get_delegation_evidence_template(conf['client']['id'], eori)

    # Send query to AR
    url = conf['ar']['delegation']
    headers={
        'Authorization': 'Bearer ' + access_token
    }
    
    response = requests.post(url, json=payload, headers=headers)
    try:
        response.raise_for_status()
    except HTTPError as e:
        message = "Necessary delegationEvidence could not be retrieved from AR"
        internal_message = "Error when querying delegationEvidence at AR: {}".format(e)
        if response.json():
            internal_message += ", received JSON response: {}".format(response.json())
        raise CreatePolicyException(message, 400, internal_message)
    
    # Check response
    query_data = response.json()
    print(query_data)
    if not query_data['delegation_token']:
        message = "Ar was not providing valid response"
        internal_message = message + ": {}".format(query_data)
        raise CreatePolicyException(message, 400, internal_message)
    
    delegation_token = query_data['delegation_token']
    decoded_token = jwt.decode(delegation_token, options={"verify_signature": False})
    del_ev = decoded_token['delegationEvidence']
    message = "AR did not provide valid delegationEvidence to create policies."
    if not del_ev:
        raise CreatePolicyException(message, 400, "Missing 'delegationEvidence' object")

    psets = del_ev['policySets']
    if not psets or len(psets) < 1:
        raise CreatePolicyException(message, 400, "Missing 'policySets'")
    
    pset = psets[0]
    policies = pset['policies']
    if not policies or len(policies) < 1:
        raise CreatePolicyException(message, 400, "Missing 'policies'")

    p = policies[0]
    target = p['target']
    if not target:
        raise CreatePolicyException(message, 400, "Missing 'target'")

    resource = target['resource']
    if not resource:
        raise CreatePolicyException(message, 400, "Missing 'resource'")

    ptype = resource['type']
    if not ptype:
        raise CreatePolicyException(message, 400, "Missing 'type'")
    if ptype != "delegationEvidence":
        raise CreatePolicyException(message, 400, "Wrong type: {} != delegationEvidence".format(ptype))

    rules = p['rules']
    if not rules or len(rules) < 1:
        raise CreatePolicyException(message, 400, "Missing 'rules'")

    r = rules[0]
    effect = r['effect']
    if not effect:
        raise CreatePolicyException(message, 400, "Missing 'effect'")
    if effect != "Permit":
        raise CreatePolicyException(message, 400, "Wrong effect: {} != Permit".format(effect))

    return None

# Create delegationEvidence at AR
def create_delegation_evidence(conf, access_token, request):

    # Get payload from request
    payload = request.json
    if not payload:
        message = "Missing payload in /createpolicy request"
        raise CreatePolicyException(message, 400, message)

    # Create policy at AR
    url = conf['ar']['policy']
    headers={
        'Authorization': 'Bearer ' + access_token
    }
    
    response = requests.post(url, json=payload, headers=headers)
    try:
        response.raise_for_status()
    except HTTPError as e:
        message = "Policy could not be created at AR: {}".format(e)
        if response.json():
            message += ", received JSON response: {}".format(response.json())
        raise CreatePolicyException(message, 400, message)

    # Check response
    query_data = response.json()
    if query_data:
        if query_data['policy_token']:
            return {
                'policy_token': query_data['policy_token']
            }

    return None
