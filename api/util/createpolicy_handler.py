import requests
import time, os
import jwt
import uuid
from requests.exceptions import HTTPError

from api.exceptions.create_policy_exception import CreatePolicyException

# ENV for PRIVATE_KEY
ENV_PRIVATE_KEY = "AS_CLIENT_KEY"

# ENV for certificate chain
ENV_CERTIFICATES = "AS_CLIENT_CERTS"

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
        raise CreatePolicyException(message, None, 400)

    # Split Bearer/token
    if not auth_header.startswith("Bearer"):
        message = "Invalid Authorization header"
        raise CreatePolicyException(message, None, 400)
    split_header = auth_header.split(" ")
    if len(split_header) != 2:
        message = "Invalid Authorization header"
        raise CreatePolicyException(message, None, 400)

    # Token
    token = split_header[1]
    if not token or len(token) < 1:
        message = "Invalid Authorization header, empty token"
        raise CreatePolicyException(message, None, 400)

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
        raise CreatePolicyException(message, internal_message, 400)

    auth_data = response.json()
    if (not 'access_token' in auth_data) or (not 'expires_in' in auth_data):
        message = "AS received invalid response from AR when obtaining token"
        internal_message = "AS received invalid response from AR when obtaining token: {}".format(auth_data)
        raise CreatePolicyException(message, internal_message, 400)

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
        raise CreatePolicyException(message, internal_message, 400)
    
    # Check response
    query_data = response.json()
    if not 'delegation_token' in query_data:
        message = "AR was not providing valid response"
        internal_message = message + ": {}".format(query_data)
        raise CreatePolicyException(message, internal_message, 400)

    message = "AR did not provide valid delegationEvidence to create policies."
    delegation_token = query_data['delegation_token']
    decoded_token = jwt.decode(delegation_token, options={"verify_signature": False})
    if not 'delegationEvidence' in decoded_token:
        raise CreatePolicyException(message, "Missing 'delegationEvidence' object", 400)
    del_ev = decoded_token['delegationEvidence']

    if not 'policySets' in del_ev:
        raise CreatePolicyException(message, "Missing 'policySets'", 400)
    psets = del_ev['policySets']
    if len(psets) < 1:
        raise CreatePolicyException(message, "Empty 'policySets'", 400)
    
    pset = psets[0]
    if not 'policies' in pset:
        raise CreatePolicyException(message, "Missing 'policies'", 400)
    policies = pset['policies']
    if len(policies) < 1:
        raise CreatePolicyException(message, "Empty 'policies'", 400)

    p = policies[0]
    if not 'target' in p:
        raise CreatePolicyException(message, "Missing 'target'", 400)
    target = p['target']

    if not 'actions' in target:
        raise CreatePolicyException(message, "Missing 'actions'", 400)
    actions = target['actions']
    if len(actions) < 1:
        raise CreatePolicyException(message, "Empty 'actions'", 400)
    if not 'POST' in actions:
        raise CreatePolicyException(message, "'actions' is missing 'POST': {}".format(actions), 400)
    
    if not 'resource' in target:
        raise CreatePolicyException(message, "Missing 'resource'", 400)
    resource = target['resource']
    
    if not 'type' in resource:
        raise CreatePolicyException(message, "Missing 'type'", 400)
    ptype = resource['type']
    if ptype != "delegationEvidence":
        raise CreatePolicyException(message, "Wrong type: {} != delegationEvidence".format(ptype), 400)

    if not 'rules' in p:
        raise CreatePolicyException(message, "Missing 'rules'", 400)
    rules = p['rules']
    if len(rules) < 1:
        raise CreatePolicyException(message, "Empty 'rules'", 400)

    r = rules[0]
    if not 'effect' in r:
        raise CreatePolicyException(message, "Missing 'effect'", 400)
    effect = r['effect']
    if effect != "Permit":
        raise CreatePolicyException(message, "Wrong effect: {} != Permit".format(effect), 400)

    return None

# Create delegationEvidence at AR
def create_delegation_evidence(conf, access_token, request):

    # Get payload from request
    payload = request.json
    if not payload:
        message = "Missing payload in /createpolicy request"
        raise CreatePolicyException(message, None, 400)

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
        raise CreatePolicyException(message, None, 400)

    # Check response
    query_data = response.json()
    if query_data:
        if 'policy_token' in query_data:
            return {
                'policy_token': query_data['policy_token']
            }

    return None
