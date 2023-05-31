import requests
import time, os
import jwt
from jwt import PyJWKClient
import uuid
from requests.exceptions import HTTPError

from api.exceptions.issuer_exception import IssuerException

# Analyse request header and extract access token
def extract_access_token(request):

    # Get header
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        # Empty Authorization header, will return 302 redirect to initiate OIDC4VP/SIOP-2 flow
        return None

    # Split Bearer/token
    if not auth_header.startswith("Bearer"):
        message = "Invalid Authorization header"
        raise IssuerException(message, None, 400)
    split_header = auth_header.split(" ")
    if len(split_header) != 2:
        message = "Invalid Authorization header"
        raise IssuerException(message, None, 400)

    # Token
    token = split_header[1]
    if not token or len(token) < 1:
        message = "Invalid Authorization header, empty token"
        raise IssuerException(message, None, 400)

    return token

# Build redirect URL for samedevice flow
def get_samedevice_redirect_url(conf):

    # Generate session ID
    session_id = str(uuid.uuid4())

    # Get client_id
    if not 'issuer' in conf or not 'clientId' in conf['issuer']:
        message = "Missing 'clientId' in issuer config"
        raise IssuerException("Internal server error", message, 500)
    client_id = conf['issuer']['clientId']

    # Get verifier URI and path
    if not 'issuer' in conf or not 'verifierUri' in conf['issuer']:
        message = "Missing 'verifierUri' in issuer config"
        raise IssuerException("Internal server error", message, 500)
    verifier_uri = conf['issuer']['verifierUri']
    if not 'issuer' in conf or not 'samedevicePath' in conf['issuer']:
        message = "Missing 'samedevicePath' in issuer config"
        raise IssuerException("Internal server error", message, 500)
    samedevice_path = conf['issuer']['samedevicePath']

    # Build URL
    return "{}{}?state={}&client_id={}".format(verifier_uri, samedevice_path, session_id, client_id)

# Validate and decode the token using JWKS
def decode_token_with_jwk(token, conf):

    # Get JWKS URI and path
    if not 'issuer' in conf or not 'verifierUri' in conf['issuer']:
        message = "Missing 'verifierUri' in issuer config"
        raise IssuerException("Internal server error", message, 500)
    verifier_uri = conf['issuer']['verifierUri']
    if not 'issuer' in conf or not 'jwksPath' in conf['issuer']:
        message = "Missing 'jwksPath' in issuer config"
        raise IssuerException("Internal server error", message, 500)
    jwks_path = conf['issuer']['jwksPath']

    # Get allowed algorithms
    if not 'algorithms' in conf['issuer']:
        message = "Missing 'algorithms' in issuer config"
        raise IssuerException("Internal server error", message, 500)
    alg = conf['issuer']['algorithms']
    if len(alg) < 1:
        message = "Empty 'algorithms' in issuer config"
        raise IssuerException("Internal server error", message, 500)
    
    # Build JWKS URL
    url = "{}{}".format(verifier_uri, jwks_path)

    # JWK client
    jwks_client = PyJWKClient(url)

    # Get signing key from JWKS endpoint by kid specified in token
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
    except Exception as kex:
        message = "Error when obtaining signing key"
        int_msg = message + ": {}".format(kex)
        raise IssuerException(message, int_msg, 400)

    # Validate and decode
    try:
        data = jwt.decode(
            token,
            signing_key.key,
            algorithms=alg,
            options = {
                "verify_aud": False
            }
        )
    except Exception as dex:
        message = "Invalid token provided"
        int_msg = message + ": {}".format(dex)
        raise IssuerException(message, int_msg, 401)

    return data

# Check if credential contains necessary role
def check_role(credential_roles, required_role, provider_id):

    # Loop over credential roles and look for required role
    for r in credential_roles:
        if 'target' in r and r['target'] == provider_id:
            if 'names' in r['target']:
                r_names = r['target']['names']
                if required_role in r_names:
                    return True

    return False
    

# Check if credential contains necessary role to create issuer
def check_create_role(token_payload, conf):

    # Get required role
    if not 'issuer' in conf or not 'roles' in conf['issuer']:
        message = "Missing 'roles' in issuer config"
        raise IssuerException("Internal server error", message, 500)
    conf_roles = conf['issuer']['roles']
    if not 'createRole' in conf_roles:
        message = "Missing 'createRole' in issuer roles config"
        raise IssuerException("Internal server error", message, 500)
    create_role = conf_roles['createRole']

    # Get target DID
    if not 'providerId' in conf['issuer']:
        message = "Missing 'providerId' in issuer config"
        raise IssuerException("Internal server error", message, 500)
    provider_id = conf['issuer']['providerId']

    # Get roles from credential payload
    if not 'verifiableCredential' in token_payload:
        msg = "No 'verifiableCredential' in JWT"
        raise IssuerException(msg, None, 400)
    credential = token_payload['verifiableCredential']
    if not 'credentialSubject' in credential:
        msg = "No 'credentialSubject' in verifiableCredential"
        raise IssuerException(msg, None, 400)
    subject = credential['credentialSubject']
    if not 'roles' in subject:
        msg = "No 'roles' in credentialSubject"
        raise IssuerException(msg, None, 400)
    token_roles = subject['roles']
    if len(token_roles) < 1:
        msg = "Empty 'roles' in credentialSubject"
        raise IssuerException(msg, None, 400)

    # Check for role
    return check_role(token_roles, create_role, provider_id)

# Forward request to TIL
def forward_til_request(request, conf):

    # Get URI of TIL service
    if not 'tilUri' in conf['issuer']:
        message = "Missing 'tilUri' in issuer config"
        raise IssuerException("Internal server error", message, 500)
    til_uri = conf['issuer']['tilUri']

    # Build request parameters
    headers = {k:v for k,v in request.headers if k != "Authorization" and k.lower() != 'host'}
    url = request.url.replace(request.host_url, f'{til_uri}/')
    data = request.get_data()
    
    # Forward request
    response = requests.request(
        method          = request.method,
        url             = url,
        headers         = headers,
        data            = data,
        cookies         = request.cookies,
        allow_redirects = False,
    )

    return response
