import requests
import time, os
import jwt
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
