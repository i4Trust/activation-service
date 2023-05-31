from flask import Blueprint, Response, current_app, abort, request, redirect
from api.util.issuer_handler import extract_access_token, get_samedevice_redirect_url
from api.util.issuer_handler import decode_token_with_jwk, check_create_role, forward_til_request
import time

from api.exceptions.issuer_exception import IssuerException
from api.exceptions.database_exception import DatabaseException

# Blueprint
issuer_endpoint = Blueprint("issuer_endpoint", __name__)

# POST /issuer
# TODO: Check for PUT to overwrite by DID: https://github.com/FIWARE/trusted-issuers-list/blob/main/api/trusted-issuers-list.yaml#L51
@issuer_endpoint.route("/issuer", methods = ['POST'])
def index():
    current_app.logger.debug('Received request at /issuer endpoint (HTTP Method: {})'.format(request.method))

    # Load config
    conf = current_app.config['as']

    # Check for access token JWT in request header
    request_token = None
    try:
        request_token = extract_access_token(request)
    except IssuerException as iex:
        current_app.logger.debug("Error when extracting access token JWT from authorization header: {}. Returning status {}.".format(iex.internal_msg, iex.status_code))
        abort(iex.status_code, iex.public_msg)

    if not request_token:
        current_app.logger.debug("... no access token JWT in 'Authorization' header, returning 302 redirect")

        redirect_url = None
        try:
            redirect_url = get_samedevice_redirect_url(conf)
        except IssuerException as rie:
            current_app.logger.error("Error when generating redirect URL: {}. Returning status {}.".format(rie.internal_msg, rie.status_code))
            abort(rie.status_code, rie.public_msg)

        # Return redirect
        current_app.logger.debug("... returning redirect to: {}".format(redirect_url))
        return redirect(redirect_url, 302)

    # Received JWT in Authorization header
    current_app.logger.debug("...received access token JWT in incoming request: {}".format(request_token))
    
    # Validate JWT with verifier JWKS
    payload = None
    try:
        current_app.logger.debug("... validating and decoding JWT using JWKS ...")
        payload = decode_token_with_jwk(request_token, conf)
    except IssuerException as die:
            current_app.logger.debug("Error when validating/decoding: {}. Returning status {}.".format(die.internal_msg, die.status_code))
            abort(die.status_code, die.public_msg)
    current_app.logger.debug("... decoded token payload: {}".format(payload))

    # Check TIL access depending on HTTP method
    if request.method == 'POST':
        # POST: Create issuer flow
        
        # Check for 'Create Issuer' role
        try:
            current_app.logger.debug("... checking for necessary role to create issuer")
            if not check_create_role(payload, conf):
                current_app.logger.debug("Required role was not found in JWT credential. Returning status 401.")
                current_app.logger.debug("... required role '{}' for target DID '{}'".format(conf['issuer']['roles']['createRole'], conf['issuer']['providerId']))
                abort(401, "Issued roles do not allow to create an issuer")
        except IssuerException as cie:
            current_app.logger.debug("Error when checking for required role: {}. Returning status {}.".format(cie.internal_msg, cie.status_code))
            abort(cie.status_code, cie.public_msg)
        current_app.logger.debug("... access granted!")
        
    elif request.method == 'PUT':
        # PUT: Update issuer flow
    
        # TODO: Implement issuer update
        abort(500, "PUT not implemented")
    else:
        # should not happen
        abort(500, "Invalid HTTP method")
        
    # Forward request to TIL
    try:
        current_app.logger.debug("... forwarding request to TIL")
        res = forward_til_request(request, conf)
        current_app.logger.debug("... received TIL response (code: {}): {}".format(res.status_code, res.content))
        current_app.logger.debug("... returning response to sender!")
        return res.content, res.status_code, res.headers.items()
    except IssuerException as fie:
        current_app.logger.error("Error when forwarding request to TIL: {}. Returning status {}.".format(fie.internal_msg, fie.status_code))
        abort(fie.status_code, fie.public_msg)
