from flask import Blueprint, Response, current_app, abort, request, redirect
from api.util.issuer_handler import extract_access_token, get_samedevice_redirect_url
from api.util.issuer_handler import decode_token_with_jwk, forward_til_request
from api.util.issuer_handler import check_create_role, check_update_role, check_delete_role
from api.util.apikey_handler import check_api_key
import time

from api.exceptions.issuer_exception import IssuerException
from api.exceptions.database_exception import DatabaseException
from api.exceptions.apikey_exception import ApiKeyException

# Blueprint
issuer_endpoint = Blueprint("issuer_endpoint", __name__)

# POST /issuer
@issuer_endpoint.route("/issuer", methods = ['POST','PUT','DELETE'])
def index():
    current_app.logger.debug('Received request at /issuer endpoint (HTTP Method: {})'.format(request.method))

    # Load config
    conf = current_app.config['as']
 
    # Check for API-Key
    if 'apikeys' in conf:
        apikey_conf = conf['apikeys']
        if 'ishare' in apikey_conf and apikey_conf['issuer']['enabledIssuer']:
            try:
                current_app.logger.debug("Checking API-Key...")
                check_api_key(request, apikey_conf['issuer']['headerName'], apikey_conf['issuer']['apiKey'])
            except ApiKeyException as ake:
                current_app.logger.debug("Checking API-Key not successful: {}. Returning status {}.".format(ake.internal_msg, ake.status_code))
                abort(ake.status_code, ake.public_msg)
            current_app.logger.debug("... API-Key accepted")
 
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
        # TODO: catch expired token exception, to send redirect as well
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
        
    elif request.method == 'PUT':
        # PUT: Update issuer flow

        # Check for 'Update Issuer' role
        try:
            current_app.logger.debug("... checking for necessary role to update issuer")
            if not check_update_role(payload, conf):
                current_app.logger.debug("Required role was not found in JWT credential. Returning status 401.")
                current_app.logger.debug("... required role '{}' for target DID '{}'".format(conf['issuer']['roles']['updateRole'], conf['issuer']['providerId']))
                abort(401, "Issued roles do not allow to update an issuer")
        except IssuerException as pie:
            current_app.logger.debug("Error when checking for required role: {}. Returning status {}.".format(pie.internal_msg, pie.status_code))
            abort(pie.status_code, pie.public_msg)
    
    elif request.method == 'DELETE':
        # DELETE: Delete issuer flow

        # Check for 'Delete Issuer' role
        try:
            current_app.logger.debug("... checking for necessary role to delete issuer")
            if not check_delete_role(payload, conf):
                current_app.logger.debug("Required role was not found in JWT credential. Returning status 401.")
                current_app.logger.debug("... required role '{}' for target DID '{}'".format(conf['issuer']['roles']['deleteRole'], conf['issuer']['providerId']))
                abort(401, "Issued roles do not allow to delete an issuer")
        except IssuerException as delie:
            current_app.logger.debug("Error when checking for required role: {}. Returning status {}.".format(delie.internal_msg, delie.status_code))
            abort(delie.status_code, delie.public_msg)
    
    else:
        # should not happen
        abort(500, "Invalid HTTP method")

    # Forward request to TIL
    current_app.logger.debug("... access granted!")
    try:
        current_app.logger.debug("... forwarding request to TIL")
        res = forward_til_request(request, conf)
        current_app.logger.debug("... received TIL response (code: {}): {}".format(res.status_code, res.content))
        current_app.logger.debug("... returning response to sender!")
        return res.content, res.status_code, res.headers.items()
    except IssuerException as fie:
        current_app.logger.error("Error when forwarding request to TIL: {}. Returning status {}.".format(fie.internal_msg, fie.status_code))
        abort(fie.status_code, fie.public_msg)
