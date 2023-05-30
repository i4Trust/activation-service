from flask import Blueprint, Response, current_app, abort, request, redirect
from api.util.issuer_handler import extract_access_token, get_samedevice_redirect_url
import time

from api.exceptions.issuer_exception import IssuerException
from api.exceptions.database_exception import DatabaseException

# Blueprint
issuer_endpoint = Blueprint("issuer_endpoint", __name__)

# POST /issuer
@issuer_endpoint.route("/issuer", methods = ['POST'])
def index():
    current_app.logger.debug('Received request at /issuer endpoint')

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
    
    # validate JWT with verifier JWKS
    # check role --> define credential and role first
    # forward request to TIL /issuer endpoint
    # return TIL response

    return "OK", 200
