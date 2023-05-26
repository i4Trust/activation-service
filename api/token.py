from flask import Blueprint, Response, current_app, abort, request
from api.util.token_handler import forward_token
import time

from api.exceptions.token_exception import TokenException
from api.exceptions.database_exception import DatabaseException

# Blueprint
token_endpoint = Blueprint("token_endpoint", __name__)

# POST /token
@token_endpoint.route("/token", methods = ['POST'])
def index():
    current_app.logger.debug('Received request at /token endpoint')
    
    # Load config
    conf = current_app.config['as']
    
    # Forward token
    auth_data = None
    try:
        response = forward_token(request, current_app)
        auth_data = response.json()
    except TokenException as tex:
        current_app.logger.debug("Error when forwarding token request to AR: {}. Returning status {}.".format(tex.internal_msg, tex.status_code))
        abort(tex.status_code, tex.public_msg)
    if (not 'access_token' in auth_data) or (not 'expires_in' in auth_data):
        app.logger.debug("Invalid response from AR: {}".format(auth_data))
        abort(400, "Received invalid response from AR")
        return None
    
    # Build Token object
    try:
        from api.models.token import Token
        client_id = request.form.get('client_id')
        ar_token = Token(
            eori=client_id,
            access_token=auth_data['access_token'],
            expires=int(time.time() * 1000) + (1000*auth_data['expires_in']))
    except Exception as bex:
        print(bex)
        current_app.logger.error("Internal error when building Token object for DB insert: {}".format(ex))
        abort(500, "Internal error")
    current_app.logger.debug('Received access token with data: {}'.format(ar_token))
    
    # Insert token
    try:
        from api.util.db_handler import insert_token
        insert_token(ar_token, current_app.config['db'])
    except DatabaseException as dex:
        current_app.logger.error("Error when inserting token into DB: {}. Returning status: {}".format(dex.internal_msg, dex.status_code))
        abort(dex.status_code, dex.public_msg)
        
    return auth_data, 200
    
