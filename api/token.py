from flask import Blueprint, Response, current_app, abort, request
from api.util.token_handler import forward_token
import time

# Blueprint
token_endpoint = Blueprint("token_endpoint", __name__)

# POST /token
@token_endpoint.route("/token", methods = ['POST'])
def index():
    current_app.logger.debug('Received request at /token endpoint')
    
    # Load config
    conf = current_app.config['as']
    
    # Forward token
    response = forward_token(request, current_app, abort)
    auth_data = response.json()
    if (not 'access_token' in auth_data) or (not 'expires_in' in auth_data):
        app.logger.debug("Invalid response from AR: {}".format(auth_data))
        abort(400, description="Received invalid response from AR")
        return None
    
    # Build Token object
    from api.models.token import Token
    client_id = request.form.get('client_id')
    ar_token = Token(
        eori=client_id,
        access_token=auth_data['access_token'],
        expires=int(time.time() * 1000) + (1000*auth_data['expires_in']))
    current_app.logger.debug('Received access token with data: {}'.format(ar_token))
    
    # Insert token
    from api.util.db_handler import insert_token
    insert_error = insert_token(ar_token, current_app)
    if insert_error:
        current_app.logger.debug("Error when inserting token into DB: {}".format(insert_error))
        abort(500, description="Internal server error (DB access)")

    # TEST
    #from api.util.db_handler import get_token_by_eori
    #t = get_token_by_eori("EU.EORI.DEMARKETPLACE", current_app)
    #current_app.logger.info("Get by EORI: {}".format(t))
    
    return auth_data, 200
    
