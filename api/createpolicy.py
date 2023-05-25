from flask import Blueprint, Response, current_app, abort, request

from api.util.createpolicy_handler import extract_access_token, get_ar_token, check_create_delegation_evidence, create_delegation_evidence

from api.exceptions.create_policy_exception import CreatePolicyException

# Blueprint
createpolicy_endpoint = Blueprint("createpolicy_endpoint", __name__)

# POST /createpolicy
@createpolicy_endpoint.route("/createpolicy", methods = ['POST'])
def index():
    current_app.logger.debug('Received request at /createpolicy endpoint')
    
    # Load config
    conf = current_app.config['as']

    # Get access token from request header
    token = None
    try:
        request_token = extract_access_token(request)
    except CreatePolicyException as cpe:
        current_app.logger.debug("Error when extracting access token from authorization header: {}. Returning status {}.".format(cpe.internal_message, cpe.status_code))
        abort(cpe.status_code, cpe.message)
    except Exception as ex:
        current_app.logger.error("Internal error: {}".format(ex))
        abort(500, "Internal error")
    current_app.logger.debug("...received access token in incoming request: {}".format(request_token))

    # Get token DB entry
    current_app.logger.debug("Compare token at database...")
    db_token = None
    try:
        from api.util.db_handler import get_token_by_token
        db_token = get_token_by_token(request_token, current_app)
    except Exception as exd:
        current_app.logger.error("Internal error when accessing DB: {}".format(exd))
        abort(500, "Internal error")
    if not db_token:
        current_app.logger.debug("Token could not be found in DB, probably no valid token provided by request")
        abort(400, "No valid token has been provided")
    current_app.logger.debug("...provided token is valid")
    
    # Get token from AR
    current_app.logger.debug("AS requests access_token at AR...")
    try:
        access_token = get_ar_token(conf)
    except CreatePolicyException as cpet:
        current_app.logger.error("Error when AS is obtaining access token from AR: {}. Returning status {}.".format(cpet.internal_message, cpet.status_code))
        abort(cpet.status_code, cpet.message)
    except Exception as ext:
        current_app.logger.error("Internal error: {}".format(ext))
        abort(500, "Internal error")
    current_app.logger.debug("...received access token from AR: {}".format(access_token))
    
    # Check delegationEvidence allowing to create policy
    current_app.logger.debug('Check at AR if sender is allowed to create policies...')
    try:
        check_create_delegation_evidence(conf, db_token.eori, access_token)
    except CreatePolicyException as cpede:
        current_app.logger.debug("Necessary delegationEvidence could not be retrieved from AR: {}. Returning status: {}.".format(cpede.internal_message, cpede.status_code))
        abort(cped.status_code, cpede.message)
    except Exception as exde:
        current_app.logger.error("Internal error: {}".format(exde))
        abort(500, "Internal error")
    current_app.logger.debug("... necessary delegationEvidence has been found, creating policies is allowed.")
        
    # Create policy
    current_app.logger.debug("Create policy from sender at AR...")
    try:
        policy_response = create_delegation_evidence(conf, access_token, request)
        if policy_response:
            current_app.logger.debug("... policy created, AR returned policy_token: {}".format(policy_response))
            return policy_response, 200
        else:
            current_app.logger.debug("... policy created, AR returned empty response")
            return '', 200
    except CreatePolicyException as cpep:
        current_app.logger.error("Error when AS is creating policy at AR: {}. Returning status {}.".format(cpep.internal_message, cpep.status_code))
        abort(cpep.status_code, cpep.message)
    except Exception as exp:
        current_app.logger.error("Internal error: {}".format(exp))
        abort(500, "Internal error")
    
