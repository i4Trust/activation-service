import requests
from requests.exceptions import HTTPError

from api.exceptions.token_exception import TokenException

# Proxy the request to AR
def proxy_request(url, form_data, headers, app):

    app.logger.debug("Proxy request to AR...")
    app.logger.debug("...sending request to {}".format(url))
    app.logger.debug("...form parameters: {}".format(form_data))

    response = requests.post(url, data=form_data, headers=headers)
    try:
        response.raise_for_status()
    except HTTPError as e:
        message = "Error when token request was forwarded to AR"
        internal_message = 'Error retrieving token from AR: {}'.format(e)
        if response.json():
            internal_message += '. JSON response: {}'.format(response.json())
        raise TokenException(message, internal_message, 400)
    except Exception as ex:
        message = "Internal server error"
        internal_message = "Internal error when forwarding request to AR: {}".format(ex)
        raise TokenException(message, internal_message, 500)
    
    app.logger.debug('...received response')
    
    # Return response
    return response

# Forward token request to actual AR
def forward_token(request, app):
    app.logger.debug('Forwarding request to /token endpoint of AR')
    
    # Load config
    conf = app.config['as']

    # Check for form parameters
    client_id = request.form.get('client_id')
    if not client_id:
        message = 'Invalid form parameters: {}'.format("Missing client_id")
        raise TokenException(message, None, 400)
    grant_type = request.form.get('grant_type')
    if not grant_type:
        message = 'Invalid form parameters: {}'.format("Missing grant_type")
        raise TokenException(message, None, 400)
    scope = request.form.get('scope')
    if not scope:
        message = 'Invalid form parameters: {}'.format("Missing scope")
        raise TokenException(message, None, 400)
    client_assertion_type = request.form.get('client_assertion_type')
    if not client_assertion_type:
        message = 'Invalid form parameters: {}'.format("Missing client_assertion_type")
        raise TokenException(message, None, 400)
    client_assertion = request.form.get('client_assertion')
    if not client_assertion:
        message = 'Invalid form parameters: {}'.format("Missing client_assertion")
        raise TokenException(message, None, 400)
    
    # Proxy request to AR /token endpoint
    url = conf['ar']['token']
    form_data = {
        'grant_type': grant_type,
        'scope': scope,
        'client_id': client_id,
        'client_assertion_type': client_assertion_type,
        'client_assertion': client_assertion
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    # Proxy request
    return proxy_request(url, form_data, headers, app)
