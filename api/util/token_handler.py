import requests
from requests.exceptions import HTTPError

# Proxy the request to AR
def proxy_request(url, form_data, headers, app):

    app.logger.debug("Proxy request to AR...")
    app.logger.debug("...sending request to {}".format(url))
    app.logger.debug("...form parameters: {}".format(form_data))

    response = requests.post(url, data=form_data, headers=headers)
    try:
        response.raise_for_status()
    except HTTPError as e:
        app.logger.debug('Error retrieving token from AR: {}'.format(e))
        if response.json():
            app.logger.debug('JSON response: {}'.format(response.json()))
        message = "Error retrieving token from AR: {}".format(e)
        if response.json():
            message += ", received JSON response: {}".format(response.json())
        abort(400, description=message)
        return None
    app.logger.debug('...received response')
    
    # Return response
    return response

# Forward token request to actual AR
def forward_token(request, app, abort):
    app.logger.debug('Forwarding request to /token endpoint of AR')
    
    # Load config
    conf = app.config['as']

    # Check for form parameters
    client_id = ""
    grant_type = ""
    scope = ""
    client_assertion_type = ""
    client_assertion = ""
    try:
        client_id = request.form.get('client_id')
        if not client_id:
            raise Exception("Missing client_id")
        grant_type = request.form.get('grant_type')
        if not grant_type:
            raise Exception("Missing grant_type")
        scope = request.form.get('scope')
        if not scope:
            raise Exception("Missing scope")
        client_assertion_type = request.form.get('client_assertion_type')
        if not client_assertion_type:
            raise Exception("Missing client_assertion_type")
        client_assertion = request.form.get('client_assertion')
        if not client_assertion:
            raise Exception("Missing client_assertion")
    except Exception as ex:
        app.logger.debug('Missing form parameters: {}'.format(ex))
        abort(400)
        return None

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
