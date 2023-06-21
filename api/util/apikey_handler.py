from api.exceptions.apikey_exception import ApiKeyException

# Check API-Key in request
def check_api_key(request, header_name, api_key):

    # Get header
    auth_header = request.headers.get(header_name)
    if not auth_header:
        message = "Missing API-Key header"
        internal_msg = message + " ('{}')".format(header_name)
        raise ApiKeyException(message, internal_msg, 400)

    # Check API-Keys
    if auth_header != api_key:
        msg = "Invalid API-Key"
        int_msg = msg + " (provided '{}' != expected '{}')".format(auth_header, api_key)
        raise ApiKeyException(msg, int_msg, 400)
        
    return True
