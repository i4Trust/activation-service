from flask import Blueprint, Response, jsonify
from werkzeug.exceptions import HTTPException, InternalServerError

# Blueprint
errors = Blueprint("errors", __name__)

# Handler for HTTP exceptions
@errors.app_errorhandler(HTTPException)
def http_error(error):
    return {
        'code': error.code,
        'message': error.name,
        'description': error.description,
    }, error.code

# Handler for any other kind of exceptions
@errors.app_errorhandler(Exception)
def server_error(error):
    return {
        'code': 500,
        'message': 'Internal server error: {}'.format(error),
    }, 500
