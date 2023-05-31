from flask import Flask, Response, jsonify, request

from .errors import errors
from .token import token_endpoint
from .createpolicy import createpolicy_endpoint
from .issuer import issuer_endpoint

app = Flask(__name__)

# Register error handler
app.register_blueprint(errors)

# Register routes
app.register_blueprint(createpolicy_endpoint)
app.register_blueprint(token_endpoint)
app.register_blueprint(issuer_endpoint)

# Default 500 error handler
@app.errorhandler(500)
def catch_server_errors(e):
    app.logger.error("Internal error: {}".format(e))
    return "Internal server error", 500
    #abort(500, "Internal server error")

# Register health endpoint
@app.route("/health")
def health():
    return Response("OK", status=200)
