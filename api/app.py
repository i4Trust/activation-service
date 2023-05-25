from flask import Flask, Response, jsonify, request

from .errors import errors
#from .versions import versions
#from .trusted_list import trusted_list
#from .parties import parties
from .token import token_endpoint
#from .trusted_issuer import trusted_issuer

app = Flask(__name__)

# Register error handler
app.register_blueprint(errors)

# Register routes
#app.register_blueprint(versions)
#app.register_blueprint(trusted_list)
#app.register_blueprint(parties)
app.register_blueprint(token_endpoint)
#app.register_blueprint(trusted_issuer)

# Register health endpoint
@app.route("/health")
def health():

    # TEST
    #from api.models.token import Token
    #token = Token(
    #    eori="EU.EORI.DEABC",
    #    access_token="dgagaggdgagg",
    #    expires=3600)
    #from flask import current_app
    #db = current_app.config['db']
    #db.session.add(token)  # Adds new User record to database
    #db.session.commit()  # Commits all changes
    
    return Response("OK", status=200)
