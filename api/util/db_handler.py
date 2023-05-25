from api.models.token import Token
import time

# Insert token
def insert_token(token, app):
    app.logger.debug("Inserting token: {}".format(token))
    db = app.config['db']
    try:
        db.session.add(token)
        db.session.commit()
        return None
    except Exception as error:
        db.session.rollback()
        app.logger.error("Error inserting token: {}".format(error))
        return "Error inserting token"

# Get token by EORI
def get_token_by_eori(eori, app):
    app.logger.debug("Get token by EORI: {}".format(eori))
    db = app.config['db']

    # First clean entries
    clean_err = clean_token(app)
    if clean_err:
        return None

    # Perform query
    try:
        token = Token.query.filter_by(eori=eori).first()
        return token
    except Exception as error:
        db.session.rollback()
        app.logger.error("Error retrieving token: {}".format(error))
        return None

# Get token by access_token
def get_token_by_token(token, app):
    app.logger.debug("Get token by access_token: {}".format(token[:50]))
    db = app.config['db']

    # First clean entries
    clean_err = clean_token(app)
    if clean_err:
        return None

    # Perform query
    try:
        r_token = Token.query.filter_by(access_token=token).first()
        return r_token
    except Exception as error:
        db.session.rollback()
        app.logger.error("Error retrieving token: {}".format(error))
        return None

# Clean expired tokens
def clean_token(app):
    app.logger.debug("Removing expired tokens...")
    db = app.config['db']
    try:
        deleted = Token.query.filter(Token.expires<int(time.time() * 1000)).delete()
        db.session.commit()
        app.logger.debug("... {} token entries removed.".format(deleted))
        return None
    except Exception as error:
        db.session.rollback()
        app.logger.error("Error deleting tokens: {}".format(error))
        return "Error deleting tokens"
