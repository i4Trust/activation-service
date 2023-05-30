from api.models.token import Token
import time

from api.exceptions.database_exception import DatabaseException

# Insert token
def insert_token(token, db):
    
    try:
        db.session.add(token) #TODO: check for existing token and delete it beforehand?
        db.session.commit()
        return None
    except Exception as error:
        db.session.rollback()
        message = "Internal server error when accessing DB"
        internal_message = "Error inserting token: {}".format(error)
        raise DatabaseException(message, internal_message, 500)

# Get token by EORI
def get_token_by_eori(eori, db):
    
    try:
        # First clean entries
        deleted = clean_token(db)

        # Perform query
        token = Token.query.filter_by(eori=eori).first()
        return {
            'token': token,
            'deleted': deleted
        }
    
    except DatabaseException as dex:
        raise dex
    except Exception as error:
        db.session.rollback()
        message = "Internal server error when accessing DB"
        internal_message = "Error retrieving token: {}".format(error)
        raise DatabaseException(message, internal_message, 500)

# Get token by access_token
def get_token_by_token(token, db):
    
    try:
        # First clean entries
        deleted = clean_token(db)
    
        # Perform query
        r_token = Token.query.filter_by(access_token=token).first()
        return {
            'token': r_token,
            'deleted': deleted
        }

    except DatabaseException as dex:
        raise dex
    except Exception as error:
        db.session.rollback()
        message = "Internal server error when accessing DB"
        internal_message = "Error retrieving token: {}".format(error)
        raise DatabaseException(message, internal_message, 500)

# Clean expired tokens
def clean_token(db):
    
    try:
        deleted = Token.query.filter(Token.expires<int(time.time() * 1000)).delete()
        db.session.commit()
        return deleted
    except Exception as error:
        db.session.rollback()
        message = "Internal server error when accessing DB"
        internal_message = "Error deleting tokens: {}".format(error)
        raise DatabaseException(message, internal_message, 500)

