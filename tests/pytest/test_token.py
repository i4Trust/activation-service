import pytest
import os
from api import app
from flask_sqlalchemy import SQLAlchemy

from tests.pytest.util.config_handler import load_config

# Get AS config
as_config = load_config("tests/config/as.yml", app)
app.config['as'] = as_config

# Database
db_conf = as_config['db']
basedir = os.path.abspath(os.path.dirname(__file__))
dbpath = os.path.join(basedir, db_conf['useFile'])
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + dbpath
db = SQLAlchemy(app)
app.config['db'] = db

# Token endpoint
TOKEN_ENDPOINT = as_config['ar']['token']

# Dummy access token
ACCESS_TOKEN = 'gfgarhgrfha'

# Client EORI
CLIENT_EORI = 'EU.EORI.DEMARKETPLACE'

# Form parameters
REQ_FORM = {
    'client_id': CLIENT_EORI,
    'grant_type': 'client_credentials',
    'scope': 'iSHARE',
    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    'client_assertion': 'dfggrghaerhahahhahp'
}

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

@pytest.fixture
def clean_db():
    with app.app_context():
        from api.models import token
        db.drop_all()
        db.create_all()

@pytest.fixture
def mock_post_token_ok(requests_mock):
    return requests_mock.post(TOKEN_ENDPOINT,
                              json={
                                  'access_token': ACCESS_TOKEN,
                                  'expires_in': 3600,
                                  'token_type': "Bearer"
                              })

# Test: Successful token
@pytest.mark.ok
@pytest.mark.it('should successfully obtain access token')
def test_token_ok(client, mock_post_token_ok, clean_db):

    # Invoke request
    response = client.post(TOKEN_ENDPOINT, data=REQ_FORM)
    
    # Asserts on response
    assert mock_post_token_ok.called
    assert mock_post_token_ok.call_count == 1
    assert 'access_token' in response.json, 'Response should contain access_token'
    assert response.json['access_token'] == ACCESS_TOKEN, "should have correct access token"
    assert response.json['expires_in'] == 3600, "should have correct expiration period"

    # Get and assert DB entry
    with app.app_context():
        from api.models.token import Token
        db_token = Token.query.filter_by(eori=CLIENT_EORI).first()
        print(db_token)
        assert db_token.eori == CLIENT_EORI, "DB entry should have correct EORI"
        assert db_token.access_token == ACCESS_TOKEN, "DB entry should have correct access token"

# Test: Failure missing client_id
@pytest.mark.failure
@pytest.mark.it('should fail due to missing client_id')
def test_token_ok(client, mock_post_token_ok, clean_db):

    # Remove client_id
    form = dict(REQ_FORM)
    form.pop('client_id', None)
    
    # Invoke request
    response = client.post(TOKEN_ENDPOINT, data=form)
    
    # Asserts on response
    assert response.status_code == 400, "should return code 400"
