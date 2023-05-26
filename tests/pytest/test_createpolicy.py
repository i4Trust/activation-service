import pytest
import os, time
from api import app
from flask_sqlalchemy import SQLAlchemy

from tests.pytest.util.config_handler import load_config
from tests.pytest.util.token_handler import build_signed_jwt

# Get AS config
as_config = load_config("tests/config/as.yml", app)
app.config['as'] = as_config

# Database
db = None
if not 'db' in app.config:
    db_conf = as_config['db']
    basedir = os.path.abspath(os.path.dirname(__file__))
    dbpath = os.path.join(basedir, db_conf['useFile'])
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + dbpath
    db = SQLAlchemy(app)
    app.config['db'] = db
else:
    db = app.config['db']

# Token endpoint
TOKEN_ENDPOINT = as_config['ar']['token']

# Policy endpoint
POLICY_ENDPOINT = as_config['ar']['policy']

# Delegation endpoint
DELEGATION_ENDPOINT = as_config['ar']['delegation']

# Dummy access token
ACCESS_TOKEN = 'gfgarhgrfha'

# Client EORI
CLIENT_EORI = 'EU.EORI.DEMARKETPLACE'

# Policy access subject
ACCESS_SUBJECT_EORI = "EU.EORI.DECONSUMERONE"

# delegationEvidence template for policy to create
TEMPLATE_POLICY_CREATE = {
    'delegationEvidence': {
        'notBefore': int(str(time.time()).split('.')[0]),
	'notOnOrAfter': int(str(time.time()).split('.')[0]) + 60000,
        'policyIssuer': as_config['client']['id'],
        'target': {
            'accessSubject': ACCESS_SUBJECT_EORI
        },
        'policySets': [
            {
                'policies': [
                    {
                        'target': {
                            'resource': {
                                'type': "EntityType",
                                'identifiers': ["id1"],
                                'attributes': ["attr1", "attr2"]
                            },
                            'actions': ["POST","GET"]
                        },
                        'rules': [
                            {
                                'effect': "Permit"
                            }
                        ]
                    }
                ]
            }
        ]
    }
}

# delegationEvidence template for client AR access
TEMPLATE_DELEGATION_EVIDENCE = {
    'delegationEvidence': {
        'notBefore': int(str(time.time()).split('.')[0]),
	'notOnOrAfter': int(str(time.time()).split('.')[0]) + 60000,
        'policyIssuer': as_config['client']['id'],
        'target': {
            'accessSubject': CLIENT_EORI
        },
        'policySets': [
            {
                'policies': [
                    {
                        'target': {
                            'resource': {
                                'type': "delegationEvidence",
                                'identifiers': ["*"],
                                'attributes': ["*"]
                            },
                            'actions': ["POST"]
                        },
                        'rules': [
                            {
                                'effect': "Permit"
                            }
                        ]
                    }
                ]
            }
        ]
    }
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
def insert_token():
    with app.app_context():
        from api.models import token
        db.drop_all()
        db.create_all()
        ar_token = token.Token(
            eori=CLIENT_EORI,
            access_token=ACCESS_TOKEN,
            expires=int(time.time() * 1000) + 3600)
        from api.util.db_handler import insert_token
        insert_token(ar_token, db)

@pytest.fixture
def mock_post_token_ok(requests_mock):
    return requests_mock.post(TOKEN_ENDPOINT,
                              json={
                                  'access_token': ACCESS_TOKEN+"xyz",
                                  'expires_in': 3600,
                                  'token_type': "Bearer"
                              })

@pytest.fixture
def mock_post_delegation_ok(requests_mock):
    payload = TEMPLATE_DELEGATION_EVIDENCE
    delegation_token = build_signed_jwt(as_config, payload['delegationEvidence'], "delegationEvidence", CLIENT_EORI)
    return requests_mock.post(DELEGATION_ENDPOINT,
                              json={
                                  'delegation_token': delegation_token
                              })

@pytest.fixture
def mock_post_policy_ok(requests_mock):
    payload = TEMPLATE_POLICY_CREATE
    policy_token = build_signed_jwt(as_config, payload['delegationEvidence'], "delegationEvidence", CLIENT_EORI)
    return requests_mock.post(POLICY_ENDPOINT,
                              json={
                                  'policy_token': policy_token
                              })

@pytest.mark.ok
@pytest.mark.it('should successfully obtain access token')
def test_policy_ok(client, mock_post_token_ok, mock_post_delegation_ok, mock_post_policy_ok, insert_token):

    # Invoke request
    headers = {
        'Authorization': "Bearer " + ACCESS_TOKEN
    }
    response = client.post("/createpolicy", json=TEMPLATE_POLICY_CREATE, headers=headers)
    
    # Asserts on response
    assert mock_post_token_ok.called
    assert mock_post_token_ok.call_count == 1
    assert mock_post_delegation_ok.called
    assert mock_post_delegation_ok.call_count == 1
    assert mock_post_policy_ok.called
    assert mock_post_policy_ok.call_count == 1
    assert 'policy_token' in response.json, 'Response should contain policy_token'

@pytest.mark.failure
@pytest.mark.it('should fail due to invalid access_token')
def test_policy_invalid_access_token(client, mock_post_token_ok, mock_post_delegation_ok, mock_post_policy_ok, insert_token):

    # Invoke request
    headers = {
        'Authorization': "Bearer " + ACCESS_TOKEN+"gsrfghhsh"
    }
    response = client.post("/createpolicy", json=TEMPLATE_POLICY_CREATE, headers=headers)
    
    # Asserts on response
    assert not mock_post_token_ok.called
    assert not mock_post_delegation_ok.called
    assert not mock_post_policy_ok.called
    assert response.status_code == 400, "should return code 400"
    assert "No valid token has been provided" in response.json['description'], "should return correct error message"


