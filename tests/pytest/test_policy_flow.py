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
    if os.environ.get('AS_DATABASE_URI'):
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('AS_DATABASE_URI')
    else:
        db_conf = as_config['db']
        basedir = os.path.abspath(os.path.dirname(__file__))
        dbpath = os.path.join(basedir, db_conf['useFile']['filename'])
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

# Form parameters
REQ_FORM = {
    'client_id': CLIENT_EORI,
    'grant_type': 'client_credentials',
    'scope': 'iSHARE',
    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    'client_assertion': 'dfggrghaerhahahhahp'
}

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
def mock_post_token_ok(requests_mock):
    return requests_mock.post(TOKEN_ENDPOINT,
                              json={
                                  'access_token': ACCESS_TOKEN,
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
@pytest.mark.it('should successfully obtain a token and create the policy')
def test_policy_flow_ok(client, mock_post_token_ok, mock_post_delegation_ok, mock_post_policy_ok, clean_db):

    # Invoke request for /token
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
        assert db_token.eori == CLIENT_EORI, "DB entry should have correct EORI"
        assert db_token.access_token == ACCESS_TOKEN, "DB entry should have correct access token"

    # Get access token
    access_token = response.json['access_token']

    # Invoke request for /createpolicy
    headers = {
        'Authorization': "Bearer " + ACCESS_TOKEN
    }
    response = client.post("/createpolicy", json=TEMPLATE_POLICY_CREATE, headers=headers)
    
    # Asserts on response
    assert mock_post_token_ok.called
    assert mock_post_token_ok.call_count == 2
    assert mock_post_delegation_ok.called
    assert mock_post_delegation_ok.call_count == 1
    assert mock_post_policy_ok.called
    assert mock_post_policy_ok.call_count == 1
    assert 'policy_token' in response.json, 'Response should contain policy_token'
    
