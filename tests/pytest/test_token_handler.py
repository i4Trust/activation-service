import pytest
from api import app
from tests.pytest.util.config_handler import load_config
from api.util.token_handler import forward_token

from api.exceptions.token_exception import TokenException

# Get AS config
as_config = load_config("tests/config/as.yml", app)
app.config['as'] = as_config

# Dummy access token
ACCESS_TOKEN = 'gfgarhgrfha'

# Form parameters
REQ_FORM = {
    'client_id': 'EU.EORI.DEMARKETPLACE',
    'grant_type': 'client_credentials',
    'scope': 'iSHARE',
    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    'client_assertion': 'dfggrghaerhahahhahp'
}

@pytest.fixture
def mock_request_ok(mocker):
    def form_get(attr):
        if attr == "client_id": return REQ_FORM['client_id']
        elif attr == "grant_type": return REQ_FORM['grant_type']
        elif attr == "scope": return REQ_FORM['scope']
        elif attr == "client_assertion_type": return REQ_FORM['client_assertion_type']
        elif attr == "client_assertion": return REQ_FORM['client_assertion']
    request = mocker.Mock()
    request.form.get.side_effect = form_get
    return request

@pytest.fixture
def mock_request_missing_attr(mocker):
    def form_get(attr):
        return None
        #raise TokenException("Missing attribute", "Missing attribute", 400)
    request = mocker.Mock()
    request.form.get.side_effect = form_get
    return request

@pytest.fixture
def mock_request_missing_client_id(mocker):
    def form_get(attr):
        if attr == "client_id": return None #raise Exception("Missing client_id")
        elif attr == "grant_type": return REQ_FORM['grant_type']
        elif attr == "scope": return REQ_FORM['scope']
        elif attr == "client_assertion_type": return REQ_FORM['client_assertion_type']
        elif attr == "client_assertion": return REQ_FORM['client_assertion']
    request = mocker.Mock()
    request.form.get.side_effect = form_get
    return request

@pytest.fixture
def mock_proxy_request_ok(mocker):
    ar_response = {
        'access_token': ACCESS_TOKEN,
        'expires_in': 3600,
        'token_type': "Bearer"
    }
    return mocker.patch('api.util.token_handler.proxy_request', return_value=ar_response)

# Test: Successful token
@pytest.mark.ok
@pytest.mark.it('should successfully forward token request')
def test_forward_token_ok(mocker, mock_request_ok, mock_proxy_request_ok):

    # Mock abort function
    abort = mocker.Mock()

    # Call function
    response = forward_token(mock_request_ok, app)
    
    # Asserts
    mock_proxy_request_ok.assert_called_once()
    assert 'access_token' in response, 'Response should contain access_token'
    assert response['access_token'] == ACCESS_TOKEN
    assert response['expires_in'] == 3600

# Test: Missing attr
@pytest.mark.failure
@pytest.mark.it('should fail due to missing attr')
def test_forward_token_missing_attr(mocker, mock_request_missing_attr, mock_proxy_request_ok):

    # Mock abort function
    abort = mocker.Mock()

    # Call function
    with pytest.raises(TokenException, match=r'Missing'):
        response = forward_token(mock_request_missing_attr, app)

# Test: Missing client_id
@pytest.mark.failure
@pytest.mark.it('should fail due to missing client_id')
def test_forward_token_missing_client_id(mocker, mock_request_missing_client_id, mock_proxy_request_ok):

    # Mock abort function
    abort = mocker.Mock()

    # Call function
    with pytest.raises(TokenException, match=r'Missing client_id'):
        response = forward_token(mock_request_missing_client_id, app)
