import pytest
from api import app
from tests.pytest.util.config_handler import load_config
from api.util.apikey_handler import check_api_key

from api.exceptions.apikey_exception import ApiKeyException

# Get AS config
as_config = load_config("tests/config/as.yml", app)
app.config['as'] = as_config

@pytest.fixture
def mock_request_apikey_ok_ishare(mocker):
    def headers_get(attr):
        if attr == "AS-API-KEY": return "31f5247c-17e5-4969-95f0-928c8ab16504"
        else: return None
    request = mocker.Mock()
    request.headers.get.side_effect = headers_get
    return request

@pytest.fixture
def mock_request_apikey_ok_issuer(mocker):
    def headers_get(attr):
        if attr == "AS-API-KEY": return "eb4675ed-860e-4de1-a9a7-3e2e4356d08d"
        else: return None
    request = mocker.Mock()
    request.headers.get.side_effect = headers_get
    return request

@pytest.fixture
def mock_request_apikey_invalid_header(mocker):
    def headers_get(attr):
        if attr == "AS-API-KEY": return "abc"
        else: return None
    request = mocker.Mock()
    request.headers.get.side_effect = headers_get
    return request

@pytest.fixture
def mock_request_apikey_no_headers(mocker):
    def headers_get(attr):
        return None
    request = mocker.Mock()
    request.headers.get.side_effect = headers_get
    return request

@pytest.mark.ok
@pytest.mark.it('should successfully check API-Key for iSHARE flow')
def test_apikey_ok_ishare(mock_request_apikey_ok_ishare):
        
    # Call function with request mock
    try:
        check_api_key(mock_request_apikey_ok_ishare, "AS-API-KEY", "31f5247c-17e5-4969-95f0-928c8ab16504")
    except Exception as ex:
        pytest.fail("should throw no exception: {}".format(ex))

@pytest.mark.ok
@pytest.mark.it('should successfully check API-Key for TIL flow')
def test_apikey_ok_issuer(mock_request_apikey_ok_issuer):
        
    # Call function with request mock
    try:
        check_api_key(mock_request_apikey_ok_issuer, "AS-API-KEY", "eb4675ed-860e-4de1-a9a7-3e2e4356d08d")
    except Exception as ex:
        pytest.fail("should throw no exception: {}".format(ex))
    
@pytest.mark.failure
@pytest.mark.it('should throw exception about missing API-Key header')
def test_check_missing_header(mock_request_apikey_no_headers):
    
    # Call function
    with pytest.raises(ApiKeyException, match=r'Missing API-Key header') as ex:
        check_api_key(mock_request_apikey_no_headers, "AS-API-KEY", "eb4675ed-860e-4de1-a9a7-3e2e4356d08d")

@pytest.mark.failure
@pytest.mark.it('should throw exception about invalid API-Key')
def test_check_invalid_header(mock_request_apikey_invalid_header):
    
    # Call function
    with pytest.raises(ApiKeyException, match=r'Invalid API-Key') as ex:
        check_api_key(mock_request_apikey_invalid_header, "AS-API-KEY", "eb4675ed-860e-4de1-a9a7-3e2e4356d08d")
