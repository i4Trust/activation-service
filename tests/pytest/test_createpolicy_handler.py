import pytest
import time, copy
from api import app

from tests.pytest.util.config_handler import load_config
from tests.pytest.util.token_handler import build_signed_jwt

from api.util.createpolicy_handler import extract_access_token
from api.util.createpolicy_handler import get_ar_token
from api.util.createpolicy_handler import check_create_delegation_evidence
from api.util.createpolicy_handler import create_delegation_evidence

from api.exceptions.create_policy_exception import CreatePolicyException

# Get AS config
as_config = load_config("tests/config/as.yml", app)
app.config['as'] = as_config

# Dummy access token
ACCESS_TOKEN = 'gfgarhgrfha'

# Token endpoint
TOKEN_ENDPOINT = as_config['ar']['token']

# Policy endpoint
POLICY_ENDPOINT = as_config['ar']['policy']

# Delegation endpoint
DELEGATION_ENDPOINT = as_config['ar']['delegation']

# Client EORI
CLIENT_EORI = 'EU.EORI.DEMARKETPLACE'

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

# Tests for function extract_access_token(request)
class TestExtractAccessToken:

    @pytest.fixture
    def mock_request_ok(self, mocker):
        def headers_get(attr):
            if attr == "Authorization": return "Bearer " + ACCESS_TOKEN
            else: return None
        request = mocker.Mock()
        request.headers.get.side_effect = headers_get
        return request

    @pytest.fixture
    def mock_request_empty_token(self, mocker):
        def headers_get(attr):
            if attr == "Authorization": return "Bearer "
            else: return None
        request = mocker.Mock()
        request.headers.get.side_effect = headers_get
        return request

    @pytest.fixture
    def mock_request_invalid_header(self, mocker):
        def headers_get(attr):
            if attr == "Authorization": return "Bearer " + ACCESS_TOKEN + " invalid"
            else: return None
        request = mocker.Mock()
        request.headers.get.side_effect = headers_get
        return request

    @pytest.fixture
    def mock_request_no_bearer(self, mocker):
        def headers_get(attr):
            if attr == "Authorization": return ACCESS_TOKEN
            else: return None
        request = mocker.Mock()
        request.headers.get.side_effect = headers_get
        return request

    @pytest.fixture
    def mock_request_no_headers(self, mocker):
        def headers_get(attr):
            return None
        request = mocker.Mock()
        request.headers.get.side_effect = headers_get
        return request

    @pytest.mark.ok
    @pytest.mark.it('should successfully extract access token')
    def test_extract_ok(self, mock_request_ok):
        
        # Call function with request mock
        token = extract_access_token(mock_request_ok)
        assert token == ACCESS_TOKEN, "should return correct access token"

    @pytest.mark.failure
    @pytest.mark.it('should fail due to missing Authorization header')
    def test_extract_missing_header(self, mock_request_no_headers):
        
        # Call function with request mock
        with pytest.raises(CreatePolicyException, match=r'Missing Authorization header'):
            token = extract_access_token(mock_request_no_headers)

    @pytest.mark.failure
    @pytest.mark.it('should fail due to missing Bearer in Authorization header')
    def test_extract_missing_bearer(self, mock_request_no_bearer):
        
        # Call function with request mock
        with pytest.raises(CreatePolicyException, match=r'Invalid Authorization header'):
            token = extract_access_token(mock_request_no_bearer)

    @pytest.mark.failure
    @pytest.mark.it('should fail due to invalid Authorization header')
    def test_extract_invalid_header(self, mock_request_invalid_header):
        
        # Call function with request mock
        with pytest.raises(CreatePolicyException, match=r'Invalid Authorization header'):
            token = extract_access_token(mock_request_invalid_header)

    @pytest.mark.failure
    @pytest.mark.it('should fail due to empty_token')
    def test_extract_empty_token(self, mock_request_empty_token):
        
        # Call function with request mock
        with pytest.raises(CreatePolicyException, match=r'Invalid Authorization header, empty token'):
            token = extract_access_token(mock_request_empty_token)


# Tests for get_ar_token(conf)
class TestGetARToken:

    @pytest.fixture
    def mock_post_token_ok(self, requests_mock):
        return requests_mock.post(TOKEN_ENDPOINT,
                                  json={
                                      'access_token': ACCESS_TOKEN,
                                      'expires_in': 3600,
                                      'token_type': "Bearer"
                                  })

    @pytest.mark.ok
    @pytest.mark.it('should successfully obtain access token')
    def test_token_ok(self, mock_post_token_ok):

        # Call function
        access_token = get_ar_token(as_config)

        # Asserts
        assert access_token == ACCESS_TOKEN, "should return correct access_token"

# Tests for check_create_delegation_evidence(conf, eori, access_token)
class TestCheckCreateDelegationEvidence:

    @pytest.fixture
    def mock_post_delegation_ok(self, requests_mock):
        payload = TEMPLATE_DELEGATION_EVIDENCE
        delegation_token = build_signed_jwt(as_config, payload['delegationEvidence'], "delegationEvidence", CLIENT_EORI)
        return requests_mock.post(DELEGATION_ENDPOINT,
                                  json={
                                      'delegation_token': delegation_token
                                  })

    @pytest.fixture
    def mock_post_no_delegation_evidence(self, requests_mock):
        payload = TEMPLATE_DELEGATION_EVIDENCE
        delegation_token = build_signed_jwt(as_config, payload['delegationEvidence'], "delegationRequest", CLIENT_EORI)
        return requests_mock.post(DELEGATION_ENDPOINT,
                                  json={
                                      'delegation_token': delegation_token
                                  })

    @pytest.fixture
    def mock_post_no_policy_sets(self, requests_mock):
        payload = copy.deepcopy(TEMPLATE_DELEGATION_EVIDENCE)
        payload['delegationEvidence'].pop('policySets', None)
        delegation_token = build_signed_jwt(as_config, payload['delegationEvidence'], "delegationEvidence", CLIENT_EORI)
        return requests_mock.post(DELEGATION_ENDPOINT,
                                  json={
                                      'delegation_token': delegation_token
                                  })

    @pytest.fixture
    def mock_post_empty_policies(self, requests_mock):
        payload = copy.deepcopy(TEMPLATE_DELEGATION_EVIDENCE)
        payload['delegationEvidence']['policySets'][0]['policies'] = []
        delegation_token = build_signed_jwt(as_config, payload['delegationEvidence'], "delegationEvidence", CLIENT_EORI)
        return requests_mock.post(DELEGATION_ENDPOINT,
                                  json={
                                      'delegation_token': delegation_token
                                  })

    @pytest.fixture
    def mock_post_no_post_action(self, requests_mock):
        payload = copy.deepcopy(TEMPLATE_DELEGATION_EVIDENCE)
        payload['delegationEvidence']['policySets'][0]['policies'][0]['target']['actions'] = ["GET","PATCH"]
        delegation_token = build_signed_jwt(as_config, payload['delegationEvidence'], "delegationEvidence", CLIENT_EORI)
        return requests_mock.post(DELEGATION_ENDPOINT,
                                  json={
                                      'delegation_token': delegation_token
                                  })

    @pytest.fixture
    def mock_post_no_permit_rule(self, requests_mock):
        payload = copy.deepcopy(TEMPLATE_DELEGATION_EVIDENCE)
        payload['delegationEvidence']['policySets'][0]['policies'][0]['rules'][0] = {
            'effect': "Deny"
        }
        delegation_token = build_signed_jwt(as_config, payload['delegationEvidence'], "delegationEvidence", CLIENT_EORI)
        return requests_mock.post(DELEGATION_ENDPOINT,
                                  json={
                                      'delegation_token': delegation_token
                                  })

    @pytest.fixture
    def mock_post_no_delegation_token(self, requests_mock):
        return requests_mock.post(DELEGATION_ENDPOINT,
                                  json={
                                      'empty_token': "EMPTY"
                                  })

    @pytest.mark.ok
    @pytest.mark.it('should accept and throw no exception')
    def test_check_ok(self, mock_post_delegation_ok):

        # Call function
        try:
            check_create_delegation_evidence(as_config, CLIENT_EORI, ACCESS_TOKEN)
        except Exception as ex:
            pytest.fail("should throw no exception: {}".format(ex))

    @pytest.mark.failure
    @pytest.mark.it('should throw exception about missing delegation_token')
    def test_check_missing_token(self, mock_post_no_delegation_token):

        # Call function
        with pytest.raises(CreatePolicyException, match=r'AR was not providing valid response') as ex:
            check_create_delegation_evidence(as_config, CLIENT_EORI, ACCESS_TOKEN)

    @pytest.mark.failure
    @pytest.mark.it('should throw exception about missing delegationEvidence')
    def test_check_missing_delegation_evidence(self, mock_post_no_delegation_evidence):

        # Call function
        with pytest.raises(CreatePolicyException, match=r'AR did not provide valid delegationEvidence to create policies.') as ex:
            check_create_delegation_evidence(as_config, CLIENT_EORI, ACCESS_TOKEN)

        assert "Missing 'delegationEvidence' object" in ex.value.internal_msg, "should report correct error message"

    @pytest.mark.failure
    @pytest.mark.it('should throw exception about missing policySets')
    def test_check_no_policy_sets(self, mock_post_no_policy_sets):

        # Call function
        with pytest.raises(CreatePolicyException, match=r'AR did not provide valid delegationEvidence to create policies.') as ex:
            check_create_delegation_evidence(as_config, CLIENT_EORI, ACCESS_TOKEN)

        assert "Missing 'policySets'" in ex.value.internal_msg, "should report correct error message"

    @pytest.mark.failure
    @pytest.mark.it('should throw exception about empty policies')
    def test_check_empty_policies(self, mock_post_empty_policies):

        # Call function
        with pytest.raises(CreatePolicyException, match=r'AR did not provide valid delegationEvidence to create policies.') as ex:
            check_create_delegation_evidence(as_config, CLIENT_EORI, ACCESS_TOKEN)

        assert "Empty 'policies'" in ex.value.internal_msg, "should report correct error message"

    @pytest.mark.failure
    @pytest.mark.it('should throw exception about missing POST action')
    def test_check_missing_post_action(self, mock_post_no_post_action):

        # Call function
        with pytest.raises(CreatePolicyException, match=r'AR did not provide valid delegationEvidence to create policies.') as ex:
            check_create_delegation_evidence(as_config, CLIENT_EORI, ACCESS_TOKEN)

        assert "'actions' is missing 'POST'" in ex.value.internal_msg, "should report correct error message"

    @pytest.mark.failure
    @pytest.mark.it('should throw exception about missing Permit rule')
    def test_check_missing_permit_rule(self, mock_post_no_permit_rule):

        # Call function
        with pytest.raises(CreatePolicyException, match=r'AR did not provide valid delegationEvidence to create policies.') as ex:
            check_create_delegation_evidence(as_config, CLIENT_EORI, ACCESS_TOKEN)

        assert "Wrong effect: Deny != Permit" in ex.value.internal_msg, "should report correct error message"

# Test create_delegation_evidence(conf, access_token, request)
class TestCreateDelegationEvidence:

    @pytest.fixture
    def mock_post_policy_ok(self, requests_mock):
        # Re-use template also for simulation of policy vreation
        payload = TEMPLATE_DELEGATION_EVIDENCE
        policy_token = build_signed_jwt(as_config, payload['delegationEvidence'], "delegationEvidence", CLIENT_EORI)
        return requests_mock.post(POLICY_ENDPOINT,
                                  json={
                                      'policy_token': policy_token
                                  })

    @pytest.fixture
    def mock_post_policy_empty_response(self, requests_mock):
        return requests_mock.post(POLICY_ENDPOINT,
                                  json={ })

    @pytest.fixture
    def mock_request_ok(self, mocker):
        request = mocker.Mock()
        request.json = TEMPLATE_DELEGATION_EVIDENCE
        return request

    @pytest.fixture
    def mock_request_no_payload(self, mocker):
        request = mocker.Mock()
        request.json = None
        return request

    @pytest.mark.ok
    @pytest.mark.it('should successfully create policy and return policy_token')
    def test_policy_ok(self, mock_post_policy_ok, mock_request_ok):

        # Call function
        try:
            response = create_delegation_evidence(as_config, ACCESS_TOKEN, mock_request_ok)
        except Exception as ex:
            pytest.fail("should throw no exception: {}".format(ex))

        # Asserts
        assert 'policy_token' in response, "response should contain policy_token"

    @pytest.mark.ok
    @pytest.mark.it('should successfully create policy and return empty response')
    def test_policy_ok_empty_response(self, mock_post_policy_empty_response, mock_request_ok):

        # Call function
        try:
            response = create_delegation_evidence(as_config, ACCESS_TOKEN, mock_request_ok)
        except Exception as ex:
            pytest.fail("should throw no exception: {}".format(ex))

        # Asserts
        assert not response, "response should be empty"

    @pytest.mark.failure
    @pytest.mark.it('should fail due to missing payload')
    def test_policy_missing_payload(self, mock_request_no_payload):

        # Call function
        with pytest.raises(CreatePolicyException, match=r'Missing payload in /createpolicy request') as ex:
            response = create_delegation_evidence(as_config, ACCESS_TOKEN, mock_request_no_payload)
        
    
