const chai = require("chai");
const sinon = require("sinon");
const expect = chai.expect;
const faker = require("faker");
const decache = require('decache');
const fetch = require('node-fetch');
const fs = require('fs');

var cert = require('../../util/cert.js');
var config = require('../../config.js');
const createPolicyHelper = require("../../activation/createPolicyHelper");

config.key = fs.readFileSync("./test/activation/provider.key.pem");
config.crt = fs.readFileSync("./test/activation/provider.ca-chain.cert.pem");
cert.initCertChain();
const chain = cert.chain;

describe("createPolicyHelper.getToken", () => {

    let fetchStub;

    const token = "fhsjjahreha";

    afterEach(() => {
	fetchStub.restore();
    });

    it("should get token from AR", async () => {

	// Stub fetch to AR
	fetchStub = sinon.stub(fetch, "Promise")
	    .returns(Promise.resolve({
		status: 200,
		json: () => {
		    return {
			access_token: token
		    };
		}
	    }));
	
	const token_result = await createPolicyHelper.getToken(chain);

	expect(fetchStub.calledOnce, "Method fetch should be called once").to.be.true;
	expect(token_result.err, "There should be no error").to.equal(null);
	expect(token_result.access_token, "Should return correct access_token").to.equal(token);
	
    });

    it("should fail when the AR returns an error when requesting the access token", async () => {
	// Stub fetch to AR
	fetchStub = sinon.stub(fetch, "Promise")
	    .returns(Promise.resolve({
		status: 401,
		text: () => {
		    return "Unauthorized";
		}
	    }));
	
	const token_result = await createPolicyHelper.getToken(chain);

	expect(fetchStub.calledOnce, "Method fetch should be called once").to.be.true;
	expect(token_result.err, "There should be the correct error messsage").to.equal("Error when retrieving token at AR: Unauthorized");
	expect(token_result.access_token, "Should return no access_token").to.equal(null);
    });

    it("should fail when AR returns no access_token", async () => {

	// Stub fetch to AR
	fetchStub = sinon.stub(fetch, "Promise")
	    .returns(Promise.resolve({
		status: 200,
		json: () => {
		    return {
			access_bacon: token
		    };
		}
	    }));
	
	const token_result = await createPolicyHelper.getToken(chain);

	expect(fetchStub.calledOnce, "Method fetch should be called once").to.be.true;
	expect(token_result.err, "There should be the correct error").to.equal('Received invalid response from AR: {"access_bacon":"fhsjjahreha"}');
	expect(token_result.access_token, "Should return no access_token").to.equal(null);
	
    });

});

describe("createPolicyHelper.checkCreateDelegationEvidence", () => {

    let fetchStub;

    const eori = "EU.EORI.DEMARKETPLACE";
    const access_token = "abcdefghj";

    afterEach(() => {
	fetchStub.restore();
    });

    // Creation of policy successful
    it("should allow policy creation", async () => {
	
	// Stub fetch to AR
	let resBody = JSON.parse(fs.readFileSync('./test/activation/delegation_token.json', 'utf8'));
	fetchStub = sinon.stub(fetch, "Promise")
	    .returns(Promise.resolve({
		status: 200,
		json: () => {
		    return resBody;
		}
	    }));
	
	const msg = await createPolicyHelper.checkCreateDelegationEvidence(eori, access_token);

	expect(fetchStub.calledOnce, "Method fetch should be called once").to.be.true;
	expect(msg, "There should be no error").to.equal(null);

    });

    // Policy creation not allowed, AR returned 404
    it("should fail, because AR returns 404", async () => {
	// Stub fetch to AR
	fetchStub = sinon.stub(fetch, "Promise")
	    .returns(Promise.resolve({
		status: 404
	    }));
	
	const msg = await createPolicyHelper.checkCreateDelegationEvidence(eori, access_token);

	expect(fetchStub.calledOnce, "Method fetch should be called once").to.be.true;
	expect(msg, "There should be the correct error message").to.equal("Policy not found at AR, Creating policies not permitted");

    });

    // Policy creation not allowed, AR returned status != 200
    it("should fail, because AR returns status != 200", async () => {
	// Stub fetch to AR
	fetchStub = sinon.stub(fetch, "Promise")
	    .returns(Promise.resolve({
		status: 500,
		text: () => {
		    return "Internal Server Error";
		}
	    }));
	
	const msg = await createPolicyHelper.checkCreateDelegationEvidence(eori, access_token);

	expect(fetchStub.calledOnce, "Method fetch should be called once").to.be.true;
	expect(msg, "There should be the correct error message").to.equal("Error when retrieving policy from AR: Internal Server Error");

    });

    // Policy creation not allowed, AR returned no delegation_token
    it("should fail, because AR returns no delegation_token", async () => {
	// Stub fetch to AR
	fetchStub = sinon.stub(fetch, "Promise")
	    .returns(Promise.resolve({
		status: 200,
		json: () => {
		    return {
			error: "No delegation_token provided"
		    };
		}
	    }));
	
	const msg = await createPolicyHelper.checkCreateDelegationEvidence(eori, access_token);

	expect(fetchStub.calledOnce, "Method fetch should be called once").to.be.true;
	expect(msg, "There should be the correct error message").to.equal('Received invalid response from AR: {"error":"No delegation_token provided"}');

    });

    // Policy creation not allowed, AR returned Deny in delegation_token
    it("should fail, because AR returns Deny in delegation_token", async () => {
	// Stub fetch to AR
	let resBody = JSON.parse(fs.readFileSync('./test/activation/delegation_token_deny.json', 'utf8'));
	fetchStub = sinon.stub(fetch, "Promise")
	    .returns(Promise.resolve({
		status: 200,
		json: () => {
		    return resBody;
		}
	    }));
	
	const msg = await createPolicyHelper.checkCreateDelegationEvidence(eori, access_token);

	expect(fetchStub.calledOnce, "Method fetch should be called once").to.be.true;
	expect(msg, "There should be the correct error message").to.equal('Creating policies not permitted');

    });
    
});


describe("createPolicyHelper.createPolicy", () => {

    let fetchStub;

    const token = "fhsjjahreha";
    const access_token = "hdjshghahg";
    const payload = {
	dummy: "Dummy"
    };

    afterEach(() => {
	fetchStub.restore();
    });

    it("should create policy at AR", async () => {

	// Stub fetch to AR
	fetchStub = sinon.stub(fetch, "Promise")
	    .returns(Promise.resolve({
		status: 200,
		json: () => {
		    return {
			policy_token: token
		    };
		}
	    }));
	
	const policy_result = await createPolicyHelper.createPolicy(access_token, payload);

	expect(fetchStub.calledOnce, "Method fetch should be called once").to.be.true;
	expect(policy_result.err, "There should be no error").to.equal(null);
	expect(policy_result.policy_token, "Should return correct policy_token").to.equal(token);
	
    });

    it("should fail when the AR responds with an error", async () => {

	// Stub fetch to AR
	fetchStub = sinon.stub(fetch, "Promise")
	    .returns(Promise.resolve({
		status: 401,
		text: () => {
		    return "Unauthorized";
		}
	    }));
	
	const policy_result = await createPolicyHelper.createPolicy(access_token, payload);

	expect(fetchStub.calledOnce, "Method fetch should be called once").to.be.true;
	expect(policy_result.err, "There should be the correct error").to.equal('Error when creating policy at AR: Unauthorized');
	expect(policy_result.policy_token, "Should return no policy_token").to.equal(null);
    });

    it("should also succeed when the AR returns no policy_token", async () => {

	// Stub fetch to AR
	fetchStub = sinon.stub(fetch, "Promise")
	    .returns(Promise.resolve({
		status: 200,
		json: () => {
		    return {
			policy_bacon: token
		    };
		}
	    }));
	
	const policy_result = await createPolicyHelper.createPolicy(access_token, payload);

	expect(fetchStub.calledOnce, "Method fetch should be called once").to.be.true;
	expect(policy_result.err, "There should be no error").to.equal(null);
	expect(policy_result.policy_token, "Should return no policy_token").to.equal(null);
    });

});
