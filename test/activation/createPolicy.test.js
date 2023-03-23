const chai = require("chai");
const sinon = require("sinon");
const expect = chai.expect;
const faker = require("faker");
const decache = require('decache');

describe("createPolicy.performCreatePolicy", () => {

    let createPolicyHelper;
    let performCreatePolicy;

    let getByTokenStub;
    let getTokenStub;
    let checkCreateDelegationEvidenceStub;
    let createPolicyStub;
    
    beforeEach(function () {
        decache("../../activation/createPolicyHelper");
	decache("../../activation/createPolicy");
	decache('../../util/databaseHelper.js');
	createPolicyHelper = require("../../activation/createPolicyHelper");
	databaseHelper = require('../../util/databaseHelper');

	// Stub for DB getByToken
	getByTokenStub = sinon.stub(databaseHelper, "getByToken")
	    .returns({
		token: {
		    eori: "EU.EORI.DECLIENT"
		}
	    });

	// Stub for getToken at AR
	getTokenStub = sinon.stub(createPolicyHelper, "getToken")
	    .returns({
		access_token: "dsgfhhashhashhbas"
	    });

	// Stub for checking at AR for policy allowing to create delegation evidence for sending party
	checkCreateDelegationEvidenceStub = sinon.stub(createPolicyHelper, "checkCreateDelegationEvidence")
	    .returns(null);

	// Stub for forwarding the creation of the policy to the AR
	createPolicyStub = sinon.stub(createPolicyHelper, "createPolicy")
	    .returns({
		err: null,
		policy_token: "XYZ"
	    });

	performCreatePolicy = require("../../activation/createPolicy");
    });

    afterEach(() => {
	getByTokenStub.restore();
	getTokenStub.restore();
	checkCreateDelegationEvidenceStub.restore();
	createPolicyStub.restore();
    });

    // Creation of policy successful
    it("should create policy", async () => {
	const req = {
	    header: (name) => {
		if(name == "Authorization") return "Bearer dsgsdsgd";
		return undefined;
	    }
	};

	const policy_response = await performCreatePolicy(req, null, null);
	expect(getByTokenStub.calledOnce, "Method getByToken should be called once").to.be.true;
	expect(getTokenStub.calledOnce, "Method getToken should be called once").to.be.true;
	expect(checkCreateDelegationEvidenceStub.calledOnce, "Method checkCreateDelegationEvidence should be called once").to.be.true;
	expect(createPolicyStub.calledOnce, "Method createPolicy should be called once").to.be.true;
	expect(policy_response.policy_token, "policy_token should be correct").to.equal("XYZ");
	expect(policy_response.err, "There should be no error").to.equal(null);
    });

    // Fail due to missing auth header
    it("should return error about missing auth header", async () => {
	const req = {
	    header: (name) => {
		if(name == "TestHeader") return "Bearer dsgsdsgd";
		return undefined;
	    }
	};

	const policy_response = await performCreatePolicy(req, null, null);
	expect(getByTokenStub.calledOnce, "Method getByToken should not be called").to.be.false;
	expect(getTokenStub.calledOnce, "Method getToken should not be called").to.be.false;
	expect(checkCreateDelegationEvidenceStub.calledOnce, "Method checkCreateDelegationEvidence should not be called").to.be.false;
	expect(createPolicyStub.calledOnce, "Method getToken should not be called").to.be.false;
	expect(policy_response).to.equal(null);
    });

    // Fail due to wrong auth header
    it("should return error about wrong auth header", async () => {
	const req = {
	    header: (name) => {
		if(name == "Authorization") return "Beerer dsgsdsgd";
		return undefined;
	    }
	};

	const policy_response = await performCreatePolicy(req, null, null);
	expect(getByTokenStub.calledOnce, "Method getByToken should not be called").to.be.false;
	expect(getTokenStub.calledOnce, "Method getToken should not be called").to.be.false;
	expect(checkCreateDelegationEvidenceStub.calledOnce, "Method checkCreateDelegationEvidence should not be called").to.be.false;
	expect(createPolicyStub.calledOnce, "Method getToken should not be called").to.be.false;
	expect(policy_response).to.equal(null);
    });
    
    
});
