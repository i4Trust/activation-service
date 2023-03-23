const chai = require("chai");
const sinon = require("sinon");
const expect = chai.expect;
const faker = require("faker");
const decache = require('decache');
const fetch = require('node-fetch');
const fs = require('fs');

var cert = require('../../util/cert.js');
var config = require('../../config.js');
const tokenHelper = require("../../activation/tokenHelper");

config.key = fs.readFileSync("./test/activation/provider.key.pem");
config.crt = fs.readFileSync("./test/activation/provider.ca-chain.cert.pem");
cert.initCertChain();
const chain = cert.chain;

describe("tokenHelper.forwardToken", () => {

    let fetchStub;

    const token = "fhsjjahreha";
    const eori = "EU.EORI.DEMARKETPLACE";

    afterEach(() => {
	fetchStub.restore();
    });

    it("should get token from AR", async () => {

	const req = {
	    body: {
		dummy: "dummy",
		client_id: eori
	    }
	};
	
	// Stub fetch to AR
	fetchStub = sinon.stub(fetch, "Promise")
	    .returns(Promise.resolve({
		status: 200,
		json: () => {
		    return {
			access_token: token,
			expires_in: 3600
		    };
		}
	    }));
	
	const token_result = await tokenHelper.forwardToken(req);

	expect(fetchStub.calledOnce, "Method fetch should be called once").to.be.true;
	expect(token_result, "There should be no error").to.not.equal(null);
	expect(token_result.token.access_token, "Should return correct access_token").to.equal(token);
	expect(token_result.token.eori, "Should return correct access_token").to.equal(eori);

    });

});
