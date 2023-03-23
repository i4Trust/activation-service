const chai = require("chai");
const sinon = require("sinon");
const expect = chai.expect;
const faker = require("faker");
const decache = require('decache');

describe("token.performToken", () => {

    const access_token = "dfghsthsrtjhjsrtthj"
    let tokenHelper;
    let performToken;
    let database;
    let forwardStub;
    let insertStub;
    
    beforeEach(function () {
        decache("../../activation/tokenHelper");
	decache("../../activation/token");
	decache('../../util/databaseHelper.js');
	tokenHelper = require("../../activation/tokenHelper");
	databaseHelper = require('../../util/databaseHelper');

	// Stub forwarding of request and DB insert
	forwardStub = sinon.stub(tokenHelper, "forwardToken").returns(access_token);
	insertStub = sinon.stub(databaseHelper, "insertToken").returns(null);
	
    });

    afterEach(() => {
	forwardStub.restore();
	insertStub.restore();
    });
    
    it("should receive token", async () => {
	const req = {
	    body: {
		client_id: "EU.EORI.DECLIENT",
		scope: "iSHARE",
		grant_type: "client_credentials",
		client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		client_assertion: "XYZ"
	    }
	};

	performToken = require("../../activation/token");
	const returned_token = await performToken(req, null);
	expect(forwardStub.calledOnce, "Method forwardToken should be called once").to.be.true;
	expect(insertStub.calledOnce, "Method insertToken should be called once").to.be.true;
	expect(returned_token).to.equal(access_token);
    });

    it("should fail due to missing client_id", async () => {
	const req = {
	    body: {
		scope: "iSHARE",
		grant_type: "client_credentials",
		client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		client_assertion: "XYZ"
	    }
	};

	performToken = require("../../activation/token");
	const returned_token = await performToken(req, null);
	expect(forwardStub.calledOnce, "Method forwardToken should not be called").to.be.false;
	expect(insertStub.calledOnce, "Method insertToken should not be called").to.be.false;
	expect(returned_token).to.equal(null);
    });

    it("should fail due to wrong scope", async () => {
	const req = {
	    body: {
		client_id: "EU.EORI.DECLIENT",
		scope: "profile",
		grant_type: "client_credentials",
		client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		client_assertion: "XYZ"
	    }
	};

	performToken = require("../../activation/token");
	const returned_token = await performToken(req, null);
	expect(forwardStub.calledOnce, "Method forwardToken should not be called").to.be.false;
	expect(insertStub.calledOnce, "Method insertToken should not be called").to.be.false;
	expect(returned_token).to.equal(null);
    });

    it("should fail due to missing scope", async () => {
	const req = {
	    body: {
		client_id: "EU.EORI.DECLIENT",
		grant_type: "client_credentials",
		client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		client_assertion: "XYZ"
	    }
	};

	performToken = require("../../activation/token");
	const returned_token = await performToken(req, null);
	expect(forwardStub.calledOnce, "Method forwardToken should not be called").to.be.false;
	expect(insertStub.calledOnce, "Method insertToken should not be called").to.be.false;
	expect(returned_token).to.equal(null);
    });

    it("should fail due to missing client_assertion_type", async () => {
	const req = {
	    body: {
		client_id: "EU.EORI.DECLIENT",
		scope: "iSHARE",
		grant_type: "client_credentials",
		client_assertion: "XYZ"
	    }
	};

	performToken = require("../../activation/token");
	const returned_token = await performToken(req, null);
	expect(forwardStub.calledOnce, "Method forwardToken should not be called").to.be.false;
	expect(insertStub.calledOnce, "Method insertToken should not be called").to.be.false;
	expect(returned_token).to.equal(null);
    });

    it("should fail due to wrong client_assertion_type", async () => {
	const req = {
	    body: {
		client_id: "EU.EORI.DECLIENT",
		scope: "iSHARE",
		grant_type: "client_credentials",
		client_assertion_type: "XYZ",
		client_assertion: "XYZ"
	    }
	};

	performToken = require("../../activation/token");
	const returned_token = await performToken(req, null);
	expect(forwardStub.calledOnce, "Method forwardToken should not be called").to.be.false;
	expect(insertStub.calledOnce, "Method insertToken should not be called").to.be.false;
	expect(returned_token).to.equal(null);
    });

    it("should fail due to missing grant_type", async () => {
	const req = {
	    body: {
		client_id: "EU.EORI.DECLIENT",
		scope: "iSHARE",
		client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		client_assertion: "XYZ"
	    }
	};

	performToken = require("../../activation/token");
	const returned_token = await performToken(req, null);
	expect(forwardStub.calledOnce, "Method forwardToken should not be called").to.be.false;
	expect(insertStub.calledOnce, "Method insertToken should not be called").to.be.false;
	expect(returned_token).to.equal(null);
    });

    it("should fail due to wrong grant_type", async () => {
	const req = {
	    body: {
		client_id: "EU.EORI.DECLIENT",
		scope: "iSHARE",
		grant_type: "XYZ",
		client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		client_assertion: "XYZ"
	    }
	};

	performToken = require("../../activation/token");
	const returned_token = await performToken(req, null);
	expect(forwardStub.calledOnce, "Method forwardToken should not be called").to.be.false;
	expect(insertStub.calledOnce, "Method insertToken should not be called").to.be.false;
	expect(returned_token).to.equal(null);
    });

    it("should fail due to missing client_assertion", async () => {
	const req = {
	    body: {
		client_id: "EU.EORI.DECLIENT",
		scope: "iSHARE",
		grant_type: "client_credentials",
		client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	    }
	};

	performToken = require("../../activation/token");
	const returned_token = await performToken(req, null);
	expect(forwardStub.calledOnce, "Method forwardToken should not be called").to.be.false;
	expect(insertStub.calledOnce, "Method insertToken should not be called").to.be.false;
	expect(returned_token).to.equal(null);
    });
});
