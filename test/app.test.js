//var rewire = require("rewire");
const chai = require("chai");
const sinon = require("sinon");
const expect = chai.expect;
const faker = require("faker");
const request = require('supertest');
const decache = require('decache');
var databaseHelper = require('../util/databaseHelper');

let app;

// app health tests
describe("app health", () => {

    beforeEach(() => {
	decache("../app");
	app = require("../app").createApp();
    });
    
    it("should return health status OK", () => {
	return request(app)
	    .get("/health")
	    .expect(200)
	    .then((res) => {
		expect(res.body.message).to.equal('OK');
	    });	
    });

});

// app token tests
describe("app token", () => {

    let forwardStub = null;
    let tokenHelper;

    beforeEach(async () => {
	await databaseHelper.init();
		
	const return_token = {
	    token: {
		access_token: "aW2ys9NGE8RjHPZ4mytQivkWJO5HGQCYJ7VyMBGGDLIOw",
		eori: "EU.EORI.DECLIENT",
		expires: Date.now() + (1000*3600)
	    },
	    response: {
		access_token: "aW2ys9NGE8RjHPZ4mytQivkWJO5HGQCYJ7VyMBGGDLIOw",
		token_type: "Bearer",
		expires_in: 3600
	    }
	};
	decache("../app");

	decache("../activation/tokenHelper");
	tokenHelper = require("../activation/tokenHelper");

	// Stub forwarding of token request to AR
	// TODO: Stub only fetch() function?
	forwardStub = sinon.stub(tokenHelper, "forwardToken").returns(return_token);
	
	app = require("../app").createApp();
    });

    // Missing client_id
    it("should return error about missing client_id", async () => {
	const client_assert_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	const client_assert = "abcdefgh"
	const scope = "iSHARE"
	const grant_type = "client_credentials"
	
	return request(app)
	    .post("/token")
	    .send('scope='+scope+'&grant_type='+grant_type+'&client_assertion_type='+client_assert_type+'&client_assertion='+client_assert)
	    .expect(400) // , "should return status code 400"
	    .then((res) => {
		expect(res.body.msg, "should return correct error message").to.equal('Missing parameter client_id');
	    });
    });

    // Missing scope
    it("should return error about missing scope", async () => {
	const client_id = "EU.EORI.DECLIENT"
	const client_assert_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	const client_assert = "abcdefgh"
	const grant_type = "client_credentials"
	
	return request(app)
	    .post("/token")
	    .send('client_id='+client_id+'&grant_type='+grant_type+'&client_assertion_type='+client_assert_type+'&client_assertion='+client_assert)
	    .expect(400) // , "should return status code 400"
	    .then((res) => {
		expect(res.body.msg, "should return correct error message").to.equal('Missing parameter scope');
	    });
    });

    // Wrong scope
    it("should return error about wrong scope", async () => {
	const client_id = "EU.EORI.DECLIENT"
	const client_assert_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	const client_assert = "abcdefgh"
	const scope = "profile"
	const grant_type = "client_credentials"
	
	return request(app)
	    .post("/token")
	    .send('client_id='+client_id+'&scope='+scope+'&grant_type='+grant_type+'&client_assertion_type='+client_assert_type+'&client_assertion='+client_assert)
	    .expect(400) // , "should return status code 400"
	    .then((res) => {
		expect(res.body.msg, "should return correct error message").to.equal("Wrong parameter scope: profile. MUST include 'iSHARE'");
	    });
    });

    // Missing grant_type
    it("should return error about missing grant_type", async () => {
	const client_id = "EU.EORI.DECLIENT"
	const client_assert_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	const client_assert = "abcdefgh"
	const scope = "iSHARE"
		
	return request(app)
	    .post("/token")
	    .send('client_id='+client_id+'&scope='+scope+'&client_assertion_type='+client_assert_type+'&client_assertion='+client_assert)
	    .expect(400) // , "should return status code 400"
	    .then((res) => {
		expect(res.body.msg, "should return correct error message").to.equal('Missing parameter grant_type');
	    });
    });

    // Wrong grant type
    it("should return error about wrong grant_type", async () => {
	const client_id = "EU.EORI.DECLIENT"
	const client_assert_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	const client_assert = "abcdefgh"
	const scope = "iSHARE"
	const grant_type = "XYZ"
	
	return request(app)
	    .post("/token")
	    .send('client_id='+client_id+'&scope='+scope+'&grant_type='+grant_type+'&client_assertion_type='+client_assert_type+'&client_assertion='+client_assert)
	    .expect(400) // , "should return status code 400"
	    .then((res) => {
		expect(res.body.msg, "should return correct error message").to.equal("Wrong parameter grant_type: XYZ. MUST be 'client_credentials'");
	    });
    });

    // Missing client assertion type
    it("should return error about missing client_assertion_type", async () => {
	const client_id = "EU.EORI.DECLIENT"
	const client_assert = "abcdefgh"
	const scope = "iSHARE"
	const grant_type = "client_credentials"
	
	return request(app)
	    .post("/token")
	    .send('client_id='+client_id+'&scope='+scope+'&grant_type='+grant_type+'&client_assertion='+client_assert)
	    .expect(400) // , "should return status code 400"
	    .then((res) => {
		expect(res.body.msg, "should return correct error message").to.equal('Missing parameter client_assertion_type');
	    });
    });

    // Wrong client assertion type
    it("should return error about wrong client_assertion_type", async () => {
	const client_id = "EU.EORI.DECLIENT"
	const client_assert_type = "XYZ"
	const client_assert = "abcdefgh"
	const scope = "iSHARE"
	const grant_type = "client_credentials"
	
	return request(app)
	    .post("/token")
	    .send('client_id='+client_id+'&scope='+scope+'&grant_type='+grant_type+'&client_assertion_type='+client_assert_type+'&client_assertion='+client_assert)
	    .expect(400) // , "should return status code 400"
	    .then((res) => {
		expect(res.body.msg, "should return correct error message")
		    .to
		    .equal("Wrong parameter client_assertion_type: XYZ. MUST be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'");
	    });
    });

    // Missing client assertion
    it("should return error about missing client_assertion", async () => {
	const client_id = "EU.EORI.DECLIENT"
	const client_assert_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	const scope = "iSHARE"
	const grant_type = "client_credentials"
	
	return request(app)
	    .post("/token")
	    .send('client_id='+client_id+'&scope='+scope+'&grant_type='+grant_type+'&client_assertion_type='+client_assert_type)
	    .expect(400) // , "should return status code 400"
	    .then((res) => {
		expect(res.body.msg, "should return correct error message").to.equal('Missing parameter client_assertion');
	    });
    });
    
    // Test token endpoint
    it("should return token", () => {
	const client_id = "EU.EORI.DECLIENT";
	const client_assert_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
	const client_assert = "abcdefgh";
	const scope = "iSHARE";
	const grant_type = "client_credentials";

	return request(app)
	    .post("/token")
	    .send('client_id='+client_id+'&scope='+scope+'&grant_type='+grant_type+'&client_assertion_type='+client_assert_type+'&client_assertion='+client_assert)
	    .expect(200)
	    .then(async (res) => {
		expect(res.body.access_token,"should return correct access_token").to.equal("aW2ys9NGE8RjHPZ4mytQivkWJO5HGQCYJ7VyMBGGDLIOw");

		// Check that token has been inserted into DB
		// Get via token
		let inserted_token = await databaseHelper.getByToken("aW2ys9NGE8RjHPZ4mytQivkWJO5HGQCYJ7VyMBGGDLIOw");
		expect(inserted_token.err, "There should be no error when retrieving the inserted token from the DB").to.equal(null);
		expect(inserted_token, "There should be a key token").to.have.property("token");
		expect(inserted_token.token.eori, "Inserted token entry should have correct EORI").to.equal("EU.EORI.DECLIENT");
		expect(inserted_token.token.access_token, "Inserted token entry should have correct acces_token")
		    .to.equal("aW2ys9NGE8RjHPZ4mytQivkWJO5HGQCYJ7VyMBGGDLIOw");
		// Get via EORI
		inserted_token = await databaseHelper.getByEORI("EU.EORI.DECLIENT");
		expect(inserted_token.err, "There should be no error when retrieving the inserted token from the DB").to.equal(null);
		expect(inserted_token, "There should be a key token").to.have.property("token");
		expect(inserted_token.token.eori, "Inserted token entry should have correct EORI").to.equal("EU.EORI.DECLIENT");
		expect(inserted_token.token.access_token, "Inserted token entry should have correct acces_token")
		    .to.equal("aW2ys9NGE8RjHPZ4mytQivkWJO5HGQCYJ7VyMBGGDLIOw");
	    });
    });

});


// app createPolicy tests
describe("app createPolicy", () => {

    let createPolicyHelper;
    let performCreatePolicy;

    //let getByTokenStub;
    let getTokenStub;
    let checkCreateDelegationEvidenceStub;
    let createPolicyStub;

    const req_token = "gsdfgdsgdsgsdgsg";
    
    //let forwardStub = null;
    //let tokenHelper;

    beforeEach(async () => {

	//await databaseHelper.init();

	const db_token_insert = {
	    eori: "EU.EORI.DEMARKETPLACE",
	    access_token: req_token,
	    expires: Date.now() + (1000*3600)
	};
	
	decache("../app");
	decache("../activation/createPolicyHelper");
	createPolicyHelper = require("../activation/createPolicyHelper");
	
	// Insert token into DB
	await databaseHelper.insertToken(db_token_insert);
	
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
	
	app = require("../app").createApp();
    });

    // Successfully create policy
    it("should create policy", async () => {
	
	return request(app)
	    .post('/createpolicy')
	    .set('Authorization', 'Bearer ' + req_token)
	    .expect(200)
	    .then(async (res) => {
		expect(res.body.policy_token,"should return correct access_token").to.equal("XYZ");
	    });
    });

    it("should return error about missing auth header", async () => {
	return request(app)
	    .post('/createpolicy')
	    .expect(400)
	    .then(async (res) => {
		expect(res.body.msg, "should return correct error message").to.equal('Missing Authorization header');
	    });
    });

    it("should return error about missing auth header Bearer token", async () => {
	return request(app)
	    .post('/createpolicy')
	    .set('Authorization', 'Beerer ' + req_token)
	    .expect(400)
	    .then(async (res) => {
		expect(res.body.msg, "should return correct error message").to.equal('Missing Authorization header Bearer token');
	    });
    });

    it("should return error about invalid token", async () => {
	return request(app)
	    .post('/createpolicy')
	    .set('Authorization', 'Bearer ABCDEFGH')
	    .expect(400)
	    .then(async (res) => {
		expect(res.body.msg, "should return correct error message").to.equal('No valid token supplied');
	    });
    });
    
});
