var debug = require('debug')('as:token');
const https = require('https');
const fetch = require('node-fetch');

var databaseHelper = require('../util/databaseHelper');
const config = require('../config.js');
const error = require('../util/utils.js').error;
const {forwardToken} = require("./tokenHelper");

// Perform token request
//
async function performToken(req, res) {

    // Validate client_id
    if ( !req.body || !req.body.client_id) {
	let emsg = "Missing parameter client_id";
	debug(emsg);
	error(400, emsg, res);
	return null;
    }

    // Validate scope
    if ( !req.body || !req.body.scope) {
	let emsg = "Missing parameter scope";
	debug(emsg);
	error(400, emsg, res);
	return null;
    } else if (!req.body.scope.includes("iSHARE")) {
	let emsg = "Wrong parameter scope: " + req.body.scope + ". MUST include 'iSHARE'";
	debug(emsg);
	error(400, emsg, res);
	return null;
    }

    // Validate grant_type
    if ( !req.body || !req.body.grant_type) {
	let emsg = "Missing parameter grant_type";
	debug(emsg);
	error(400, emsg, res);
	return null;
    } else if (req.body.grant_type != "client_credentials") {
	emsg = "Wrong parameter grant_type: " + req.body.grant_type + ". MUST be 'client_credentials'"
	debug(emsg);
	error(400, emsg, res);
	return null;
    }

    // Validate client_assertion_type
    if ( !req.body || !req.body.client_assertion_type) {
	let emsg = "Missing parameter client_assertion_type";
	debug(emsg);
	error(400, emsg, res);
	return null;
    } else if (req.body.client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") {
	emsg = "Wrong parameter client_assertion_type: " + req.body.client_assertion_type + ". MUST be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'"
	debug(emsg);
	error(400, emsg, res);
	return null;
    }

    // Validate client_assertion
    if ( !req.body || !req.body.client_assertion) {
	let emsg = "Missing parameter client_assertion";
	debug(emsg);
	error(400, emsg, res);
	return null;
    }

    // Forward token request to AR
    const token = await forwardToken(req, res);
    if ( !token ) {
	return null;
    }
    
    // DB entry insert
    const ins_err = await databaseHelper.insertToken(token.token);
    if (ins_err) {
	error(500, "Could not insert token into DB: " + ins_err, res);
	return null;
    }
    
    return token;    
};

module.exports = performToken; 
