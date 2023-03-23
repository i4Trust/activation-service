var debug = require('debug')('as:createPolicy');
var databaseHelper = require('../util/databaseHelper');
var createPolicyHelper = require('./createPolicyHelper');
const error = require('../util/utils.js').error;


// Perform createPolicy request
//
async function performCreatePolicy(req, res, chain) {
    
    // Get Autorization header
    debug('Extracting authorization header');
    if ( !req.header('Authorization')) {
	debug("Missing Authorization header");
	error(400, "Missing Authorization header", res);
	return null;
    }
    const auth = req.header('Authorization');
    let token = null;
    if (auth.startsWith("Bearer ")){
	token = auth.split(" ")[1];
    } 
    if (!token) {
	debug('No authorization header found: %o', auth);
	error(400, "Missing Authorization header Bearer token", res);
	return null;
    }

    // Get DB entry for token
    debug('Retrieving token from DB');
    const db_token = await databaseHelper.getByToken(token);
    if (!db_token.token) {
	let msg = "No valid token supplied";
	if (db_token.err) {
	    msg += ": " + db_token.err;
	}
	debug(msg);
	error(400, msg, res);
	return null;
    }
    
    // Get token from AR
    const tresult = await createPolicyHelper.getToken(chain);
    if (tresult.err) {
	let msg = "Retrieving token failed: " + tresult.err;
	debug(msg);
	error(400, msg, res);
	return null;
    }
    const access_token = tresult.access_token;

    // Check for policy at AR, if sender is allowed to create delegation evidence
    const err = await createPolicyHelper.checkCreateDelegationEvidence(db_token.token.eori, access_token);
    if (err) {
	let msg = db_token.token.eori + " was not issued required policy: " + err;
	debug(msg);
	error(400, msg, res);
	return null;
    }

    // Create requested policy at AR
    const presult = await createPolicyHelper.createPolicy(access_token, req.body);
    if (presult.err) {
	let msg = "Creating policy failed: " + presult.err;
	debug(msg);
	error(400, msg, res);
	return null;
    }

    return presult;
}

module.exports = performCreatePolicy;

