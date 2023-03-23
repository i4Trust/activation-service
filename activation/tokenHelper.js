var debug = require('debug')('as:tokenHelper');
const https = require('https');
const fetch = require('node-fetch');

const config = require('../config.js');
const error = require('../util/utils.js').error;

const httpsAgent = new https.Agent({
    rejectUnauthorized: config.ar_ssl,
});

// Forward token request to AR
//
module.exports.forwardToken = async (req, res) => {
    debug('Forward request to /token endpoint of AR');
    
    // Proxy request to AR
    let token = {};
    try {
	const tparams = new URLSearchParams(req.body);
	const options = {
            method: 'POST',
            body: tparams,
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
	}
	if(config.ar_token.toLowerCase().startsWith("https://")) {
		options.agent = httpsAgent;
	}
	const ar_response = await fetch(config.ar_token, options);
	if (ar_response.status != 200) {
	    const res_text = await ar_response.text();
	    debug('Wrong status code in response: %o', res_text);
	    res.status(ar_response.status).send(res_text);
	    return null;
	}
	const res_body = await ar_response.json();
	if ( !res_body.access_token || !res_body.expires_in) {
	    debug('Invalid response: %o', res_body);
	    error(400, "Received invalid response from AR: " + JSON.stringify(res_body), res);
	    return null;
	}
	token = {
	    eori: req.body.client_id,
	    access_token: res_body.access_token,
	    expires: Date.now() + (1000*res_body.expires_in)
	};
	debug('Received response: %o', res_body);
	return {
	    token: token,
	    response: res_body
	};
    } catch (e) {
	console.error(e);
	let msg = e;
	if (e.response) {
	    msg = e.response.text();
	}
	error(500, "Error when forwarding request to AR: " + msg, res);
	return null;
    }
}


