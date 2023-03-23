var debug = require('debug')('as:app');
const https = require('https');
const express = require('express');
const app = express();
var bodyParser = require('body-parser');

const config = require('./config.js');
const chain = require('./util/cert.js').chain;
const performToken = require('./activation/token.js');
const performCreatePolicy = require('./activation/createPolicy.js');

function createApp() { 

    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: true }));
    const httpsAgent = new https.Agent({
	rejectUnauthorized: config.ar_ssl,
    });

    // /token
    // Proxy request to /token endpoint of AR
    // and store returned token
    app.post('/token', async (req, res) => {
	debug('Received request at /token endpoint');
	const token = await performToken(req, res); //, db);
	
	// Return AR response
	if (token) {
	    debug('Received access_token with response: %o', token.response);
	    debug('==============');
	    res.send(token.response);
	}
    });


    // /createpolicy
    // Create policy at AR
    // Perform additional activation steps if needed
    app.post('/createpolicy', async (req, res) => {
	debug('Received request at /createpolicy endpoint');
	// Create requested policy at AR
	const presult = await performCreatePolicy(req, res, chain);

	// **********************
	// Other activation steps (e.g. starting computation nodes)
	// could be added here!
	// **********************

	// Return result
	if (presult) {
	    if (presult.policy_token) {
		debug('Successfully created new policy at AR. Received policy_token: %o', presult.policy_token);
		res.send({
		    policy_token: presult.policy_token
		});
	    } else {
		debug('Successfully created new policy at AR');
		res.sendStatus(200);
	    }
	    debug('==============');
	}
    });

    // /health
    // Healthcheck endpoint
    app.get('/health', (req, res) => {
	res.send({
	    uptime: process.uptime(),
	    message: 'OK',
	    timestamp: Date.now()
	});
    });

    return app;
}

// Export app
module.exports = {
    createApp: createApp
}
