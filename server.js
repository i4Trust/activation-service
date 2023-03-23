var debug = require('debug')('as:server');
var cert = require('./util/cert.js');
const config = require('./config.js');

const app = require("./app").createApp();

let chain = [];

// Init server
// 
async function init() {
    debug('Initialising server...');
    
    // Prepare cert chain
    cert.initCertChain();
    chain = cert.chain;
}



// Start server
//
const server = app.listen(config.port, () => {
    console.log(`Express running → PORT ${server.address().port}`);
    init();
});
