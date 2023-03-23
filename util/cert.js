var debug = require('debug')('as:cert');
const config = require('../config.js');

let chain = [];

function initCertChain() {
    const crt_regex = /^-----BEGIN CERTIFICATE-----\n([\s\S]+?)\n-----END CERTIFICATE-----$/gm;
    let m;
    while ((m = crt_regex.exec(config.crt)) !== null) {
	// This is necessary to avoid infinite loops with zero-width matches
	if (m.index === crt_regex.lastIndex) {
            crt_regex.lastIndex++;
	}
	chain.push(m[1].replace(/\n/g, ""));
    }
}

module.exports = {
    initCertChain: initCertChain,
    chain: chain
};
