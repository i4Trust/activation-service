var debug = require('debug')('as:databaseHelper');
var pool = require("./database");

async function closeDB() {
    await pool.drain().then(function() {
	return pool.clear();
    });
}

async function init() {
    try {
	debug("Setup database...");
	const db = await pool.acquire();
	await db.run(`CREATE TABLE token (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            eori text NOT NULL UNIQUE, 
            access_token text NOT NULL UNIQUE, 
            expires int NOT NULL
            )`);
	debug("Created new database");
	await pool.release(db);
    } catch (err) {
	debug("Loaded existing database");
	let clean_err = await clean();
	if (clean_err) {
	    console.error("Error cleaning tokens: ", clean_err);
	    throw clean_err;
	}
    }
}

async function insertToken(token) {
    var sql = 'INSERT OR REPLACE INTO token (eori, access_token, expires) VALUES (?,?,?)';
    var params = [ token.eori, token.access_token, token.expires];
    try {
	debug('Inserting new token for %o', token.eori);
	const db = await pool.acquire();
	const result = await db.run(sql, params);
	await pool.release(db);

	return null;
    } catch (err) {
	console.error(err);
	return err;
    }
    
}

async function getByEORI(eori) {
    let result = {
	token: null,
	err: null
    };
    let clean_err = await clean();
    if (clean_err) {
	result.err = clean_err;
	return result;
    }
    var sql = 'SELECT eori, access_token, expires FROM token WHERE eori = ?';
    try {
	debug('Getting token DB entry by EORI: %o', eori);
	const db = await pool.acquire();
	const res = await db.get(sql, eori);
	result.token = res;
	await pool.release(db);
    } catch (err) {
	result.err = err;
    }
    return result;
}

async function getByToken(token) {
    let result = {
	token: null,
	err: null
    };
    let clean_err = await clean();
    if (clean_err) {
	result.err = clean_err;
	return result;
    }
    var sql = 'SELECT eori, access_token, expires FROM token WHERE access_token = ?';
    try {
	debug('Getting token DB entry by token');
	const db = await pool.acquire();
	const res = await db.get(sql, token);
	result.token = res;
	await pool.release(db);
    } catch (err) {
	result.err = err;
    }
    return result;
}

async function clean() {
    let cur_date = Date.now();
    try {
	const db = await pool.acquire();
	const result = await db.run('DELETE FROM token WHERE expires < ?',
				    cur_date);
	debug('Removed expired tokens from DB: %o', result);
	await pool.release(db);
	return null;
    } catch (err) {
	console.error("err:",err);
	return err;
    }
}

module.exports = {
    closeDB: closeDB,
    clean: clean,
    insertToken: insertToken,
    getByEORI: getByEORI,
    getByToken: getByToken,
    init: init
};
