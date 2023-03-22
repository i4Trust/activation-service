var debug = require('debug')('as:database');
var sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const genericPool = require('generic-pool');
const config = require('../config.js');

const DBSOURCE = config.db_source;

// Open DB
debug("Connecting to SQLite Database: %o", config.db_source);
const factory = {
    name: 'sqlite',
    create: async () => await open({
	filename: config.db_source,
	driver: sqlite3.Database
    }),
    destroy: (db) => db.close()
};
const opts = {
    max: 10,
    min: 2,
    idleTimeoutMillis: 30000,
    log: false
};
const pool = genericPool.createPool(factory, opts);

module.exports = pool;
