from api import app
from flask_sqlalchemy import SQLAlchemy
import logging, os
import yaml, sys

# Port
port = int(os.environ.get("AS_PORT", 8080))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port)
else:
    # Running inside gunicorn, set logger
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
    app.logger.info("Setting gunicorn logger...")

# Load config
app.logger.info("Loading config from " + "config/as.yml")
try:
    with open("config/as.yml", "r") as stream:
        conf = yaml.safe_load(stream)
        app.logger.debug("... config loaded")
        app.config['as'] = conf
except yaml.YAMLError as exc:
    app.logger.error('Error loading YAML: {}'.format(exc))
    sys.exit(4)
except FileNotFoundError as fnfe:
    app.logger.error('Could not load config file: {}'.format(fnfe))
    sys.exit(4)

# Create database
app.logger.info("Creating database...")
conf = app.config['as']
if 'db' not in conf:
    app.logger.error('No database configuration in config file')
    sys.exit(4)
db_conf = conf['db']

if os.environ.get('AS_DATABASE_URI'):
    app.logger.info("... taking URI from ENV...")
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('AS_DATABASE_URI')
if 'useMemory' in db_conf and db_conf['useMemory']:
    app.logger.info("... using in-memory SQLite ...")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
elif 'useFile' in db_conf and db_conf['useFile'] and 'filename' in db_conf['useFile']:
    basedir = os.path.abspath(os.path.dirname(__file__))
    if 'filepath' in db_conf['useFile'] and len(db_conf['useFile']['filepath']) > 0:
        basedir = db_conf['useFile']['filepath']
    dbpath = os.path.join(basedir, db_conf['useFile']['filename'])
    app.logger.info("... using file-based SQLite (" +  dbpath + ") ...")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + dbpath
elif 'useURI' in db_conf and db_conf['useURI'] and len(db_conf['useURI']) > 0:
    app.logger.info("... using specified URI '" + db_conf['useURI'] + "' ...")
    app.config['SQLALCHEMY_DATABASE_URI'] = db_conf['useURI']

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
if db_conf['modTracking']:
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

app.config['SQLALCHEMY_ECHO'] = False
if db_conf['echo']:
    app.config['SQLALCHEMY_ECHO'] = True

db = SQLAlchemy(app)
app.config['db'] = db
app.logger.info("... database created!")

with app.app_context():
    app.logger.info("Creating database tables...")
    from api.models import token
    db.drop_all() # TODO: Make configurable
    db.create_all()
    app.logger.info("... database tables created")

