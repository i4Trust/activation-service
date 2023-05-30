import yaml, sys

def load_config(filename, app):
    try:
        with open(filename, "r") as stream:
            conf = yaml.safe_load(stream)
            return conf
    except yaml.YAMLError as exc:
        app.logger.error('Error loading YAML: {}'.format(exc))
        sys.exit(4)
    except FileNotFoundError as fnfe:
        app.logger.error('Could not load config file: {}'.format(fnfe))
        sys.exit(4)
