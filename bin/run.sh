#!/usr/bin/env bash

# Port
AS_PORT="${AS_PORT:-8080}"

# gunicorn workers
AS_GUNICORN_WORKERS="${AS_GUNICORN_WORKERS:-1}"

# Max header size
AS_MAX_HEADER_SIZE="${AS_MAX_HEADER_SIZE:-32768}"

# Log level
AS_LOG_LEVEL="${AS_LOG_LEVEL:-info}"

exec gunicorn wsgi:app --bind 0.0.0.0:${AS_PORT} --log-level=${AS_LOG_LEVEL} --workers=${AS_GUNICORN_WORKERS} --limit-request-field_size=${AS_MAX_HEADER_SIZE}
