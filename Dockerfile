FROM python:3.7-alpine

ENV AS_PORT=8080

RUN apk update && \
    apk add gcc build-base libc-dev libffi-dev openssl-dev bash curl

WORKDIR /var/aservice
COPY ./ ./
RUN pip install --no-cache-dir -r requirements.txt

HEALTHCHECK CMD curl --fail http://localhost:${AS_PORT}/health || exit 1
EXPOSE $AS_PORT
CMD [ "./bin/run.sh" ]
