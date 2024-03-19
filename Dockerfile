FROM python:3.7-alpine

LABEL org.opencontainers.image.source="https://github.com/i4Trust/activation-service"

ENV AS_PORT=8080

RUN apk update && \
    apk add gcc build-base libc-dev libffi-dev openssl-dev bash curl

RUN addgroup --gid 5000 aservice \
    && adduser --uid 5000 -G aservice -D -s /bin/sh -k /dev/null aservice

WORKDIR /var/aservice
COPY ./ ./
RUN pip install --no-cache-dir -r requirements.txt

USER aservice
WORKDIR /var/aservice

HEALTHCHECK CMD curl --fail http://localhost:${AS_PORT}/health || exit 1
EXPOSE $AS_PORT
CMD [ "./bin/run.sh" ]
