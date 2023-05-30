# activation-service
Service allowing to activate services and create access rights during the acquisition step via:
* creating policies in an iSHARE authorisation registry 
* creating entries at a trusted issuer list (TBD)

It is based on Python Flask using gunicorn. The service requires to store data in an SQL database. 
It ca be configured to use external databases (e.g., MySQL, PostgreSQL) or SQLite.


## Preparation

Requirements:
* python >= 3.7
* [./requirements.txt](./requirements.txt)

Required python modules can be installed with 
```shell
pip install -r requirements.txt
```



### Configuration

Configuration is done in the file `config/as.yml`. You need to modify the values according to your 
environment and add your private key and certificate chain for the iSHARE flow.

Private key and certificate chain can be also provided as ENVs as given below. In this case, the values from 
`config/as.yml` would be overwritten.
* Private key: `AS_CLIENT_KEY`
* Certificate chain: `AS_CLIENT_CRT`

In case of very large JWTs in the Authorization header, one needs to increase the max. HTTP header size of 
gunicorn. This can be done by setting the following ENV (here: max. 32kb):

* `AS_MAX_HEADER_SIZE=32768` (Default: 32768)

When using a file-based SQLite, make sure that the volume is writeable.

Further ENVs control the execution of the activation service. Below is a list of the supported ENVs:

| ENV                                    | Default      | Description |
|:---------------------------------------|:------------:|:------------|
| AS_PORT                         | 8080         | Listen port |
| AS_GUNICORN_WORKERS             | 1            | Number of workers that should be created (note that multiple workers can result in conflicts when using in-memory or file-based databases) |
| AS_MAX_HEADER_SIZE              | 32768        | Maximum header size in bytes |
| AS_LOG_LEVEL                    | 'info'       | Log level |
| AS_DATABASE_URI                 |              | Database URI to use instead of config from configuration file |
| AS_CLIENT_KEY                          |              | iSHARE private key provided as ENV (compare to [config/as.yml](./config/as.yml#L8)) |
| AS_CLIENT_CERTS                        |              | iSHARE certificate chain provided as ENV (compare to [config/as.yml](./config/as.yml#L10)) |


## Usage

### Local

After placing a configuration file at `config/as.yml`, the activation service can be started with 
```shell
bin/run.sh
```


### Docker

A Dockerfile is provided to build a docker image. Releases automatically create Docker images 
at [DockerHub](https://hub.docker.com/r/i4trust/activation-service) and 
[quay.io](https://quay.io/repository/i4trust/activation-service).

Using Docker, the activation service can be run with:
```shell
docker run --rm -p 8080:8080 -v $PWD/config/as.yml:/var/aservice/config/as.yml quay.io/i4trust/activation-service:{RELEASE}
```

To enable DEBUG output, add the ENV:
* `-e "AS_LOG_LEVEL=DEBUG"`


### Kubernetes

A Helm chart is provided on [GitHub](https://github.com/i4Trust/helm-charts/tree/main/charts/activation-service) 
and [Artifacthub](https://artifacthub.io/packages/helm/i4trust/activation-service).



## Endpoints

* `/health`: Get health output of web server
* `/token`: Forwards a token request to the `/token` endpoint at the locally configured authorisation registry (iSHARE flow)
* `/createpolicy`: Activates the service by creating a policy at the locally configured authorisation registry (iSHARE flow)


## Extend

This version just allows to create policies at the local authorisation registry or entries at a trusted issuer list 
during acquisition/activation. 

However, depending on the service provided, it might be needed that further steps are required when activating 
a service, e.g. booting worker nodes or adding other resources. Such steps require to extend this activation service 
adding the necessary steps into the execution chain of the corresponding route.


## Debug

Enable debugging by setting the environment variable:
```shell
AS_LOG_LEVEL=DEBUG"
```


## Tests

Tests can be run with `pytest` via
```shell
pytest
```
