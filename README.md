# GRANEF Analysis API module, flow2granef thesis version

This is a fork of the [Analysis API module](https://gitlab.ics.muni.cz/granef/analysis/api) of [GRANEF](https://granef.csirt.muni.cz/). Its functionality is the same but this repo contains changes written to ensure compatibility with [flow2granef]. Please see and use the original version unless you are planning to use *flow2granef*.

### Requirements

- a running instance of Dgraph (see next section for a quickstart)
- Docker 
- Python3
- Python3 packages in [requirements.txt](requirements.txt)

### Run dgraph quickstart
NB: This is just a quickstart deployment, see the [official docs](https://docs.hypermode.com/dgraph/overview) for more thorough guidance.
1. Run dgraph zero:
```bash
$ docker run --rm -d --name zero -h zero -p 5080:5080 --network granef -p 6080:6080 -v ~/zero_data:/dgraph dgraph/dgraph:latest dgraph zero --my=zero:5080 --telemetry "sentry=false;"
```
2. Run dgraph alpha:
```bash
$ docker run --rm -d --name alpha1 -h alpha1 -p 7080:7080 --network granef -p 8080:8080 -p 9080:9080 -v ~/plugins:/plugins -v ~/alpha_data1:/dgraph dgraph/dgraph:latest dgraph alpha --zero=zero:5080 --my=alpha1:7080 --custom_tokenizers=/plugins/cidr-plugin.so --security whitelist=0.0.0.0/0 --telemetry "sentry=false;"
```
NOTE: the plugins have to be built with the same golang version as dgraph

### Usage
1. Clone this repository. Make sure you are using the right branch/version (coresponding to the version of *flow2granef*).
2. Build the docker image:
```bash
$ docker build --tag=granef/analysis-api .
```
3. Run the API module:
```bash
$ docker run -d --rm --name analysis-api -h analysis-api --network granef -p 127.0.0.1:7000:7000 granef/analysis-api -ip 0.0.0.0 -p 7000 -di alpha1 -dp 9080
```
