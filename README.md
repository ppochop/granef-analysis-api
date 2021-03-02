# Data Analysis

API for communicating with a running instance of Dgraph database (Alpha) with predefined queries.

## Requirements

* Docker
* Python 3 
* Python libraries specified in requirements.txt

## Usage

1. Dockerfile build:
```bash
docker build --tag=granef/analysis-api .
```

2. Run API:


```bash
docker run --rm --network granef -p 127.0.0.1:7000:7000 granef/analysis-api -ip 0.0.0.0 -p 7000 -di alpha -dp 9080
```
