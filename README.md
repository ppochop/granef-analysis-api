
<img  src="https://is.muni.cz/www/milan.cermak/granef/granef-logo.svg"  height="60px">

[**Graph-Based Network Forensics**](https://gitlab.ics.muni.cz/granef/granef)**: Analysis API**

---
  
The Analysis API Module is used to perform queries on a running instance of the [Dgraph](https://dgraph.io/) graph database. A set of predefined queries is available, which can be easily extended by new queries. A custom query can be defined by the user as well. 

It is used by the [Analysis Web Module](https://gitlab.ics.muni.cz/granef/analysis-web-v2), which extends the usage of this module by a friendly user interface.

### Requirements

- a running instance of Dgraph
- Docker 
- Python3
- Python3 packages in [requirements.txt](requirements.txt)

The installation can be performed using the following command:

```bash
$ git clone https://gitlab.ics.muni.cz/granef/analysis-api.git
```

Use the following command to build the Docker container:

```bash
$ docker build --tag=granef/analysis-api .
```

### Usage

The Docker container can be either run separately with command line arguments or as part of the Granef toolkit with arguments set in the [granef.yml](https://gitlab.ics.muni.cz/granef/granef/-/blob/master/granef.yml) configuration file. 

The following arguments can be set:

| Short argument | Long argument | Description | Default | 
|-|-|-|-|
|`-i`|`--input`|Dummy argument (requested by the GRANEF toolkit)||
|`-ip`|`--ip`|IP address to bind the API web server|`0.0.0.0`|
|`-p`|`--port`|Port to bind the API web server|`7000`|
|`-di`|`--dgraph_ip`|Dgraph server IP addres|`alpha`|
|`-dp`|`--dgraph_port`|Dgraph server port|`9080`|

Use the following command to run the API:

```bash
$ docker run --rm --network granef -p 127.0.0.1:7000:7000 granef/analysis-api -ip 0.0.0.0 -p 7000 -di alpha -dp 9080
```

The API is then available at [http://127.0.0.1:7000](http://127.0.0.1:7000).


