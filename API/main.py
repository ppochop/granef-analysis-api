#! /usr/bin/env python3
# -*- coding: utf-8 -*-


"""
Granef API to perform Dgraph queries and provide responses with defined layout.

The default configuration exposes API at 127.0.0.1:7000. To access Swagger documentation visit
http://127.0.0.1:7000/docs.

Usage:  $ python3 main.py
        $ python3 main.py --ip "172.23.79.229"
"""

import argparse
import json  # Fast JSON parser
import re
import sys
import ipaddress

# Modules required to run FastAPI
import uvicorn  # Python web server
from typing import Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Custom modules of Granef API
from dgraph_client import DgraphClient
import models
import network_queries
import host_queries
import connections_queries
import other_queries


def is_ip_address(string):
    """
        Check if the given string is a valid IP address.

        :param string: String that should be verified if it is IP address
        :return: True if the string is a valid IP address
    """
    try:
        ipaddress.ip_address(string)
        return True
    except ValueError:
        return False


def is_hostname(string):
    """
        Check if the given string is a valid hostname.

        Source: https://stackoverflow.com/questions/2532053/validate-a-hostname-string

        :param string: String that should be verified if it is a hostname
        :return: True if the string is a valid hostname
    """
    if len(string) > 255:
        return False
    if string[-1] == ".":
        string = string[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in string.split("."))


def ip_or_hostname(string):
    """
        Check if the given string is a valid IP address or hostname.

        :param string: String that should be verified if it is an IP address or hostname
        :return: Given string if True
    """
    if is_ip_address(string) or is_hostname(string):
        return string
    raise argparse.ArgumentTypeError('Given string is not a valid IP address or a hostname: ' + string)


def is_integer(val):
    """
        Checks if input val is an integer.

        :return: True if val is a integer
    """
    try:
        int(val)
        return True
    except ValueError:
        return False


def port(val):
    """
        Check if the given val is a valid port number.

        :param val: port number expected to be in range [0, 65536]
        :return: True if val is in valid format
    """
    if is_integer(val) and 0 < int(val) < 65536:
        return val
    raise argparse.ArgumentTypeError('Given argument is not a valid port: ' + val)


# Application definition ("description" key may be added too).
app = FastAPI(
    title="Granef API",
    version="0.2",
)

# Load API routers
app.include_router(network_queries.router, prefix="/network_queries", tags=["network queries"])
app.include_router(host_queries.router, prefix="/host_queries", tags=["host queries"])
app.include_router(connections_queries.router, prefix="/connections_queries", tags=["connections queries"])
app.include_router(other_queries.router)


@app.get("/", summary="Get API information")
def get_root(request: Request):
    """
    Default function to show Granef API name, version, and Swagger URL when root path is requested.
    """
    swagger_path = "http://{hostname}:{port}/docs".format(hostname=request.url.hostname, port=request.url.port)
    return {"name": app.title, "version": app.version, "swagger": swagger_path}


@app.get("/connect", summary="Establish connection to Dgraph database")
def dgraph_connect():
    """
    Establish connection to Dgraph database server. When API starts the connection is automatically
    established. Call this function onl if some connection error occurred.
    """
    dgraph_client = DgraphClient()
    try:
        dgraph_client.connect(ip=args.dgraph_ip, port=args.dgraph_port)
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=str(e)
        )
    return {"detail": "Granef API connected to Dgraph server."}


if __name__ == "__main__":
    # Argument parser automatically creates -h argument
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Dummy argument.", default="")
    parser.add_argument("-ip", "--ip", help="IP address to bind the API web server.", type=ip_or_hostname, default="0.0.0.0")
    parser.add_argument("-p", "--port", help="Port to bind the API web server.", type=port, default=7000)
    parser.add_argument("-di", "--dgraph_ip", help="Dgraph server IP addres.", type=ip_or_hostname, default="alpha")
    parser.add_argument("-dp", "--dgraph_port", help="Dgraph server port.", type=port, default=9080)
    global args
    args = parser.parse_args()

    print(f'DEBUG: main.py got args: ip={args.ip}; port={args.port}; dgraph_ip={args.dgraph_ip}; dgraph_port={args.dgraph_port}.')

    # Set HTTP headers and allow all connection
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Initialize dgraph client
    dgraph_client = DgraphClient()
    dgraph_client.connect(ip=args.dgraph_ip, port=int(args.dgraph_port))

    # Start API web server using Uvicorn server
    uvicorn.run(app, host=args.ip, port=int(args.port))
