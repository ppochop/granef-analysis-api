#! /usr/bin/env python3
# -*- coding: utf-8 -*-

#
# Granef -- graph-based network forensics toolkit
# Copyright (C) 2020-2021  Milan Cermak, Institute of Computer Science of Masaryk University
# Copyright (C) 2020-2021  Denisa Sramkova, Institute of Computer Science of Masaryk University
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#


"""Granef API to perform Dgraph queries and provide responses with defined layout.

The default configuration exposes API at 127.0.0.1:7000. To access Swagger documentation visit
http://127.0.0.1:7000/docs.

Examples:
    $ python3 main.py
    $ python3 main.py --ip "172.23.79.229"
"""

#
# TODO: Add verification of the connection to the Dgraph database
#


# Common Python modules
import argparse

# Modules required to run FastAPI
import uvicorn  # Python web server
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Custom modules of Granef API
from utilities.dgraph_client import DgraphClient
from routers import general_queries, overview_queries, graph_queries, flow_queries, flow_http_queries


# Application definition ("description" key may be added too).
app = FastAPI(
    title="Granef API",
    version="0.5",
)

# Load API routers
app.include_router(general_queries.router, tags=["General"])
app.include_router(graph_queries.router, prefix="/graph", tags=["Graph queries"])
app.include_router(flow_queries.router, prefix="/flow", tags=["Flow queries"])
app.include_router(flow_http_queries.router, prefix="/flow_http", tags=["HTTP queries"])
app.include_router(overview_queries.router, prefix="/overview", tags=["Overview queries"])


@app.get("/", summary="Get API information", tags=["General"])
def get_root(request: Request) -> dict:
    """
    Default function to show Granef API name, version, and Swagger URL when root path is requested.
    """
    swagger_path = "http://{hostname}:{port}/docs".format(hostname=request.url.hostname, port=request.url.port)
    return {"name": app.title, "version": app.version, "swagger": swagger_path}


@app.get("/connect", summary="Re-establish connection to the Dgraph database server", tags=["General"])
def dgraph_connect() -> dict:
    """
    The connection is automatically established with Granef API start. Call this function only if some
    connection error occurred.
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
    parser.add_argument("-ip", "--ip", help="IP address to bind the API web server.", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", help="Port to bind the API web server.", type=int, default=7000)
    parser.add_argument("-di", "--dgraph_ip", help="Dgraph server IP addres.", type=str, default="alpha")
    parser.add_argument("-dp", "--dgraph_port", help="Dgraph server port.", type=int, default=9080)
    global args
    args = parser.parse_args()

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
