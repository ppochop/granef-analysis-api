#! /usr/bin/env python3
# -*- coding: utf-8 -*-

#
# Granef -- graph-based network forensics toolkit
# Copyright (C) 2020-2021  Aneta Jablunkova, Faculty of Informatics, Masaryk University
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

"""
Definition of http network flow queries for Granef API.
"""

# Common Python modules
import json

# FastAPI modules
from fastapi import APIRouter
from fastapi import HTTPException

# GranefAPI
from models import query_models
from utilities import validation, preprocessing
from utilities.dgraph_client import DgraphClient

# Initialize FastAPI router
router = APIRouter()


@router.post("/host_initiate_http", 
    response_model=query_models.GeneralResponseList, 
    summary="List of IP addresses from subnet that initiated HTTP or HTTPS connection.")
def host_initiate_http(request: query_models.AddressQuery) -> dict:

    # Validate IP address and raise exception if not valid
    validation.validate(request.address, "address")

    dgraph_client = DgraphClient()
    
    query = f"""{{
        host_initiate_http(func: allof(host.ip, cidr, "{request.address}")) {{
            label : host.ip
            host.ip
            httpOrigNodes as math(1)

            host.originated {{
                connection.Destination_Address
                connection.produced @filter(type(HTTP_formats)) {{
                    httpOrigInside as math(httpOrigNodes)
                }}
                httpOrigSum as sum(val(httpOrigInside))
            }}

            httpOriginatedCount : sum(val(httpOrigSum))
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["host_initiate_http"]}


@router.post("/get_hostname", 
    response_model=query_models.GeneralResponseList, 
    summary="List of the count of all HTTP hostnames.")
def get_hostname() -> dict:

    dgraph_client = DgraphClient()

    query = f"""{{ 
        get_hostname(func: type(HTTP_formats)) @groupby(HTTP_formats.HTTP_Hostname) {{
            hostname_count : count(uid)
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["get_hostname"]}


@router.post("/get_all_urls", 
    response_model=query_models.GeneralResponseList, 
    summary="List of the count of all HTTP urls.")
def get_all_urls() -> dict:

    dgraph_client = DgraphClient()

    query = f"""{{ 
        get_all_urls(func: type(HTTP_formats)) @groupby(HTTP_formats.HTTP_URL) {{
            uri_count : count(uid)
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["get_all_urls"]}


@router.post("/http_count", response_model=query_models.GeneralResponseList, summary="Return count of HTTP connections.")
def http_count(request: query_models.AddressQuery) -> dict:

    # Validate IP address and raise exception if not valid
    validation.validate(request.address, "address")

    dgraph_client = DgraphClient()

    query = f"""{{ 
        http_count(func: eq(host.ip, "{request.address}")) @normalize {{
            label : host.ip
            host.ip
            httpOrigNodes as math(1)

            host.originated {{
                connection.produced @filter(type(HTTP_formats)) {{
                    httpOrigInside as math(httpOrigNodes)
                }}
                httpOrigSum as sum(val(httpOrigInside))
            }}

            httpOriginatedCount : sum(val(httpOrigSum))
            httpRespNodes as math(1)

            host.responded {{
                connection.produced @filter(type(HTTP_formats)) {{
                    httpRespInside as math(httpRespNodes)
                }}
                httpRespSum as sum(val(httpRespInside))
            }}
            
            httpRespondedCount : sum(val(httpRespSum))
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["http_count"]}