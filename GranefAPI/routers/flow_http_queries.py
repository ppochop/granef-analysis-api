#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of common network queries for Granef API.
"""

import json  # Fast JSON parser
from fastapi import APIRouter  # FastAPI modules
from fastapi import HTTPException

from models import query_models     # Custom GranefAPI models
from utilities import validation
from utilities.dgraph_client import DgraphClient

# Initialize FastAPI router
router = APIRouter()


@router.get("/host_initiate_http", response_model=query_models.GeneralResponse, summary="List of IP addresses from subnet that initiated HTTP or HTTPS connection.")
def connection_info(subnet_mask: str, type: str = "json", layout: str = "sfdp"):

    if not validation.is_address(subnet_mask):
        raise HTTPException(
            status_code = 400,
            detail = f"Given address {subnet_mask} is not valid IPv4, IPv6 address, or CIDR notation."
        )

    dgraph_client = DgraphClient()
    
    query_variables = {subnet_mask: "string"}
    query = f"""{{
        getOriginatedHostsHTTP(func: allof(host.ip, cidr, "{subnet_mask}")) {{
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
    try:
        result = dgraph_client.query(query, query_variables)
    except Exception as e:
        raise HTTPException(
            status_code = 500,
            detail = str(e)
        )
    return {"response": json.loads(result)}


@router.get("/get_hostname", response_model=query_models.GeneralResponse, summary="List of the count of all HTTP hostnames.")
def subnet_info(type: str = "json", layout: str = "sfdp"):

    dgraph_client = DgraphClient()

    query = f"""{{ 
        getHttpHostname(func: type(HTTP_formats)) @groupby(HTTP_formats.HTTP_Hostname) {{
            hostname_count : count(uid)
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    try:
        result = dgraph_client.query(query)
    except Exception as e:
        raise HTTPException(
            status_code = 500,
            detail = str(e)
        )
    return {"response": json.loads(result)}


@router.get("/get_all_urls", response_model=query_models.GeneralResponse, summary="List of the count of all HTTP urls.")
def subnet_info(type: str = "json", layout: str = "sfdp"):

    dgraph_client = DgraphClient()

    query = f"""{{ 
        getHttpUri(func: type(HTTP_formats)) @groupby(HTTP_formats.HTTP_URL) {{
            uri_count : count(uid)
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    try:
        result = dgraph_client.query(query)
    except Exception as e:
        raise HTTPException(
            status_code = 500,
            detail = str(e)
        )
    return {"response": json.loads(result)}


@router.get("/http_count", response_model=query_models.GeneralResponse, summary="Return count of HTTP connections.")
def subnet_info(host_ip: str, type: str = "json", layout: str = "sfdp"):

    if not validation.is_address(host_ip):
        raise HTTPException(
            status_code = 400,
            detail = f"Given address {host_ip} is not valid IPv4, IPv6 address, or CIDR notation."
        )

    dgraph_client = DgraphClient()

    query_variables = {host_ip: "string"}
    query = f"""{{ 
        getHttpCount(func: eq(host.ip, "{host_ip}")) @normalize {{
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
    try:
        result = dgraph_client.query(query)
    except Exception as e:
        raise HTTPException(
            status_code = 500,
            detail = str(e)
        )
    return {"response": json.loads(result)}