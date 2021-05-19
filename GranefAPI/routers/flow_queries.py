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


@router.get("/subnet_info", response_model=query_models.GeneralResponse, summary="Perform statistics query about given subnet mask.")
def subnet_info(subnet_mask: str, protocol: str, from_timestamp: str, to_timestamp: str, type: str = "json", layout: str = "sfdp"):
    if not validation.is_address(subnet_mask):
        raise HTTPException(
            status_code = 400,
            detail = f"Given address {subnet_mask} is not valid IPv4, IPv6 address, or CIDR notation."
        )

    dgraph_client = DgraphClient()

    query_variables = {subnet_mask: "string", protocol: "string", from_timestamp: "string", to_timestamp: "string"}
    query = f"""{{ 
        getSubnetConnections(func: allof(host.ip, cidr, "{subnet_mask}")) {{ 
            label : host.ip
            host.ip
            host.originated @filter(ge(connection.Start_Time_first_seen, "{from_timestamp}") AND le(connection.End_Time_last_seen, "{to_timestamp}")) {{
                connection.produced @filter(eq(dgraph.type, "{protocol}")) {{
                    expand(_all_)
                }}
                ~host.responded {{
                    label : host.ip
                    host.ip
                }}
            }}
            host.responded @filter(ge(connection.Start_Time_first_seen, "{from_timestamp}") AND le(connection.End_Time_last_seen, "{to_timestamp}")) {{
                connection.produced @filter(eq(dgraph.type, {"protocol"})) {{
                    expand(_all_)
                }}
                ~host.originated {{
                    label : host.ip
                    host.ip
                }}
            }}    
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


@router.get("/connection_info", response_model=query_models.GeneralResponse, summary="Return connections in specified time interval.")
def connection_info(from_timestamp: str, to_timestamp: str, type: str = "json", layout: str = "sfdp"):

    dgraph_client = DgraphClient()
    
    query_variables = {from_timestamp: "string", to_timestamp: "string"}
    query = f"""{{
        getConnections(func: has(host.ip)) {{
            label : host.ip
            host.ip
            host.originated @filter(ge(connection.Start_Time_first_seen, "{from_timestamp}") AND le(connection.End_Time_last_seen, "{to_timestamp}")) {{
                expand(connection)
                ~host.responded {{
                    label : host.ip
                    host.ip
                }}
            }}
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


@router.get("/communicated_hosts", response_model=query_models.GeneralResponse, summary="List of all hosts that communicate with specified host.")
def communicated_hosts(host_ip: str, type: str = "json", layout: str = "sfdp"):

    if not validation.is_address(host_ip):
        raise HTTPException(
            status_code = 400,
            detail = f"Given address {host_ip} is not valid IPv4, IPv6 address, or CIDR notation."
        )

    dgraph_client = DgraphClient()
    
    query_variables = {host_ip: "string"}
    query = f"""{{
        getCommunicatedHosts(func: allof(host.ip, cidr, "{host_ip}")) {{ 
            label : host.ip
            host.ip
            host.communicated {{
                label : host.ip
                host.ip
                host.hostname {{
                    label: hostname.type
                    hostname.name
                }}
            }}
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


@router.get("/connection_between_two_hosts", response_model=query_models.GeneralResponse, summary="List of all originated connections between two hosts.")
def connection_between_two_hosts(host_ip1: str, host_ip2: str, from_timestamp: str, to_timestamp: str, type: str = "json", layout: str = "sfdp"):

    if not validation.is_address(host_ip1) or not validation.is_address(host_ip2):
        raise HTTPException(
            status_code = 400,
            detail = f"Given address {host_ip1} or {host_ip2} is not valid IPv4, IPv6 address, or CIDR notation."
        )

    dgraph_client = DgraphClient()
    
    query_variables = {host_ip1: "string", host_ip2: "string", from_timestamp: "string", to_timestamp: "string"}
    query = f"""{{
        var(func: eq(host.ip, "{host_ip1}")) {{
            connectionsWithWantedHost as host.originated @cascade {{
                ~host.responded @filter(eq(host.ip, "{host_ip2}")) {{}}
            }}
        }}
        getConnectionsBetweenTwoHosts(func: uid(connectionsWithWantedHost)) {{
            expand(connection)

            ~host.originated @filter(ge(connection.Start_Time_first_seen, "{from_timestamp}") AND le(connection.End_Time_last_seen, "{to_timestamp}")) {{
                label : host.ip
                host.hostname {{
                    label: hostname.type
                    hostname.name
                }}
            }}
            connection.produced @filter(ge(connection.Start_Time_first_seen, "{from_timestamp}") AND le(connection.End_Time_last_seen, "{to_timestamp}")) {{
                expand(_all_)
            }}
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