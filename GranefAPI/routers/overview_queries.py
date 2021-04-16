#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of queries providing an overview of the network data.
"""

# Common Python modules
import json

# FastAPI modules
from fastapi import APIRouter
from fastapi import HTTPException

# GranefAPI
from models import query_models
from utilities import validation
from utilities.dgraph_client import DgraphClient


# Initialize FastAPI router
router = APIRouter()


@router.get("/hosts_info",
    response_model=query_models.GeneralResponse,
    summary="Information about hosts in a given network range (CIDR).")
def hosts_info(address: str) -> dict:
    """
    Get detailed attributes and statitsics about hosts in the given network range.
    """
    if not validation.is_address(address):
        raise HTTPException(
            status_code = 400,
            detail = f"Given address {address} is not valid IPv4, IPv6 address, or CIDR notation."
        )
    dgraph_client = DgraphClient()

    query = f"""{{
        getStatistics(func: allof(host.ip, cidr, "{address}")) {{
            label : host.ip
            host.ip
            host.hostname {{
                label : hostname.name
                hostname.name
                hostname.type
            }}
            host.user_agent {{
                label : user_agent.name
                user_agent.name
                user_agent.type
            }}
            obtained_file_count : count(host.obtained)
            provided_file_count : count(host.provided)
            communicated_count : count(host.communicated)
            originated_count : count(host.originated)
            responded_count : count(host.responded)
            x509_count : count(host.x509)
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


# @router.get("/hosts_communication",
#     response_model=models.ResponseModel, 
#     summary="Get all hosts with a connection from a given network range (CIDR)")
# def hosts_communication(host_ip: str, return_type: str = "json", graph_layout: str = "sfdp"):
#     qutils.check_cidr("host_ip", host_ip)
#     query_header = "query getCommunicatedHosts($host_ip: string)"
#     query_body = """{ 
#         getCommunicatedHosts(func: allof(host.ip, cidr, $host_ip)) { 
#             label : host.ip
#             host.ip
#             host.communicated {
#                 label : host.ip
#                 host.ip
#             }
#         } 
#     }"""
#     variables_dict = {"$host_ip": host_ip}
#     return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=return_type, layout=graph_layout)
