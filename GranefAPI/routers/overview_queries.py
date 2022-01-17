#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of queries providing an overview of the network data.
"""

# FastAPI modules
from fastapi import APIRouter   # FastAPI modules

# GranefAPI
from models import models     # Custom GranefAPI models
from utilities import queries_utils as qutils     # Query utilities


# Initialize FastAPI router
router = APIRouter()


@router.get("/hosts_info",
    response_model=models.ResponseModel,
    summary="Information about hosts in a given network range (CIDR).")
def hosts_info(host_ip: str, return_type: str = "json", graph_layout: str = "sfdp"):
    qutils.check_cidr("host_ip", host_ip)
    query_header = "query getStatistics($host_ip: string)"
    query_body = """{
        getStatistics(func: allof(host.ip, cidr, $host_ip)) {
            label : host.ip
            host.ip
            host.hostname {
                label : hostname.name
                hostname.name
                hostname.type
            }
            host.user_agent {
                label : user_agent.name
                user_agent.name
                user_agent.type
            }
            obtained_file_count : count(host.obtained)
            provided_file_count : count(host.provided)
            communicated_count : count(host.communicated)
            originated_count : count(host.originated)
            responded_count : count(host.responded)
            x509_count : count(host.x509)
        }
    }"""
    variables_dict = {"$host_ip": host_ip}
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=return_type, layout=graph_layout)


@router.get("/ioc",
    response_model=models.ResponseModel,    
    summary="Get all nodes with connection to IoC of selected platform.")
def ioc(platform: str, return_type: str = "json", graph_layout: str = "sfdp"):
    platforms = [x.strip() for x in platform.lower().split(',')]
    filter = "has(ioc.{platform})".format(platform=platforms[0])
    for ioc_platfrom in platforms[1:]:
        filter += "and has(ioc.{platform})".format(platform=ioc_platfrom)
    query_body = """{{
        getIocs(func: type(Ioc)) @filter({filter}) {{
            label: ioc.value
            ioc.type
            ioc.value
            ioc.misp {{
                label: misp.info
                misp.id
                misp.info
                misp.timestamp
                misp.url
            }}
            ~ioc {{
                expand(_all_)
            }}
        }}
    }}
    """.format(filter=filter)
    return qutils.handle_query(query_body=query_body, query_header="", variables={}, type=return_type, layout=graph_layout)
