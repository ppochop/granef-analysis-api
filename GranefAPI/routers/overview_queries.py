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


@router.get("/hosts_communication",
    response_model=models.ResponseModel, 
    summary="Get all hosts with a connection from a given network range (CIDR)")
def hosts_communication(host_ip: str, return_type: str = "json", graph_layout: str = "sfdp"):
    qutils.check_cidr("host_ip", host_ip)
    query_header = "query getCommunicatedHosts($host_ip: string)"
    query_body = """{ 
        getCommunicatedHosts(func: allof(host.ip, cidr, $host_ip)) { 
            label : host.ip
            host.ip
            host.communicated {
                label : host.ip
                host.ip
            }
        } 
    }"""
    variables_dict = {"$host_ip": host_ip}
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=return_type, layout=graph_layout)
