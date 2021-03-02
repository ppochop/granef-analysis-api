#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of common network queries for Granef API.
"""

import json  # Fast JSON parser
from fastapi import APIRouter  # FastAPI modules

import models  # Custom GranefAPI models
import queries_utils as qutils
from data_processing import DgraphDataProcessing  # Custom functions for input and output data processing


# Initialize FastAPI router
router = APIRouter()


@router.get("/stats", response_model=models.ResponseModel, summary="Perform statistics query")
def dgraph_query_stats(host_ip: str, type: str = "json", layout: str = "sfdp"):
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

    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/stats_based_on_count", response_model=models.ResponseModel, summary="Perform statistics based on some filter query")
def dgraph_query_stats_based_on_count(selected_count: str, count_value: int, type: str = "json", layout: str = "sfdp"):
    qutils.check_selected_count("selected_count", selected_count)

    query_header = "query getHostInfo($count_value: string)"
    query_body = """{{ 
        STATISTICS as var(func: type(Host)) {{
            obtained_file_count as count(host.obtained)
            provided_file_count as count(host.provided)
            originated_count as count(host.originated)
            responded_count as count(host.responded)
            x509_count as count(host.x509)
        }}
        getHostInfo(func: uid(STATISTICS), orderasc: val({selected_count}))
        @filter(ge(val({selected_count}), $count_value)) {{
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
            obtained_files : val(obtained_file_count)
            provided_files : val(provided_file_count)
            originated : val(originated_count)
            responded : val(responded_count)
            x509 : val(x509_count)
        }}
    }}""".format(selected_count=selected_count)

    variables_dict = {"$count_value": str(count_value)}

    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/local_hosts", response_model=models.ResponseModel, 
summary="Perform get all hosts in local network query")
def dgraph_query_local_hosts(type: str = "json", layout: str = "sfdp"):
    # 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16
    query_body = """{ 
        getLocalHosts(func: allof(host.ip, cidr, "10.0.0.0/8")) { 
            label : host.ip
            host.ip
        } 
    }"""

    return qutils.handle_query(query_body=query_body, type=type, layout=layout)


@router.get("/host_conns", response_model=models.ResponseModel, 
summary="Perform get all connections of host(s) query")
def dgraph_query_hosts_conns(host_ip: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_cidr("host_ip", host_ip)

    query_header = "query getAllConnections($host_ip: string)"
    query_body = """{
        getAllConnections(func: allof(host.ip, cidr, $host_ip)) {
            label : host.ip
            host.ip
            host.originated {
                expand(Connection)
                connection.produced {
                    expand(_all_)
                }
                ~host.responded {
                    label : host.ip
                    host.ip
                }
            }
            host.responded {
                expand(Connection)
                connection.produced {
                    expand(_all_)
                }
                ~host.originated {
                    label : host.ip
                    host.ip
                }
            }
        }
    }"""

    variables_dict = {"$host_ip": host_ip}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/host_communicated_filter", response_model=models.ResponseModel, 
summary="Perform get all hosts that communicated with more than count_value hosts query")
def dgraph_query_hosts_communicated_filter(host_ip: str, count_value: int, type: str = "json", layout: str = "sfdp"):
    qutils.check_cidr("host_ip", host_ip)

    query_header = "query getHostInfo($host_ip: string, $count_value: string)"
    query_body = """{ 
        COMMUNICATIONS as var(func: allof(host.ip, cidr, $host_ip)) {
            communicated_count as count(host.communicated)
        }
        getHostInfo(func: uid(COMMUNICATIONS), orderdesc: val(communicated_count)) 
              @filter(ge(val(communicated_count), $count_value)) {
            label : host.ip
            host.ip
            communicated_with_count : val(communicated_count)
            host.communicated {
                expand(Host)
            }
        } 
    }"""

    variables_dict = {"$host_ip": host_ip, "$count_value": str(count_value)}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/protocols_usage", response_model=models.ResponseModel, 
summary="Perform get protocol usage query")
def dgraph_query_protocol_usage(type: str = "json", layout: str = "sfdp"):
    # Groupby function complicates graph drawing (we will not process it)
    if type != "json":
        qutils.raise_error("Only JSON request is allowed")

    query_body = """{ 
        getProtocolsUsage(func: type(Connection)) @groupby(connection.proto) { 
            count(uid)
        } 
    }"""

    return qutils.handle_query(query_body=query_body, type=type, layout=layout)


@router.get("/ports_usage", response_model=models.ResponseModel, 
summary="Perform get ports usage (both resp_p & orig_p) query")
def dgraph_query_ports_usage_resp_p(type: str = "json", layout: str = "sfdp"):
    query_body = """{ 
        getPortsUsageOverallRespP(func: type(Connection)) @groupby(connection.resp_p) { 
            count(uid)
        } 

        getPortsUsageOverallOrigP(func: type(Connection)) @groupby(connection.orig_p) { 
            count(uid)
        } 
    }"""

    return qutils.handle_query(query_body=query_body, type=type, layout=layout)


@router.get("/port_conns", response_model=models.ResponseModel, 
summary="Perform get connections that were directed at specified port and hosts that communicated that way query")
def dgraph_query_port_conns(port_type: str, port: int, type: str = "json", layout: str = "sfdp"):
    qutils.check_port_type("port_type", port_type)

    query_header = "query getPortCommunications($port: string)"
    query_body = """{{ 
        getPortCommunications(func: eq(connection.{port_type}, $port)) {{
            expand(Connection)
            ~host.originated {{
                label : host.ip
                host.ip
            }}
            ~host.responded {{
                label : host.ip
                host.ip
            }}
            connection.produced {{
                expand(_all_)
            }}
        }}
    }}""".format(port_type=port_type)

    #TODO: [22, 80] "Dgraph parse int" not working
    variables_dict = {"$port": str(port)}

    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/all_ssh_conns", response_model=models.ResponseModel, 
summary="Perform get all SSH connections query")
def dgraph_query_all_ssh_conns(type: str = "json", layout: str = "sfdp"):
    query_body = """{
        getSsh(func: type(Ssh)) {
            expand(Ssh)
        }
    }"""

    return qutils.handle_query(query_body=query_body, type=type, layout=layout)
    # TODO: fix "Received message larger than max (4857925 vs. 4194304)", ok in Ratel GUI


@router.get("/ssh_conns_filtered", response_model=models.ResponseModel, 
summary="Perform get SSH connections with filter query")
def dgraph_query_ssh_conns_filtered(chosen_func: str, ssh_attribute: str, par_value: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_filter_func("chosen_func", chosen_func)
    qutils.check_ssh_attribute("ssh_attribute", ssh_attribute)
    # TODO: check if par_value is int if ssh_attribute == auth_attempts, version? skip for now

    query_header = "query getSsh($par_value: string)"
    query_body = """{{
        getSsh(func: type(Ssh)) @filter({chosen_func}(ssh.{ssh_attribute}, $par_value)) {{
            expand(Ssh)
            ~connection.produced {{
            expand(Connection)
                ~host.originated {{
                    label : host.ip
                    host.ip
                }}
            }}
        }}
    }}""".format(chosen_func=chosen_func, ssh_attribute=ssh_attribute)

    variables_dict = {"$par_value": par_value}

    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)
