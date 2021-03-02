#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of common host queries for Granef API.
"""

import json  # Fast JSON parser
from fastapi import APIRouter  # FastAPI modules

import models  # Custom GranefAPI models
import queries_utils as qutils
from data_processing import DgraphDataProcessing  # Custom functions for input and output data processing


# Initialize FastAPI router
router = APIRouter()


@router.get("/advanced_stats", response_model=models.ResponseModel, 
summary="Perform advanced statistics query")
def dgraph_query_advanced_stats(host_ip: str, type: str = "json", layout: str = "sfdp"):
    # Groupby function complicates graph drawing (we will not process it)
    if type != "json":
        qutils.raise_error("Only JSON request is allowed")

    qutils.check_ip_address("host_ip", host_ip)

    query_header = "query getProtocolsUsage($host_ip: string)"
    query_body = """{
        getProtocolsUsage(func: eq(host.ip, $host_ip)) @normalize {
            label : host.ip
            host.ip
            host.originated @groupby(connection.proto) {
                originated_count : count(uid)
            }
            host.responded @groupby(connection.proto) {
                responded_count : count(uid)
            }
        }
        getRespPortUsage(func: eq(host.ip, $host_ip)) @normalize {
            label : host.ip
            host.ip
            host.originated @groupby(connection.resp_p) {
                originated_count : count(uid)
            }
            host.responded @groupby(connection.resp_p) {
                responded_count : count(uid)
            }
        }
        getOrigPortUsage(func: eq(host.ip, $host_ip)) @normalize {
            label : host.ip
            host.ip
            host.originated @groupby(connection.orig_p) {
                originated_count : count(uid)
            }
            host.responded @groupby(connection.orig_p) {
                responded_count : count(uid)
            }
        }
    }"""

    variables_dict = {"$host_ip": host_ip}

    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/host_communicated", response_model=models.ResponseModel, 
summary="Perform get all hosts that communicated with specified host query")
def dgraph_query_hosts_communicated(host_ip: str, type: str = "json", layout: str = "sfdp"):
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
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/port_usage_host", response_model=models.ResponseModel, 
summary="Perform get port usage (both orig_p & resp_p) of hosts query")
def dgraph_query_port_usage_orig_p(host_ip: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_cidr("host_ip", host_ip)

    query_header = "query getPortsUsage($host_ip: string)"
    query_body = """{ 
        getPortsUsageOrigP(func: allof(host.ip, cidr, $host_ip)) { 
            label : host.ip
            host.ip
            host.responded @groupby(connection.orig_p) {
                resp_orig_p_count : count(uid)
            }
            host.originated @groupby(connection.orig_p) {
                orig_orig_p_count : count(uid)
            }
        } 
        getPortsUsageRespP(func: allof(host.ip, cidr, $host_ip)) { 
            label : host.ip
            host.ip
            host.responded @groupby(connection.resp_p) {
                resp_resp_p_count : count(uid)
            }
            host.originated @groupby(connection.resp_p) {
                orig_resp_p_count : count(uid)
            }
        } 
    }"""

    variables_dict = {"$host_ip": host_ip}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/count_http_conns", response_model=models.ResponseModel, 
summary="Perform get num of hosts HTTP connections query")
def dgraph_query_count_http_conns(host_ip: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_ip_address("host_ip", host_ip)

    # TODO: other types are possible here as well, are they interesting enough though?
    query_header = "query getHttpCount($host_ip: string)"
    query_body = """{
        getHttpCount(func: eq(host.ip, $host_ip)) @normalize {
            label : host.ip
            host.ip
            httpOrigNodes as math(1)
            host.originated {
                connection.produced @filter(type(Http)) {
                    httpOrigInside as math(httpOrigNodes)
                }
                httpOrigSum as sum(val(httpOrigInside))
            }
            httpOriginatedCount : sum(val(httpOrigSum))
            httpRespNodes as math(1)
            host.responded {
                connection.produced @filter(type(Http)) {
                    httpRespInside as math(httpRespNodes)
                }
                httpRespSum as sum(val(httpRespInside))
            }
            httpRespondedCount : sum(val(httpRespSum))
        }
    }"""

    variables_dict = {"$host_ip": host_ip}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/conns_from_to", response_model=models.ResponseModel, 
summary="Perform get all connections in interval connection.ts query")
def dgraph_query_conns_from_to(host_ip: str, from_ts_val: str, to_ts_val: str, type: str = "json", layout: str = "sfdp"):
    # Expected datetime format right now e.g.: '20/03/2019 08:00:00' (transformed to RFC3339 UTC timestamp)
    qutils.check_ip_address("host_ip", host_ip)
    from_ts_val = qutils.convert_to_datetime("from_ts_val", from_ts_val)
    to_ts_val = qutils.convert_to_datetime("to_ts_val", to_ts_val)

    query_header = "query getConnections($host_ip: string, $from_ts_val: string, $to_ts_val: string)"
    query_body = """{
        getConnections(func: eq(host.ip, $host_ip)) {
            label : host.ip
            host.ip
            host.originated @filter(ge(connection.ts, $from_ts_val) AND le(connection.ts, $to_ts_val)) {
                expand(Connection)
                ~host.responded {
                    label : host.ip
                    host.ip
                }
            }
        }
    }"""

    variables_dict = {"$host_ip": host_ip, "$from_ts_val": from_ts_val, "$to_ts_val": to_ts_val}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/specified_orig_conns", response_model=models.ResponseModel, 
summary="Perform get specified originated connections query")
def dgraph_query_specified_orig_conns(host_ip: str, chosen_func: str, conn_attribute: str, value: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_filter_func("chosen_func", chosen_func)
    qutils.check_conn_attribute("conn_attribute", conn_attribute)
    qutils.check_ip_address("host_ip", host_ip)

    query_header = "query getConnections($host_ip: string, $value: string)"
    query_body = """{{
        getSpecifiedConnections(func: eq(host.ip, $host_ip)) {{
            label : host.ip
            host.ip
  
            host.originated @filter({chosen_func}(connection.{conn_attribute}, $value)) {{
                expand(Connection)
                connection.produced {{
                    expand(_all_)
                }}
                ~host.responded {{
                    label : host.ip
                    host.ip
                }}
            }}
        }}
    }}""".format(chosen_func=chosen_func, conn_attribute=conn_attribute)

    variables_dict = {"$host_ip": host_ip, "$value": value}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/specified_resp_conns", response_model=models.ResponseModel, 
summary="Perform get specified responded connections query")
def dgraph_query_specified_resp_conns(host_ip: str, chosen_func: str, conn_attribute: str, value: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_filter_func("chosen_func", chosen_func)
    qutils.check_conn_attribute("conn_attribute", conn_attribute)
    qutils.check_ip_address("host_ip", host_ip)

    query_header = "query getConnections($host_ip: string, $value: string)"
    query_body = """{{
        getSpecifiedConnections(func: eq(host.ip, $host_ip)) {{
            label : host.ip
            host.ip
  
            host.responded @filter({chosen_func}(connection.{conn_attribute}, $value)) {{
                expand(Connection)
                connection.produced {{
                    expand(_all_)
                }}
                ~host.originated {{
                    label : host.ip
                    host.ip
                }}
            }}
        }}
    }}""".format(chosen_func=chosen_func, conn_attribute=conn_attribute)

    variables_dict = {"$host_ip": host_ip, "$value": value}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/conns_between_hosts_originated", response_model=models.ResponseModel, 
summary="Perform get all (originated) connections between two hosts query")
def dgraph_query_conns_between_hosts_originated(host_ip1: str, host_ip2: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_ip_address("host_ip1", host_ip1)
    qutils.check_ip_address("host_ip2", host_ip2)

    query_header = "query getConnectionsBetweenTwoHosts($host_ip1: string, $host_ip2: string)"
    query_body = """{
        var(func: eq(host.ip, $host_ip1)) {
            connectionsWithWantedHost as host.originated @cascade {
                ~host.responded @filter(eq(host.ip, $host_ip2)) {}
            }
        }
        getConnectionsBetweenTwoHosts(func: uid(connectionsWithWantedHost)) {
            expand(Connection)
            ~host.originated {
                label : host.ip
                expand(Host)
                host.hostname {
                    expand(Hostname)
                }
            }
            connection.produced {
                expand(_all_)
            }
        }
    }"""

    variables_dict = {"$host_ip1": host_ip1, "$host_ip2": host_ip2}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/conns_between_hosts_responded", response_model=models.ResponseModel, 
summary="Perform get all (responded) connections between two hosts query")
def dgraph_query_conns_between_hosts_responded(host_ip1: str, host_ip2: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_ip_address("host_ip1", host_ip1)
    qutils.check_ip_address("host_ip2", host_ip2)

    query_header = "query getConnectionsBetweenTwoHosts($host_ip1: string, $host_ip2: string)"
    query_body = """{
        var(func: eq(host.ip, $host_ip1)) {
            connectionsWithWantedHost as host.responded @cascade {
                ~host.originated @filter(eq(host.ip, $host_ip2)) {}
            }
        }
        getConnectionsBetweenTwoHosts(func: uid(connectionsWithWantedHost)) {
            expand(Connection)
            ~host.responded {
                label : host.ip
                expand(Host)
                host.hostname {
                    expand(Hostname)
                }
            }
            connection.produced {
                expand(_all_)
            }
        }
    }"""

    variables_dict = {"$host_ip1": host_ip1, "$host_ip2": host_ip2}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/conns_num_between_hosts", response_model=models.ResponseModel, 
summary="Perform get num of all connections between two hosts query")
def dgraph_query_conns_num_between_hosts(host_ip1: str, host_ip2: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_ip_address("host_ip1", host_ip1)
    qutils.check_ip_address("host_ip2", host_ip2)

    query_header = "query getNumOfConnections($host_ip1: string, $host_ip2: string)"
    query_body = """{
        var(func: eq(host.ip, $host_ip1)) {
            host.originated @cascade {
                origTmp as count(~host.responded) @filter(eq(host.ip, $host_ip2)) {}
            }
            originatedCount as sum(val(origTmp))
            host.responded @cascade {
                respondedTmp as count(~host.originated) @filter(eq(host.ip, $host_ip2)) {}
            }
            respondedCount as sum(val(respondedTmp))
        }
        getNumOfConnections(func: eq(host.ip, $host_ip1)) {
            label : host.ip
            host.ip
            originatedCount : val(originatedCount)
            respondedCount : val(respondedCount)
        }
    }"""

    variables_dict = {"$host_ip1": host_ip1, "$host_ip2": host_ip2}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/hosts_files", response_model=models.ResponseModel, 
summary="Perform get files of some host query")
def dgraph_query_hosts_files(host_ip: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_ip_address("host_ip", host_ip)

    query_header = "query getFiles($host_ip: string)"
    query_body = """{ 
        getFiles(func: eq(host.ip, $host_ip)) { 
            label : host.ip
            host.ip
            host.obtained {
                expand(File)
            }
            host.provided {
                expand(File)
            }
        } 
    }"""

    variables_dict = {"$host_ip": host_ip}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/hosts_files_detailed", response_model=models.ResponseModel, 
summary="Perform get details of files of a host query")
def dgraph_query_hosts_files_detailed(host_ip: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_ip_address("host_ip", host_ip)

    query_header = "query getFilesDetails($host_ip: string)"
    query_body = """{ 
        getFilesDetails(func: eq(host.ip, $host_ip)) { 
            label : host.ip
            host.ip
            host.obtained {
                expand(File)
                ~files.fuid {
                    expand(Files)
                    ~connection.produced {
                        expand(Connection)
                        ~host.responded {
                            label : host.ip
                            host.ip
                            host.hostname {
                                hostname.name 
                                hostname.type 
                            }
                        }
                        connection.produced {
                            expand(_all_)
                        }
                    }
                }
            }
            host.provided {
                expand(File)
                ~files.fuid {
                    expand(Files)
                    ~connection.produced {
                        expand(Connection)
                        ~host.responded {
                            label : host.ip
                            host.ip
                            host.hostname {
                                hostname.name 
                                hostname.type 
                            }
                        }
                        connection.produced {
                            expand(_all_)
                        }
                    }
                }
            }
        } 
    }"""

    variables_dict = {"$host_ip": host_ip}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)
