#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of common connections queries for Granef API.
"""

import json  # Fast JSON parser
from fastapi import APIRouter  # FastAPI modules

import models  # Custom GranefAPI models
import queries_utils as qutils
from data_processing import DgraphDataProcessing  # Custom functions for input and output data processing


# Initialize FastAPI router
router = APIRouter()


@router.get("/local_connections", response_model=models.ResponseModel, 
summary="Perform get all connections in local network query")
def dgraph_query_local_connections(type: str = "json", layout: str = "sfdp"):
    # 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16
    query_body = """{ 
        getLocalConnections(func: allof(host.ip, cidr, "10.0.0.0/8")) { 
            label : host.ip
            host.ip
            host.originated {
                expand(Connection)
            }
            host.responded {
                expand(Connection)
            }
        } 
    }"""

    return qutils.handle_query(query_body=query_body, type=type, layout=layout)


@router.get("/hosts_interacted_with_file", response_model=models.ResponseModel, 
summary="Perform get hosts that interacted with specified file query")
def dgraph_query_hosts_interacted_with_file(file_attribute: str, hash: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_file_attribute("file_attribute", file_attribute)

    query_header = "query getFilesDetails($hash: string)"
    query_body = """{{
        getFilesDetails(func: eq(file.{file_attribute}, $hash)) {{
            expand(File)
            ~files.fuid {{
                expand(Files)
                ~connection.produced {{
                    expand(Connection)
                    ~host.originated {{
                        label : host.ip
                        host.ip
                    }}
                    ~host.responded {{
                        label : host.ip
                        host.ip
                    }}
                }}
            }}
        }}
    }}""".format(file_attribute=file_attribute)

    variables_dict = {"$hash": hash}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/http_uri_grouped", response_model=models.ResponseModel, 
summary="Perform get HTTP nodes grouped by uri query")
def dgraph_query_http_uri_grouped(type: str = "json", layout: str = "sfdp"):
    query_body = """{
        getHttpUri(func: type(Http)) @groupby(http.uri) {
            uri_count : count(uid)
        }
    }"""

    return qutils.handle_query(query_body=query_body, type=type, layout=layout)


# TODO: check why its not returning anything
@router.get("/http_uri_accessed", response_model=models.ResponseModel, 
summary="Perform get hosts that accessed HTTP uri query")
def dgraph_query_http_accessed(uri: str, type: str = "json", layout: str = "sfdp"):
    query_header = "query getHttpUriAccessed($uri: string)"
    query_body = """{ 
        getHttpUriAccessed(func: regexp(http.uri, /$uri/)) { 
            expand(Http)
            ~connection.produced {
                ~host.originated {
                    label : host.ip
                    host.ip
                }
                ~host.responded {
                    label : host.ip
                    host.ip
                }
            }
        } 
    }"""

    variables_dict = {"$uri": uri}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


# TODO: check if conn_state divided correctly!
@router.get("/not_established_connections", response_model=models.ResponseModel, 
summary="Perform get all not established connections of host query")
def dgraph_query_not_established_connections(host_ip: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_ip_address("host_ip", host_ip)

    query_header = "query getNotEstablishedConnections($host_ip: string)"
    query_body = """{ 
        getNotEstablishedConnections(func: eq(host.ip, $host_ip)) { 
            label : host.ip
            host.ip
            host.responded @filter(eq(connection.conn_state, "REJ") OR 
                  eq(connection.conn_state, "RSTR") OR 
                  eq(connection.conn_state, "S0")) {
                expand(Connection)
                # connection.produced {
                #   expand(_all_)
                # }
                ~host.originated {
                    label : host.ip
                    host.ip
                }
            }
        } 
    }"""

    variables_dict = {"$host_ip": host_ip}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/not_replied_to_connections", response_model=models.ResponseModel, 
summary="Perform get all not replied to connections of host query")
def dgraph_query_not_replied_to_connections(host_ip: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_ip_address("host_ip", host_ip)

    query_header = "query getNotEstablishedConnections($host_ip: string)"
    query_body = """{ 
        getNotRepliedToConnections(func: eq(host.ip, $host_ip)) { 
            label : host.ip
            host.ip
            host.responded @filter(eq(connection.conn_state, "S2") OR 
                  eq(connection.conn_state, "S3") OR 
                  eq(connection.conn_state, "RSTOS0") OR 
                  eq(connection.conn_state, "RSTRH") OR 
                  eq(connection.conn_state, "SHR")) {
                expand(Connection)
                ~host.originated {
                    label : host.ip
                    host.ip
                }
            }
        } 
    }"""

    variables_dict = {"$host_ip": host_ip}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/other_nonbasic_connections", response_model=models.ResponseModel, 
summary="Perform get all other non-basic connections of host query")
def dgraph_query_other_nonbasic_connections(host_ip: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_ip_address("host_ip", host_ip)

    query_header = "query getNotEstablishedConnections($host_ip: string)"
    query_body = """{ 
        getPartialConnections(func: eq(host.ip, $host_ip)) { 
            label : host.ip
            host.ip
            host.responded @filter(eq(connection.conn_state, "SH") OR eq(connection.conn_state, "OTH")) {
                expand(Connection)
                ~host.originated {
                    label : host.ip
                    host.ip
                }
            }
        } 
    }"""

    variables_dict = {"$host_ip": host_ip}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/conns_in_interval", response_model=models.ResponseModel, 
summary="Perform get hosts that communicated with each other based on some info in connections query")
def dgraph_query_conns_in_interval(chosen_func: str, conn_attribute: str, filter_value: str, type: str = "json", layout: str = "sfdp"):
    qutils.check_filter_func("chosen_func", chosen_func)
    qutils.check_conn_attribute("conn_attribute", conn_attribute)

    query_header = "query getHosts($filter_value: string)"
    query_body = """{{ 
        CONNS_IN_INTERVAL as var(func: {chosen_func}(connection.{conn_attribute}, $filter_value)) {{}}
        getHosts(func: uid(CONNS_IN_INTERVAL)) {{
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
    }}""".format(chosen_func=chosen_func, conn_attribute=conn_attribute)

    variables_dict = {"$filter_value": filter_value}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)


@router.get("/time", response_model=models.ResponseModel, 
summary="Perform get time of some connections query")
def dgraph_query_time(host_ip: str, type: str = "json", layout: str = "sfdp"):
    query_header = "query getHosts($host_ip: string)"
    query_body = """{ 
        getTime(func: eq(host.ip, $host_ip)) @normalize { 
            label : host.ip
            host.ip 
            host.originated @filter(ge(connection.conn_state, "RSTR") AND eq(connection.orig_bytes, 22)) {
                time as connection.ts
            }
            maxTime : max(val(time))
            minTime : min(val(time))
        } 
    }"""

    #TODO: some smarter way of filter building here!
    variables_dict = {"$host_ip": host_ip}
    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=type, layout=layout)
