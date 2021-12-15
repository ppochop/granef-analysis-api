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
Definition of common network flow queries for Granef API.
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


@router.post("/subnet_info", 
    response_model=query_models.GeneralResponseList, 
    summary="Perform statistics query about given subnet mask.")
def subnet_info(request: query_models.AdressProtocolTimestampsQuery) -> dict:
    
    # Validate IP address and raise exception if not valid
    validation.validate(request.address, "address")

    dgraph_client = DgraphClient()

    query = f"""{{ 
        subnet_info(func: allof(host.ip, cidr, "{request.address}")) {{ 
            label : host.ip
            host.ip
            host.originated @filter(ge(connection.Start_Time_first_seen, "{request.timestamp_min}") AND le(connection.Start_Time_first_seen, "{request.timestamp_max}")) {{
                connection.produced @filter(eq(dgraph.type, "{request.protocol}")) {{
                    expand(_all_)
                }}
                ~host.responded {{
                    label : host.ip
                    host.ip
                }}
            }}
            host.responded @filter(ge(connection.Start_Time_first_seen, "{request.timestamp_min}") AND le(connection.Start_Time_first_seen, "{request.timestamp_max}")) {{
                connection.produced @filter(eq(dgraph.type, "{request.protocol}")) {{
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
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["subnet_info"]}


@router.post("/connection_info", 
    response_model=query_models.GeneralResponseList, 
    summary="Return connections in specified time interval.")
def connection_info(request: query_models.UidsTimestampsRangeQuery) -> dict:

    dgraph_client = DgraphClient()
    
    query = f"""{{
        connection_info(func: has(host.ip)) {{
            label : host.ip
            host.ip
            host.originated @filter(ge(connection.Start_Time_first_seen, "{request.timestamp_min}") AND le(connection.Start_Time_first_seen, "{request.timestamp_max}")) {{
                connection.Start_Time_first_seen
                connection.Source_Address
                connection.Destination_Address
                connection.Destination_Port
                connection.Protocol
                ~host.responded {{
                    label : host.ip
                    host.ip
                }}
                connection.produced {{
                    expand(HTTP_formats)
                }}
            }}
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["connection_info"]}


@router.post("/host_connections_info", 
    response_model=query_models.GeneralResponseList, 
    summary="Return host's connections in a specified time interval.")
def host_connections_info(request: query_models.AddressTimestampsQuery) -> dict:

    # Validate IP address and raise exception if not valid
    validation.validate(request.address, "address")

    dgraph_client = DgraphClient()

    query = f"""{{
        host_connections_info(func: eq(host.ip, "{request.address}")) {{
            label : host.ip
            host.ip
            host.originated @filter(ge(connection.Start_Time_first_seen, "{request.timestamp_min}") AND le(connection.End_Time_last_seen, "{request.timestamp_max}")) {{
                connection.Start_Time_first_seen
                connection.Source_Address
                connection.Destination_Address
                connection.Destination_Port
                connection.Protocol
                ~host.responded {{
                    label : host.ip
                    host.ip
                }}
            }}
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["host_connections_info"]}


@router.post("/host_protocol_usage", 
    response_model=query_models.GeneralResponseList, 
    summary="Return usage of protocol and ports information about the specified host.")
def host_protocol_usage(request: query_models.AddressQuery) -> dict:

    # Validate IP address and raise exception if not valid
    validation.validate(request.address, "address")

    dgraph_client = DgraphClient()
    
    query = f"""{{
        getProtocolsUsage(func: eq(host.ip, "{request.address}")) @normalize {{
            label : host.ip
            host.ip
            host.originated @groupby(connection.Protocol) {{
                originated_count : count(uid)
            }}
            host.responded @groupby(connection.Protocol) {{
                responded_count : count(uid)
            }}
        }}
        getRespPortUsage(func: eq(host.ip, "{request.address}")) @normalize {{
            label : host.ip
            host.ip
            host.originated @groupby(connection.Destination_Port) {{
                originated_count : count(uid)
            }}
            host.responded @groupby(connection.Destination_Port) {{
                responded_count : count(uid)
            }}
        }}
        getOrigPortUsage(func: eq(host.ip, "{request.address}")) @normalize {{
            label : host.ip
            host.ip
            host.originated @groupby(connection.Source_Port) {{
            originated_count : count(uid)
            }}
            host.responded @groupby(connection.Port) {{
            responded_count : count(uid)
            }}
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["host_protocol_usage"]}


@router.post("/communicated_hosts", 
    response_model=query_models.GeneralResponseList, 
    summary="List of all hosts that communicate with specified host.")
def communicated_hosts(request: query_models.AddressQuery) -> dict:

    # Validate IP address and raise exception if not valid
    validation.validate(request.address, "address")

    dgraph_client = DgraphClient()
    
    query = f"""{{
        communicated_hosts(func: allof(host.ip, cidr, "{request.address}")) {{
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
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["communicated_hosts"]}


@router.post("/responded_hosts", 
    response_model=query_models.GeneralResponseList, 
    summary="List of all hosts that responded to a specific host.")
def responded_hosts(request: query_models.AddressTimestampQuery) -> dict:

    # Validate IP address and raise exception if not valid
    validation.validate(request.address, "address")

    dgraph_client = DgraphClient()
    
    query = f"""{{
        responded_hosts(func: allof(host.ip, cidr, "{request.address}")) {{ 
            label : host.ip
            host.responded @filter(lt(connection.Start_Time_first_seen, "{request.timestamp}")) @groupby(connection.Source_Address) {{
                count(uid)
            }}
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["responded_hosts"]}


@router.post("/originated_hosts", 
    response_model=query_models.GeneralResponseList, 
    summary="List of all hosts that originated connection to a specific host.")
def originated_hosts(request: query_models.AddressTimestampQuery) -> dict:

    # Validate IP address and raise exception if not valid
    validation.validate(request.address, "address")

    dgraph_client = DgraphClient()
    
    query = f"""{{
        originated_hosts(func: allof(host.ip, cidr, "{request.address}")) {{ 
            label : host.ip
            host.originated @filter(gt(connection.Start_Time_first_seen, "{request.timestamp}")) @groupby(connection.Destination_Address) {{
                count(uid)
            }}
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["originated_hosts"]}


@router.post("/communicated_hostnames_count", 
    response_model=query_models.GeneralResponseList, 
    summary="Count all hostnames, which host communicates with the specified host.")
def communicated_hostnames_count(request: query_models.AddressProtocolQuery) -> dict:

    # Validate IP address and raise exception if not valid
    validation.validate(request.address, "address")
    
    dgraph_client = DgraphClient()
    
    query = f"""{{
        communicated_hostnames_count(func: allof(host.ip, cidr, "{request.address}")) {{
            label : host.ip
            host.ip
            host.communicated {{
                label : host.ip
                host.ip
                host.hostname @filter(eq(hostname.type, "{request.protocol}")) @groupby(hostname.name) {{
                    count(uid)
                }}
            }}
        }} 
    }}"""
    
    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["communicated_hostnames_count"]}


@router.post("/connection_between_two_hosts", 
    response_model=query_models.GeneralResponseList, 
    summary="List of all originated connections between two hosts.")
def connection_between_two_hosts(request: query_models.AdressesTimestampsQuery) -> dict:

    # Validate IP address and raise exception if not valid
    validation.validate(request.address_first, "address")
    validation.validate(request.address_second, "address")
    
    dgraph_client = DgraphClient()
    
    query = f"""{{
        var(func: eq(host.ip, "{request.address_first}")) {{
            connectionsWithWantedHost as host.originated @cascade {{
                ~host.responded @filter(eq(host.ip, "{request.address_second}")) {{}}
            }}
        }}
        connection_between_two_hosts(func: uid(connectionsWithWantedHost)) {{
            expand(connection)

            ~host.originated @filter(ge(connection.Start_Time_first_seen, "{request.timestamp_min}") AND le(connection.End_Time_last_seen, "{request.timestamp_max}")) {{
                label : host.ip
                host.hostname {{
                    label: hostname.type
                    hostname.name
                }}
            }}
            connection.produced @filter(ge(connection.Start_Time_first_seen, "{request.timestamp_min}") AND le(connection.End_Time_last_seen, "{request.timestamp_max}")) {{
                expand(_all_)
            }}
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["connection_between_two_hosts"]}


@router.post("/resp_port_usage_between_two_hosts", 
    response_model=query_models.GeneralResponseList, 
    summary="Return count of all used response ports between two hosts.")
def resp_port_usage_between_two_hosts(request: query_models.AdressesQuery) -> dict:

    # Validate IP address and raise exception if not valid
    validation.validate(request.address_first, "address")
    validation.validate(request.address_second, "address")
    
    dgraph_client = DgraphClient()
    
    query = f"""{{
        var(func: eq(host.ip, "{request.address_first}")) {{
            connectionsWithWantedHost as host.originated @cascade {{
                ~host.responded @filter(eq(host.ip, "{request.address_second}")) {{}}
            }}
        }}
        
        resp_port_usage_between_two_hosts (func: uid(connectionsWithWantedHost)) @groupby(connection.Destination_Port) {{
            responded_count : count(uid)
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["resp_port_usage_between_two_hosts"]}


@router.post("/sum_input_bytes", 
    response_model=query_models.GeneralResponseList, 
    summary="Return sum of input bytes.")
def getSumsum_input_bytesOfOInputBytes(request: query_models.AddressTimestampQuery) -> dict:

    # Validate IP address and raise exception if not valid
    validation.validate(request.address, "address")
    
    dgraph_client = DgraphClient()
    
    query = f"""{{
        sum_input_bytes(func: allof(host.ip, cidr, "{request.address}")) {{ 
            label : host.ip
            host.originated @filter(gt(connection.Start_Time_first_seen, "{request.timestamp}")) @groupby(connection.Destination_Address) {{
                sum(connection.Input_Bytes)
            }}
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["sum_input_bytes"]}


@router.post("/count_communication_of_host", 
    response_model=query_models.GeneralResponseList, 
    summary="Return count of found communication of specific host.")
def count_communication_of_host(request: query_models.AddressTimestampQuery) -> dict:

    # Validate IP address and raise exception if not valid
    validation.validate(request.address, "address")
    
    dgraph_client = DgraphClient()
    
    query = f"""{{
        count_communication_of_host(func: allof(host.ip, cidr, "{request.address}")) {{ 
            label : host.ip
            host.originated @filter(gt(connection.Start_Time_first_seen, "{request.timestamp}")) @groupby(connection.Destination_Address) {{
                count(uid)
            }}
            host.responded @filter(gt(connection.Start_Time_first_seen, "{request.timestamp}")) @groupby(connection.Source_Address) {{
                count(uid)
            }}
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["count_communication_of_host"]}
