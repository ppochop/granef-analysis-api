#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of helper queries functions for Granef API.
"""

# Common Python modules
import ipaddress
import socket
from datetime import datetime
import json

# FastAPI modules
from fastapi import HTTPException

# GranefAPI
from utilities.dgraph_client import DgraphClient
from utilities.data_processing import DgraphDataProcessing


def check_ip_address(param_name, param_val):
    try:
        socket.inet_aton(param_val)
    except socket.error:
        raise_error("Parameter '" + param_name + "' is not valid IP address (CIDR not supported).")


def check_cidr(param_name, param_val):
    try:
        ipaddress.ip_network(param_val)
    except ValueError:
        raise_error("Parameter '" + param_name + "' is not valid IP address in CIDR format.")


def convert_to_datetime(param_name, param_val):
    try:
        datetime_object = datetime.strptime(param_val, '%d/%m/%Y %H:%M:%S')
        datetime_iso = str(datetime_object.isoformat())
        return datetime_iso
    except:
        raise_error("Parameter '" + param_name + "' is expected to be in datetime '%m/%d/%y %H:%M:%S' format.")


def check_selected_count(param_name, param_val):
    possible_values = ["obtained_file_count", "provided_file_count", "originated_count", "responded_count", "x509_count"]
    if param_val not in possible_values:
        raise_error("Parameter '" + param_name + "' is not one of " + str(possible_values) + ".")


def check_port_type(param_name, param_val):
    possible_values = ["resp_p", "orig_p"]
    if param_val not in possible_values:
        raise_error("Parameter '" + param_name + "' is not one of " + str(possible_values) + ".")


def check_filter_func(param_name, param_val):
    possible_values = ["eq", "ge", "le", "gt", "lt"]
    if param_val not in possible_values:
        raise_error("Parameter '" + param_name + "' is not one of " + str(possible_values) + ".")


def check_ssh_attribute(param_name, param_val):
    possible_values = ["auth_attempts", "version", "client"]
    if param_val not in possible_values:
        raise_error("Parameter '" + param_name + "' is not one of " + str(possible_values) + ".")


def check_conn_attribute(param_name, param_val):
    possible_values = ["proto", "conn_state", "duration", "orig_bytes", "orig_ip_bytes", "orig_p", "orig_pkts", 
    "resp_bytes", "resp_ip_bytes", "resp_p", "resp_pkts", "service", "ts"]
    if param_val not in possible_values:
        raise_error("Parameter '" + param_name + "' is not one of " + str(possible_values) + ".")


def check_file_attribute(param_name, param_val):
    possible_values = ["md5", "sha1"]
    if param_val not in possible_values:
        raise_error("Parameter '" + param_name + "' is not one of " + str(possible_values) + ".")


def raise_error(msg):
    raise HTTPException(
        status_code = 400,
        detail = msg
    )


def handle_query(query_body: str, query_header: str = "", variables: dict = None, type: str = "json", layout: str = "sfdp"):
    """
    General function to process a Dgraph query. Result is provided as a JSON response or 
    extended by graph data according to desired query type.
    """
    dgraph_client = DgraphClient()
    dgraph_processing = DgraphDataProcessing(type=type, layout=layout)
    processed_query_str = query_header + dgraph_processing.process_query(query_body)

    # Perform query and raise HTTP exception if any error occures
    try:
        # Preprocess query according to the query type
        result = dgraph_client.query(processed_query_str, variables)
    except Exception as e:
        raise_error(str(e))

    # Process response accoring to the query type   
    return {"response": dgraph_processing.process_response(response=json.loads(result))}
