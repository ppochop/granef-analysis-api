#! /usr/bin/env python3
# -*- coding: utf-8 -*-

#
# Granef -- graph-based network forensics toolkit
# Copyright (C) 2020-2021  Milan Cermak, Institute of Computer Science of Masaryk University
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
Definition of queries providing an overview of the network data.
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


@router.post("/hosts_info",
    response_model=query_models.GeneralResponseList,
    summary="Information about hosts in a given network range (CIDR).")
def hosts_info(request: query_models.AddressQuery) -> dict:
    """
    Get detailed attributes and statitsics about hosts in the given network range.
    """
    # Validate IP address and raise exception if not valid
    validation.validate(request.address, "address")
    
    dgraph_client = DgraphClient()

    query = f"""{{
        hosts_info(func: allof(host.ip, cidr, "{request.address}")) {{
            host.ip
            host.hostname {{
                hostname.name
                hostname.type
            }}
            host.user_agent {{
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
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["hosts_info"]}


@router.post("/connections_from_subnet",
    response_model=query_models.GeneralResponseList,
    summary="Connections originated by hosts in a given network range (CIDR).")
def connections_from_subnet(request: query_models.AddressQuery) -> dict:
    """
    Get all connections within the given subnet.
    """
    # Validate IP address and raise exception if not valid
    validation.validate(request.address, "address")

    dgraph_client = DgraphClient()

    query = f"""{{
	    connections_from_subnet(func: allof(host.ip, cidr, "{request.address}")) @cascade {{
            host.ip
            host.originated {{
                connection.ts
                connection.orig_p
                connection.resp_p
                connection.proto
                connection.conn_state
                ~host.responded {{
				    host.ip
                }}
            }}
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["connections_from_subnet"]}


@router.post("/cluster_statistics",
    response_model=query_models.GeneralResponseList,
    summary="Statistics overview of a nodes cluster specified by uids")
def cluster_statistics(request: query_models.UidsQuery) -> dict:
    """
    Computes various statistics for a given cluster (specified as uids) to provide cluster overview.
    """
    dgraph_client = DgraphClient()

    query = f"""{{
        # Common stats and variables definition
        var(func: uid({request.uids})) {{
            selection as uid
            file_bytes as file.total_bytes
            files_total as files.total_bytes
            files_missing as files.missing_bytes
            files_overflow as files.overflow_bytes
            conn_ts as connection.ts
            conn_orig_bytes as connection.orig_bytes
            conn_resp_bytes as connection.resp_bytes
        }}
        var(func: uid(selection)) @filter(type(Ssl) AND not eq(ssl.validation_status,"ok")) {{
			ssl_invalid as math(1)
        }}

        # Various statistics computation
        cluster_stats() {{
			file_bytes_max : max(val(file_bytes))
            file_bytes_min : min(val(file_bytes))
            file_bytes_avg : avg(val(file_bytes))
            files_total_max : max(val(files_total))
            files_total_min : min(val(files_total))
            files_total_avg : avg(val(files_total))
            files_missing_max : max(val(files_missing))
            files_missing_min : min(val(files_missing))
            files_missing_avg : avg(val(files_missing))
            files_overflow_max : max(val(files_overflow))
            files_overflow_min : min(val(files_overflow))
            files_overflow_avg : avg(val(files_overflow))
            ssl_invalid_count : sum(val(ssl_invalid))
            conn_ts_max : max(val(conn_ts))
            conn_ts_min : min(val(conn_ts))
            conn_orig_bytes_max : max(val(conn_orig_bytes))
            conn_orig_bytes_min : min(val(conn_orig_bytes))
            conn_orig_bytes_avg : avg(val(conn_orig_bytes))
            conn_resp_bytes_max : max(val(conn_resp_bytes))
            conn_resp_bytes_min : min(val(conn_resp_bytes))
            conn_resp_bytes_avg : avg(val(conn_resp_bytes))
        }}
    
        # Counts on various aggregation functions
        node_type_count(func: uid(selection)) @groupby(dgraph.type) {{
		    node_type_count : count(uid)
	    }}
        ioc_type_count(func: uid(selection)) @groupby(ioc.type) {{
		    ioc_type_count : count(uid)
        }}
        file_mime_count(func: uid(selection)) @groupby(file.mime_type) {{
			file_mime_count : count(uid)
        }}
        dns_qtype_count(func: uid(selection)) @groupby(dns.qtype_name) {{
			dns_qtype_count : count(uid)
        }}
        ftp_mime_count(func: uid(selection)) @groupby(ftp.mime_type) {{
			ftp_mime_count : count(uid)
        }}
        ftp_reply_count(func: uid(selection)) @groupby(ftp.reply_code) {{
			ftp_reply_count : count(uid)
        }}
        http_method_count(func: uid(selection)) @groupby(http.method) {{
			http_method_count : count(uid)
        }}
        http_status_count(func: uid(selection)) @groupby(http.status_code) {{
			http_status_count : count(uid)
        }}
        conn_state_count(func: uid(selection)) @groupby(connection.conn_state) {{
			conn_state_count : count(uid)
        }}
        conn_proto_count(func: uid(selection)) @groupby(connection.proto) {{
			conn_proto_count : count(uid)
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(query))

    # Reformat the result for better processing
    cluster_stats = {
        "node": {
            "type": {}
        },
        "ioc": {
            "type": {}
        },
        "dns": {
            "qtype": {}
        },
        "http": {
            "method": {},
            "status": {}
        },
        "file": {
            "bytes": {
                "max": result["cluster_stats"][0].get("file_bytes_max", 0),
                "min": result["cluster_stats"][1].get("file_bytes_min", 0),
                "avg": result["cluster_stats"][2].get("file_bytes_avg", 0)
            },
            "mime_type": {}
        },
        "files": {
            "total_bytes": {
                "max": result["cluster_stats"][3].get("files_total_max", 0),
                "min": result["cluster_stats"][4].get("files_total_min", 0),
                "avg": result["cluster_stats"][5].get("files_total_avg", 0)
            },
            "missing_bytes": {
                "max": result["cluster_stats"][6].get("files_missing_max", 0),
                "min": result["cluster_stats"][7].get("files_missing_min", 0),
                "avg": result["cluster_stats"][8].get("files_missing_avg", 0)
            },
            "overflow_bytes": {
                "max": result["cluster_stats"][9].get("files_overflow_max", 0),
                "min": result["cluster_stats"][10].get("files_overflow_min", 0),
                "avg": result["cluster_stats"][11].get("files_overflow_avg", 0)
            }
        },
        "ssl": {
            "invalid": result["cluster_stats"][12].get("ssl_invalid_count", 0)
        },
        "connection": {
            "ts": {
                "max": result["cluster_stats"][13].get("conn_ts_max", "1970-01-01T00:00:00Z"),
                "min": result["cluster_stats"][14].get("conn_ts_min", "1970-01-01T00:00:00Z")
            },
            "orig_bytes": {
                "max": result["cluster_stats"][15].get("conn_orig_bytes_max", 0),
                "min": result["cluster_stats"][16].get("conn_orig_bytes_min", 0),
                "avg": result["cluster_stats"][17].get("conn_orig_bytes_avg", 0)
            },
            "resp_bytes": {
                "max": result["cluster_stats"][18].get("conn_resp_bytes_max", 0),
                "min": result["cluster_stats"][19].get("conn_resp_bytes_min", 0),
                "avg": result["cluster_stats"][20].get("conn_resp_bytes_avg", 0),
            },
            "state": {},
            "proto": {}
        }
    }
    for node_type_count in result["node_type_count"][0]["@groupby"]:
        cluster_stats["node"]["type"][node_type_count["dgraph.type"]] = node_type_count["node_type_count"]
    for ioc_type_count in result["ioc_type_count"][0]["@groupby"]:
        cluster_stats["ioc"]["type"][ioc_type_count["ioc.type"]] = ioc_type_count["ioc_type_count"]
    for file_mime_count in result["file_mime_count"][0]["@groupby"]:
        cluster_stats["file"]["mime_type"][file_mime_count["file.mime_type"]] = file_mime_count["file_mime_count"]
    for dns_qtype_count in result["dns_qtype_count"][0]["@groupby"]:
        cluster_stats["dns"]["qtype"][dns_qtype_count["dns.qtype_name"]] = dns_qtype_count["dns_qtype_count"]
    for http_method_count in result["http_method_count"][0]["@groupby"]:
        cluster_stats["http"]["method"][http_method_count["http.method"]] = http_method_count["http_method_count"]
    for http_status_count in result["http_status_count"][0]["@groupby"]:
        cluster_stats["http"]["status"][http_status_count["http.status_code"]] = http_status_count["http_status_count"]
    for conn_state_count in result["conn_state_count"][0]["@groupby"]:
        cluster_stats["connection"]["state"][conn_state_count["connection.conn_state"]] = conn_state_count["conn_state_count"]
    for conn_proto_count in result["conn_proto_count"][0]["@groupby"]:
        cluster_stats["connection"]["proto"][conn_proto_count["connection.proto"]] = conn_proto_count["conn_proto_count"]

    return {"response": cluster_stats}
