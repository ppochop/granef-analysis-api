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
import itertools

# FastAPI modules
from fastapi import APIRouter
from fastapi import HTTPException

# GranefAPI
from models import query_models
from utilities import validation, preprocessing
from utilities.dgraph_client import DgraphClient
from .graph_queries import filter_uids


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
    validation.validate(request.address.strip(), "address")
    
    dgraph_client = DgraphClient()

    query = f"""{{
        hosts_info(func: allof(Host.ip, cidr, "{request.address.strip()}")) {{
            Host.ip
            Host.hostname {{
                Hostname.name
            }}
            Host.user_agent {{
                UserAgent.user_agent
            }}
            originated_count : count(<~FlowRec.originated_by>)
            received_count : count(<~FlowRec.received_by>)
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
    validation.validate(request.address.strip(), "address")

    dgraph_client = DgraphClient()

    query = f"""{{
	    connections_from_subnet(func: allof(Host.ip, cidr, "{request.address.strip()}")) @cascade {{
            Host.ip
            <~FlowRec.originated_by> {{
                FlowRec.first_ts
                FlowRec.orig_port
                FlowRec.recv_port
                FlowRec.protocol
                FlowRec.received_by {{
				    Host.ip
                }}
            }}
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["connections_from_subnet"]}


@router.post("/cluster_statistics",
    response_model=query_models.GeneralResponseDict,
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
            flow_first_ts as FlowRec.first_ts
            flow_last_ts as FlowRec.last_ts
            flow_orig_bytes as FlowRec.from_orig_bytes
            flow_resp_bytes as FlowRec.from_recv_bytes
            flow_orig_pkts as FlowRec.from_orig_pkts
            flow_resp_pkts as FlowRec.from_recv_pkts
        }}

        # Various statistics computation
        cluster_stats() {{
            first_ts_max : max(val(flow_first_ts))
            first_ts_min : min(val(flow_first_ts))
            last_ts_max : max(val(flow_last_ts))
            last_ts_min : min(val(flow_last_ts))
            flow_orig_bytes_max : max(val(flow_orig_bytes))
            flow_orig_bytes_min : min(val(flow_orig_bytes))
            flow_orig_bytes_avg : avg(val(flow_orig_bytes))
            flow_resp_bytes_max : max(val(flow_resp_bytes))
            flow_resp_bytes_min : min(val(flow_resp_bytes))
            flow_resp_bytes_avg : avg(val(flow_resp_bytes))
            flow_orig_pkts_max : max(val(flow_orig_pkts))
            flow_orig_pkts_min : min(val(flow_orig_pkts))
            flow_orig_pkts_avg : avg(val(flow_orig_pkts))
            flow_resp_pkts_max : max(val(flow_resp_pkts))
            flow_resp_pkts_min : min(val(flow_resp_pkts))
            flow_resp_pkts_avg : avg(val(flow_resp_pkts))
        }}
    
        # Counts on various aggregation functions
        node_type_count(func: uid(selection)) @groupby(dgraph.type) {{
		    node_type_count : count(uid)
	    }}
        dns_qtype_count(func: uid(selection)) @groupby(DNS.qtype_name) {{
			dns_qtype_count : count(uid)
        }}
        http_method_count(func: uid(selection)) @groupby(HTTP.method) {{
			http_method_count : count(uid)
        }}
        http_status_count(func: uid(selection)) @groupby(HTTP.status_code) {{
			http_status_count : count(uid)
        }}
        flow_proto_count(func: uid(selection)) @groupby(FlowRec.protocol) {{
			flow_proto_count : count(uid)
        }}
        flow_app_count(func: uid(selection)) @groupby(FlowRec.app) {{
			flow_app_count : count(uid)
        }}
        flow_source_count(func: uid(selection)) @groupby(FlowRec.flow_source) {{
			flow_source_count : count(uid)
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(query))

    # Reformat the result for better processing
    cluster_stats = {
        "node": {
            "type": None
        },
        "dns": {
            "qtype": None
        },
        "http": {
            "method": None,
            "status": None
        },
        "flow": {
            "first_ts": {
                "max": result["cluster_stats"][0].get("first_ts_max", "1970-01-01T00:00:00Z"),
                "min": result["cluster_stats"][1].get("first_ts_min", "1970-01-01T00:00:00Z")
            },
            "last_ts": {
                "max": result["cluster_stats"][2].get("last_ts_max", "1970-01-01T00:00:00Z"),
                "min": result["cluster_stats"][3].get("last_ts_min", "1970-01-01T00:00:00Z")
            },
            "orig_bytes": {
                "max": result["cluster_stats"][4].get("flow_orig_bytes_max", 0),
                "min": result["cluster_stats"][5].get("flow_orig_bytes_min", 0),
                "avg": result["cluster_stats"][6].get("flow_orig_bytes_avg", 0)
            },
            "resp_bytes": {
                "max": result["cluster_stats"][7].get("flow_resp_bytes_max", 0),
                "min": result["cluster_stats"][8].get("flow_resp_bytes_min", 0),
                "avg": result["cluster_stats"][9].get("flow_resp_bytes_avg", 0),
            },
            "orig_pkts": {
                "max": result["cluster_stats"][10].get("flow_orig_pkts_max", 0),
                "min": result["cluster_stats"][11].get("flow_orig_pkts_min", 0),
                "avg": result["cluster_stats"][12].get("flow_orig_pkts_avg", 0)
            },
            "resp_pkts": {
                "max": result["cluster_stats"][13].get("flow_resp_pkts_max", 0),
                "min": result["cluster_stats"][14].get("flow_resp_pkts_min", 0),
                "avg": result["cluster_stats"][15].get("flow_resp_pkts_avg", 0),
            },
            "proto": None,
            "app": None,
            "source": None,
        }
    }
    if "dns_qtype_count" in result:
        cluster_stats["dns"]["qtype"] = {}
        for dns_qtype_count in result["dns_qtype_count"][0]["@groupby"]:
            cluster_stats["dns"]["qtype"][dns_qtype_count["DNS.qtype_name"]] = dns_qtype_count["dns_qtype_count"]
    if "http_method_count" in result:
        cluster_stats["http"]["method"] = {}
        for http_method_count in result["http_method_count"][0]["@groupby"]:
            cluster_stats["http"]["method"][http_method_count["HTTP.method"]] = http_method_count["http_method_count"]
    if "http_status_count" in result:
        cluster_stats["http"]["status"] = {}
        for http_status_count in result["http_status_count"][0]["@groupby"]:
            cluster_stats["http"]["status"][http_status_count["HTTP.status_code"]] = http_status_count["http_status_count"]
    if "node_type_count" in result:
        cluster_stats["node"]["type"] = {}
        for node_type_count in result["node_type_count"][0]["@groupby"]:
            cluster_stats["node"]["type"][node_type_count["dgraph.type"]] = node_type_count["node_type_count"]
    if "flow_proto_count" in result:
        cluster_stats["flow"]["proto"] = {}
        for flow_proto_count in result["flow_proto_count"][0]["@groupby"]:
            cluster_stats["flow"]["proto"][flow_proto_count["FlowRec.protocol"]] = flow_proto_count["flow_proto_count"]
    if "flow_app_count" in result:
        cluster_stats["flow"]["app"] = {}
        for flow_app_count in result["flow_app_count"][0]["@groupby"]:
            cluster_stats["flow"]["app"][flow_app_count["FlowRec.app"]] = flow_app_count["flow_app_count"]
    if "flow_source_count" in result:
        cluster_stats["flow"]["source"] = {}
        for flow_source_count in result["flow_source_count"][0]["@groupby"]:
            cluster_stats["flow"]["source"][flow_source_count["FlowRec.flow_source"]] = flow_source_count["flow_source_count"]
    return {"response": cluster_stats}


@router.post("/adjacency_matrix",
    response_model=query_models.GeneralResponseDict,
    summary="Count of connections between all Host nodes, both specified by uids")
def adjacency_matrix(request: query_models.UidsQuery) -> dict:
    """
    Computes communication adjacency matrix for Hosts and Connections (specified by uids). Computes for each pair in the order
    as the following example -- uids: 0x1,0x77, counts: 0x1-0x1, 0x1-0x77, 0x77-0x1, 0x77-0x77.
    """
    dgraph_client = DgraphClient()


    # Select Connection and Host uids and iterate over each host pair (naive approach)
    connection_uids = ",".join(filter_uids(query_models.UidsTypesQuery(uids=request.uids, types="FlowRec"))["response"])
    host_uids = filter_uids(query_models.UidsTypesQuery(uids=request.uids, types="Host"))["response"]
    connections = []
    for host_uid_pair in itertools.product(host_uids, repeat=2):
        # Don't make queries for same uids
        if host_uid_pair[0] == host_uid_pair[1]:
            connections.append(0)
            continue

        query = f"""{{
            var(func: uid({host_uid_pair[0]})) @cascade {{
                originated as <~FlowRec.originated_by> @filter(uid({connection_uids})) {{
			        FlowRec.received_by @filter(uid({host_uid_pair[1]}))
                }}
            }}
            originated_connections(func: uid(originated)) {{
		        connections : count(uid)
            }}
        }}"""

        # Perform query and raise HTTP exception if any error occurs
        result = json.loads(dgraph_client.query(query))
        # Append result
        connections.append(result["originated_connections"][0].get("connections",0))

    # Split connections list to sub-lists according to the number of given uids
    connections_matrix = [connections[i:i + len(host_uids)] for i in range(0, len(connections), len(host_uids))] if len(host_uids) > 0 else []
    return {"response": {"uids": host_uids, "connections": connections_matrix}}
