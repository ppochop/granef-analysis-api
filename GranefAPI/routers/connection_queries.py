#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of connection queries for Granef web user interface.
"""

# FastAPI modules
from fastapi import APIRouter   # FastAPI modules

# GranefAPI
from models import models     # Custom GranefAPI models
from utilities import queries_utils as qutils     # Query utilities


# Initialize FastAPI router
router = APIRouter()


@router.get("/connections_search",
    response_model=models.ResponseModel,
    summary="Get connections and hosts according to defined criteria.")
def connections_search(src_ip: str, dst_ip: str, timestamp_from: str, timestamp_to: str, return_type: str = "json", graph_layout: str = "sfdp"):
    query_body = """{{
        connection(func: allof(Host.ip, cidr, "{src_ip}")) @cascade {{
            label: Host.ip
            Host.ip
            <~FlowRec.originated_by> @filter(between(FlowRec.first_ts, "{timestamp_from}", "{timestamp_to}")) {{
                label: FlowRec.protocol
                FlowRec.first_ts
                FlowRec.received_by @filter(allof(Host.ip, cidr, "{dst_ip}")) {{
                    label: Host.ip
                    Host.ip
                }}
            }}
        }}
    }}
    """.format(
        src_ip=src_ip,
        dst_ip=dst_ip,
        timestamp_from=timestamp_from + ":00",
        timestamp_to=timestamp_to + ":00"
    )
    print(query_body)
    return qutils.handle_query(query_body=query_body, query_header="", variables={}, type=return_type, layout=graph_layout)
