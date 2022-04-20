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
Definition of common analytical queries focused on network traffic analysis.
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
from .graph_queries import filter_uids


# Initialize FastAPI router
router = APIRouter()


@router.post("/connections_search",
    response_model=query_models.GeneralResponseList,
    summary="Search for connections within a specified time range and between two hosts.")
def connections_search(request: query_models.AdressesTimestampsQuery) -> dict:
    """
    Get all connections within the given time range and between defined two hosts. If only one address is
    defined, it is searched for all originating or responding connections. If only one timestamp is defined,
    it is searched for previous or next connections. If no address or host is defined, then all connections
    are returned.
    """
    # Set default request values
    address_orig = request.address_orig if request.address_orig else "0.0.0.0/0"
    address_resp = request.address_resp if request.address_resp else "0.0.0.0/0"
    timestamp_min = request.timestamp_min if request.timestamp_min else "1970-01-01T00:00:00"
    timestamp_max = request.timestamp_max if request.timestamp_max else "3000-01-01T00:00:00"

    # Validate IP address and raise exception if not valid
    validation.validate(address_orig, "address")
    validation.validate(address_resp, "address")
    
    dgraph_client = DgraphClient()

    query = f"""{{
        connections_search(func: allof(host.ip, cidr, "{address_orig}")) @cascade {{
            host.ip
            host.originated @filter(ge(connection.ts, "{timestamp_min}") and le(connection.ts, "{timestamp_max}")) {{
			    connection.ts
                connection.orig_p
                connection.resp_p
                connection.proto
                connection.conn_state
                ~host.responded @filter(allof(host.ip, cidr, "{address_resp}")) {{
				    host.ip
                }}
            }}
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["connections_search"]}
