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
from utilities import validation, processing
from utilities.dgraph_client import DgraphClient


# Initialize FastAPI router
router = APIRouter()


@router.get("/hosts_info",
    response_model=query_models.GeneralResponse,
    summary="Information about hosts in a given network range (CIDR).")
def hosts_info(address: str) -> dict:
    """
    Get detailed attributes and statitsics about hosts in the given network range.
    """
    if not validation.is_address(address):
        raise HTTPException(
            status_code = 400,
            detail = f"Given address {address} is not valid IPv4, IPv6 address, or CIDR notation."
        )
    dgraph_client = DgraphClient()

    query = f"""{{
        getStatistics(func: allof(host.ip, cidr, "{address}")) {{
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
    try:
        result = dgraph_client.query(processing.add_default_attributes(query))
    except Exception as e:
        raise HTTPException(
            status_code = 500,
            detail = str(e)
        )
    return {"response": json.loads(result)}
