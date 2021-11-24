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
Definition of queries providing an interactivity for graph analysis.
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


@router.get("/node_attributes",
    response_model=query_models.GeneralResponseList, 
    summary="Get all node attributes for given nodes uid")
def node_attributes(uids: str) -> dict:
    """
    Get all node attributes for given nodes uid (separated by comma).
    """
    dgraph_client = DgraphClient()

    query = f"""{{
        node_attributes(func: uid({uids})) {{
            expand(_all_)
        }} 
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["node_attributes"]}


@router.get("/attribute_search",
    response_model=query_models.GeneralResponseList, 
    summary="Search nodes with agiven attribute and value")
def attribute_search(attribute: str, value: str) -> dict:
    """
    Get all nodes containing the given attribute and value (wide range query that sometimes takes too long).
    """
    dgraph_client = DgraphClient()

    query = f"""{{
        attribute_search(func: has({attribute})) @filter(eq({attribute}, {value})) {{
            expand(_all_)
        }} 
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["attribute_search"]}


@router.get("/uids_time_range",
    response_model=query_models.GeneralResponseDict,
    summary="Return minimal and maximal connection.ts for given uids")
def uids_time_range(uids: str) -> dict:
    """
    Get min and max connection.ts for a given list of uids (comma separated). Return null values if no uid with connection.ts attribute was found.
    """
    dgraph_client = DgraphClient()

    query = f"""{{
        var(func: uid({uids})) {{
		    time as connection.ts
        }}
        uids_time_range() {{
		    connection.ts.min: min(val(time))
            connection.ts.max: max(val(time))
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(query))
    # Merge results (provided as list of dictionaries) into one dictionary
    timestamps = {**result["uids_time_range"][0], **result["uids_time_range"][1]}
    return {"response": timestamps}


@router.get("/uids_timestamp_filter",
    response_model=query_models.GeneralResponseDict,
    summary="Filter given uids and reutnr only one in the given time range")
def uids_time_filter(uids: str, timestamp_min: str, timestamp_max: str) -> dict:
    """
    Select uids from the given list of uids (comma separated) that match the given timestamp range. Return empty array if no uid match the timestamp range.
    """
    dgraph_client = DgraphClient()

    query = f"""{{
        uids_timestamp_filter(func: uid({uids})) @filter(ge(connection.ts, "{timestamp_min}") and le(connection.ts, "{timestamp_max}")) {{
		    uid
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(query))
    # Merge uid values (dicts in list) to list
    uids = {"uids": [d["uid"] for d in result["uids_timestamp_filter"]]}
    return {"response": uids}
