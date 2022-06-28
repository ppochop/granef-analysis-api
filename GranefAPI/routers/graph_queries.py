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
from typing import List

# FastAPI modules
from fastapi import APIRouter
from fastapi import HTTPException

# GranefAPI
from models import query_models
from utilities import validation, preprocessing
from utilities.dgraph_client import DgraphClient


# Initialize FastAPI router
router = APIRouter()


@router.post("/filter_uids",
    response_model=query_models.GeneralResponseList,
    summary="Filter given list of uids with defined types")
def filter_uids(request: query_models.UidsTypesQuery) -> dict:
    """
    Selection of uids of defined node type.
    """
    dgraph_client = DgraphClient()

    type_filter = "type(" + request.types.replace(",", ") or type(") + ")"
    query = f"""{{
        filterUids(func: uid({request.uids})) @filter({type_filter}) {{
            uid
        }} 
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(query))

    # Extract uids
    uids = [x["uid"] for x in result["filterUids"]]

    return {"response": uids}


@router.post("/node_attributes",
    response_model=query_models.GeneralResponseList, 
    summary="Get all node attributes for given nodes uid")
def node_attributes(request: query_models.UidsQuery) -> dict:
    """
    Get all node attributes for given nodes uid (separated by comma).
    """
    dgraph_client = DgraphClient()

    query = f"""{{
        node_attributes(func: uid({request.uids})) {{
            expand(_all_)
        }} 
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["node_attributes"]}


@router.post("/attribute_search",
    response_model=query_models.GeneralResponseList, 
    summary="Search nodes with a given attribute and value")
def attribute_search(request: query_models.AttributeValueQuery) -> dict:
    """
    Get all nodes containing the given attribute and value (wide range query that sometimes takes too long).
    """
    dgraph_client = DgraphClient()

    query = f"""{{
        attribute_search(func: has({request.attribute})) @filter(eq({request.attribute}, {request.value})) {{
            expand(_all_)
        }} 
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["attribute_search"]}


@router.post("/uids_time_range",
    response_model=query_models.GeneralResponseDict,
    summary="Return minimal and maximal connection.ts for given uids")
def uids_time_range(request: query_models.UidsQuery) -> dict:
    """
    Get min and max connection.ts for a given list of uids (comma separated). Return null values if no uid with connection.ts attribute was found.
    """
    dgraph_client = DgraphClient()

    query = f"""{{
        var(func: uid({request.uids})) {{
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


@router.post("/uids_timestamp_filter",
    response_model=query_models.GeneralResponseDict,
    summary="Filter given uids and return only one in the given time range")
def uids_time_filter(request: query_models.UidsTimestampsRangeQuery) -> dict:
    """
    Select uids from the given list of uids (comma separated) that match the given timestamp range. Return empty array if no uid match the timestamp range.
    """
    dgraph_client = DgraphClient()

    query = f"""{{
        uids_timestamp_filter(func: uid({request.uids})) @filter(ge(connection.ts, "{request.timestamp_min}") and le(connection.ts, "{request.timestamp_max}")) {{
		    uid
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(query))
    # Merge uid values (dicts in list) to list
    uids = {"uids": [d["uid"] for d in result["uids_timestamp_filter"]]}
    return {"response": uids}


@router.post("/neighbors",
    response_model=query_models.GeneralResponseList,
    summary="Return all details for neighbor nodes of a given type for a given set of uids")
def neighbors(request: query_models.UidsTypesQuery) -> dict:
    """
    Get all attributes for a given set of uids and their neighbors of a specified type defined in database schema (comma separated).
    If "types" attribute is not specified (or is empty), than the function returns all nodes regardless of their type.
    """
    # If the "types" request value is not specified, use "_all_" in expand() function
    types = request.types if request.types else "_all_"

    dgraph_client = DgraphClient()

    query = f"""{{
        neighbors(func: uid({request.uids})) {{
            expand(_all_) {{
                expand({types})
            }}
            ioc {{
                uid
                dgraph.type
                expand({types}) {{
                    uid
                    dgraph.type
                    expand({types})
                }}
            }}
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))

    # Remove neighbors that were not expanded (doesn't have the required dgraph.type)
    neighbors = []
    for uid_result in result["neighbors"]:
        uid_result_reduced = {"uid": uid_result["uid"], "dgraph.type": uid_result["dgraph.type"]}
        # Do not select any attribute values for the parent node
        for attribute, value in uid_result.items():
            if isinstance(value, List) and attribute != "dgraph.type":
                value[:] = [x for x in value if len(x) > 2 ]
                if len(value) > 0:
                    uid_result_reduced[attribute] = value
        neighbors.append(uid_result_reduced)

    return {"response": neighbors}
