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

# GranefAPI
from models import query_models
from utilities import validation, preprocessing
from utilities.dgraph_client import DgraphClient


# Initialize FastAPI router
router = APIRouter()

@router.post("/alert",
    response_model=query_models.GeneralResponseList,
    summary="Get alerts produced by suricata.")
def alert(request: query_models.AlertFilterQuery) -> dict:
    """
    Get alerts produced by suricata.
    """

    dgraph_client = DgraphClient()

    regexp = "" if not request.regexp else f"and regexp(alert.alert.signature, {request.regexp})"

    query = f"""{{
        getAlert(func:type(Alert)) @filter (le(alert.alert.severity, {request.severity}) {regexp} ) {{
            dgraph.type
            alert.alert.signature
            alert.alert.severity
            alert.alert.action
        }}
    }}
    """

    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["getAlert"]}


@router.post("/alert-connection",
    response_model=query_models.GeneralResponseList,
    summary="Get alerts produced by suricata with related connections.")
def alert_connections(request: query_models.AlertFilterQuery) -> dict:
    """
    Get alerts produced by suricata with related connections.
    """

    dgraph_client = DgraphClient()

    regexp = "" if not request.regexp else f"and regexp(alert.alert.signature, {request.regexp})"

    query = f"""{{
        getConnectionsWithAlerts(func:type(Connection)) @filter (has(connection.alert)) @cascade {{
            dgraph.type
            ~host.responded {{
                uid
                dgraph.type
                host.ip
            }}
            ~host.originated {{
                uid
                dgraph.type
                host.ip
            }}
            connection.alert @filter(le(alert.alert.severity, {request.severity}) {regexp} ) {{
                dgraph.type
                alert.alert.signature
                alert.alert.severity
                alert.alert.action
            }}
        }}
    }}
    """

    result = json.loads(dgraph_client.query(preprocessing.add_default_attributes(query)))
    return {"response": result["getConnectionsWithAlerts"]}
