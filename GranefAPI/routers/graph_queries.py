#! /usr/bin/env python3
# -*- coding: utf-8 -*-

#
# Granef -- graph-based network forensics toolkit
# Copyright (C) 2020-2021  Milan Cermak, Institute of Computer Science of Masaryk University
# Copyright (C) 2020-2021  Denisa Sramkova, Institute of Computer Science of Masaryk University
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
Definition of graph queries for Granef web user interface.
"""

# Common Python modules
import json

# FastAPI modules
from fastapi import APIRouter
from fastapi import HTTPException

# GranefAPI
from models import models     # Custom GranefAPI models
from utilities.dgraph_client import DgraphClient


# Initialize FastAPI router
router = APIRouter()


@router.get("/node_attributes",
    response_model=models.GeneralQueryResponseModel, 
    summary="Get all node attributes for a given node uid")
def node_attributes(uid: str, return_type: str = "json", graph_layout: str = "sfdp"):
    """
    """

    query_header = "query getAllNodeAttributes($uid: string)"
    query_body = """{ 
        getAllNodeAttributes(func: uid($uid)) { 
            expand(_all_)
        } 
    }
    """
    variables_dict = {"$uid": uid}    
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=return_type, layout=graph_layout)


@router.get("/node_neighbors",
    response_model=models.ResponseModel, 
    summary="Get all node neighbors (recursively) for a given node uid")
def node_neighbors(uid: str, depth: int = 2, return_type: str = "json", graph_layout: str = "sfdp"):
    query_header = "query getAllNodeNeighbors($uid: string, $depth: int)"
    query_body = """
    {
        getAllNodeNeighbors(func: uid($uid)) @recurse(depth: $depth, loop: false) {
            expand(_all_)
        }
    }
    """
    variables_dict = {"$uid": uid, "$depth": str(depth)}  
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=return_type, layout=graph_layout)
