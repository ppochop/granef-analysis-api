#! /usr/bin/env python3
# -*- coding: utf-8 -*-

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
