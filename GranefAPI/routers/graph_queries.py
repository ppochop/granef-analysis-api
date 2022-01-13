#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of graph queries for Granef web user interface.
"""

# FastAPI modules
from fastapi import APIRouter   # FastAPI modules

# GranefAPI
from models import models     # Custom GranefAPI models
from utilities import queries_utils as qutils     # Query utilities


# Initialize FastAPI router
router = APIRouter()


@router.get("/node_attributes",
    response_model=models.ResponseModel, 
    summary="Get all node attributes for a given node uid")
def node_attributes(uid: str, return_type: str = "json", graph_layout: str = "sfdp"):
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
    summary="Get all node neighbors for a given node uid")
def node_neighbors(uid: str, types: str, return_type: str = "json", graph_layout: str = "sfdp"):
    query_header = "query getAllNodeNeighbors($uid: string, $types: string)"
    query_body = """
    {
        neighbors(func: uid($uid)) {
            expand(_all_) {
                expand($types)
            }   
        }
    }
    """
    variables_dict = {"$uid": uid, "$types": types}  
    return qutils.handle_query(query_body=query_body, query_header=query_header, variables=variables_dict, type=return_type, layout=graph_layout)
