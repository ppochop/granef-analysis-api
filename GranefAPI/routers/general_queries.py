#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of general queries functions for Granef API.

Contains custom queries that do not fall into any of the specific categories.
"""

# Common Python modules
import json

# FastAPI modules
from fastapi import APIRouter
from fastapi import HTTPException

# GranefAPI
from models import query_models
from utilities.dgraph_client import DgraphClient


# Initialize FastAPI router
router = APIRouter()


@router.post("/custom_query",
    response_model=query_models.GeneralResponse,
    summary="Universal function allowing to define a custom query using Dgraph Query Language")
def custom_query(query: query_models.CustomQuery) -> dict:
    """
    See examples of Dgraph Query Language (DQL) at https://dgraph.io/docs/query-language/graphql-fundamentals/.
    """
    dgraph_client = DgraphClient()

    # Perform query and raise HTTP exception if any error occurs
    try:
        result = dgraph_client.query(query.query)
    except Exception as e:
        raise HTTPException(
            status_code = 500,
            detail = str(e)
        )
    return {"response": json.loads(result)}
