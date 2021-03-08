#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of queries functions for Granef API.
"""

# Common Python modules
import json

# FastAPI modules
from fastapi import APIRouter   # FastAPI modules

# GranefAPI
from models import models     # Custom GranefAPI models
from utilities import queries_utils as qutils     # Query utilities
from utilities.dgraph_client import DgraphClient
from utilities.data_processing import DgraphDataProcessing


# Initialize FastAPI router
router = APIRouter()


@router.post("/custom", response_model=models.ResponseModel, summary="Perform custom query")
def dgraph_query_custom(query: models.QueryModel):
    """
    General function to process any Dgraph query given as a string. Result is provided as simple
    JSON response or extended by graph data according to desired query type.
    """
    dgraph_client = DgraphClient()
    dgraph_processing = DgraphDataProcessing(type=query.type, layout=query.layout)

    # Perform query and raise HTTP exception if any error occurs
    try:
        # Preprocess query according to the query type
        result = dgraph_client.query(dgraph_processing.process_query(query.query))
    except Exception as e:
        qutils.raise_error(str(e))

    # Process response according to the query type   
    return {"response": dgraph_processing.process_response(response=json.loads(result))}
