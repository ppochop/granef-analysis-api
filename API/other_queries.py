#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of queries functions for Granef API.
"""

import json
from fastapi import APIRouter

from dgraph_client import DgraphClient
import models
import queries_utils as qutils
from data_processing import DgraphDataProcessing

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

    # Perform query and raise HTTP exception if any error occures
    try:
        # Preprocess query according to the query type
        result = dgraph_client.query(dgraph_processing.process_query(query.query))
    except Exception as e:
        qutils.raise_error(str(e))

    # Process response accoring to the query type   
    return {"response": dgraph_processing.process_response(response=json.loads(result))}
