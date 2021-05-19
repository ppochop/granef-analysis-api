#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of common network queries for Granef API.
"""

import json  # Fast JSON parser
from fastapi import APIRouter  # FastAPI modules
from fastapi import HTTPException

from models import query_models     # Custom GranefAPI models
from utilities import validation
from utilities.dgraph_client import DgraphClient

# Initialize FastAPI router
router = APIRouter()


@router.get("/get_hostname", response_model=query_models.GeneralResponse, summary="List of the count of all HTTP hostnames.")
def subnet_info(type: str = "json", layout: str = "sfdp"):

    dgraph_client = DgraphClient()

    query = f"""{{ 
        getHttpHostname(func: type(HTTP_formats)) @groupby(HTTP_formats.HTTP_Hostname) {{
            hostname_count : count(uid)
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    try:
        result = dgraph_client.query(query)
    except Exception as e:
        raise HTTPException(
            status_code = 500,
            detail = str(e)
        )
    return {"response": json.loads(result)}

@router.get("/get_all_urls", response_model=query_models.GeneralResponse, summary="List of the count of all HTTP urls.")
def subnet_info(type: str = "json", layout: str = "sfdp"):

    dgraph_client = DgraphClient()

    query = f"""{{ 
        getHttpUri(func: type(HTTP_formats)) @groupby(HTTP_formats.HTTP_URL) {{
            uri_count : count(uid)
        }}
    }}"""

    # Perform query and raise HTTP exception if any error occurs
    try:
        result = dgraph_client.query(query)
    except Exception as e:
        raise HTTPException(
            status_code = 500,
            detail = str(e)
        )
    return {"response": json.loads(result)}