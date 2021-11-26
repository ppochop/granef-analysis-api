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
from utilities import preprocessing
from utilities.dgraph_client import DgraphClient


# Initialize FastAPI router
router = APIRouter()


@router.post("/custom_query",
    response_model=query_models.GeneralResponseDict,
    summary="Universal function allowing to define a custom query using Dgraph Query Language")
def custom_query(request: query_models.CustomQuery) -> dict:
    """
    See examples of Dgraph Query Language (DQL) at https://dgraph.io/docs/query-language/graphql-fundamentals/.
    """
    dgraph_client = DgraphClient()
    result = dgraph_client.query(preprocessing.add_default_attributes(request.query))
    return {"response": json.loads(result)}
