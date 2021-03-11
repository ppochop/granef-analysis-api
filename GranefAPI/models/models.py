#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of FastAPI data models for Granef API.
"""

from pydantic import BaseModel, Field
from typing_extensions import Literal
from typing import Optional


class QueryModel(BaseModel):
    query: str = Field(None, example='{getHost(func: allof(host.ip, cidr, "192.168.0.0/16")) {host.ip}}')
    return_type: Literal['json', 'graph'] = Field(None, example='json')
    graph_layout: Optional[str] = Field(None, example='sfdp')

class ResponseModel(BaseModel):
    response: dict = Field(None, example='{"getHost": [{"host.ip": "192.168.0.2"}, {"host.ip": "192.168.1.16"}]}')

