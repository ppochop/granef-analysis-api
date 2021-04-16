#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Query data models for Granef API.

Documentation: https://fastapi.tiangolo.com/tutorial/body-nested-models/
"""

# Modules used by FastAPI to check data models
from pydantic import BaseModel, Field
from typing_extensions import Literal
from typing import Optional


class CustomQuery(BaseModel):
    query: str = Field(None, example='{getHost(func: allof(host.ip, cidr, "192.168.0.0/16")) {host.ip}}')

class GeneralResponse(BaseModel):
    response: dict = Field(None, example='{"getHost": [{"host.ip": "192.168.0.2"}, {"host.ip": "192.168.1.16"}]}')
