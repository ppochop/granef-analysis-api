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
Query data models for Granef API.

Documentation: https://fastapi.tiangolo.com/tutorial/body-nested-models/
"""

# Modules used by FastAPI to check data models
from pydantic import BaseModel, Field
from typing_extensions import Literal
from typing import Optional


class CustomQuery(BaseModel):
    query: str = Field(None, example='{getHost(func: allof(host.ip, cidr, "192.168.0.0/16")) {host.ip}}')

class UidsQuery(BaseModel):
    uids: str = Field(None, example='0x12, 0x9c882')

class AttributeValueQuery(BaseModel):
    attribute: str = Field(None, example='connection.proto')
    value: str = Field(None, example='tcp')

class UidsTimestampsRangeQuery(BaseModel):
    uids: str = Field(None, example='0x12, 0x9c882')
    timestamp_min: str = Field(None, example='2008-07-22T01:51:07.095278Z')
    timestamp_max: str = Field(None, example='2008-07-22T01:55')

class AddressQuery(BaseModel):
    address: str = Field(None, example='192.168.15.0/24')

class GeneralResponseDict(BaseModel):
    response: dict = Field(None, example='{"getHost": [{"host.ip": "192.168.0.2"}, {"host.ip": "192.168.1.16"}]}')

class GeneralResponseList(BaseModel):
    response: list = Field(None, example='[{"host.ip": "192.168.0.2"}, {"host.ip": "192.168.1.16"}]')
