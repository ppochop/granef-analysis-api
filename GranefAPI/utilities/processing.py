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
Custom functions to ease data processing in Granef API.
"""

# Common Python modules
import re


def add_default_attributes(query: str, attributes: list[str] = ["uid", "dgraph.type"]) -> str:
    """
    Add specified attributes to all nodes of the query.

    :param query: Dgraph query to process.
    :param attributes: List of attributes that should be added to the each query node if they are not present.
    :return: Query transformed according to the requirements specified by a type of the query.
    """
    # Remove line endings and reduce spaces
    reduced_query = re.sub(" +", " ", re.sub("\n|\r|\t", "", query))

    # Process query parts
    parts = re.split("{ *", reduced_query)
    for i, part in enumerate(parts):
        # Skip non attribute parts
        if (not part) or part.isspace() or ("func:" in part):
            continue
        # Check if given attributes are specified and append missing ones
        append = ""
        for attribute in attributes:        
            if not bool(re.search('(^| ){0}( |}})'.format(attribute), part)):
                append = append + '{0} '.format(attribute)
        parts[i] = append + part
    return "{".join(parts) 
