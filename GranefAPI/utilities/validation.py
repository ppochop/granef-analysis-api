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
Definition of functions to ease data validation.
"""

# Common Python modules
import ipaddress

# FastAPI modules
from fastapi import HTTPException


def is_address(address: str) -> bool:
    """Validation of a given sting if its IPv4 and IPv6 address.

    Args:
        address (str): String to validate.

    Returns:
        bool: True if given address is valid IPv4 or IPv6 address, False otherwise.
    """
    try:
        ipaddress.ip_network(address)
        return True
    except (OSError, ValueError):
        pass
    return False


def validate(variable, type: str) -> bool:
    """Universal validation function that raise HTTPException if the variable is not valid.

    Args:
        variable (any type): Variable that should be validated.
        type (str): Required type of the variable. Available options: address

    Raises:
        HTTPException (status 400): Details about the validations if the variable is not valid.

    Returns:
        bool: True if given variable is valid, False othervise.
    """
    # Default validation response
    validation_result = False
    validation_fail_detail = ""

    # Validate given variable according to the requested type
    if type == "address":
        validation_result = is_address(variable)
        validation_fail_detail = f"Given address '{variable}' is not valid IPv4, IPv6 address, or CIDR notation."
    elif type == "address_first" or type == "address_second":
        validation_result = is_address(variable)
        validation_fail_detail = f"Given address '{variable}' is not valid IPv4, IPv6 address, or CIDR notation."

    # Raise HTTPException if the validation failed
    if not validation_result:
        raise HTTPException(
            status_code = 400,
            detail = validation_fail_detail
        )

    return validation_result
