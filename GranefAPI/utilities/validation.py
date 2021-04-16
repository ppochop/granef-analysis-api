#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Definition of functions to ease data validation.
"""

# Common Python modules
import ipaddress


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
    except OSError:
        pass
    return False
