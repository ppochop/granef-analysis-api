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
Singleton class providing Dgraph connection for Granef API. The code is inspired by Python Design patterns
available at https://refactoring.guru/design-patterns/singleton/python/example.
"""

# FastAPI modules
from fastapi import HTTPException

# Official communication module for Dgraph database
import pydgraph


class SingletonMeta(type):
    """
    Meta class to provide singleton functionality.
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class DgraphClient(metaclass=SingletonMeta):
    """The main Dgraph client class allowing to connect to the database and perform queries.

    Available as a singleton to ease usage of initialized Dgraph connection.
    """
    client_stub = None  # Pydgraph client variable to store connection details
    dgraph = None  # Initialized Pydgraph client object.

    def connect(self, ip: str, port: int):
        """Establish connection to Dgraph database server.

        Args:
            ip (str): IP address of the Dgraph server.
            port (int): Port of the Dgraph server.
        
        Raises:
            ConnectionError: Connection was not established.
        """
        # Destroy previous Dgraph connection
        if self.client_stub:
            self.client_stub.close()

        # Initialize dgraph server connection (set GRPC with maximum values)
        self.client_stub = pydgraph.DgraphClientStub("{0}:{1}".format(ip, port), options=[
            ('grpc.max_send_message_length', 1024 * 1024 * 1024),
            ('grpc.max_receive_message_length', 1024 * 1024 * 1024)
        ])
        self.dgraph = pydgraph.DgraphClient(self.client_stub)


    def query(self, query: str, variables: dict = None) -> str:
        """Perform given query and raise HTTPException if some error occurs.

        Args:
            query (str): Query string to perform.
            variables (dict, optional): Dictionary of variables name and corresponding value. Defaults to None.

        Raises:
            HTTPException (status: 503): Database is not connected.
            HTTPException (status: 500): The query transaction failed.

        Returns:
            str: Obtained response as a JSON string.
        """
        # Check if the database connection is initialized
        if not self.dgraph:
            raise HTTPException(
                status_code = 503,
                detail = "Dgraph database is not connected."
            )

        try:
            txn = self.dgraph.txn(read_only=True)
            result = txn.query(query, variables)
        except Exception as e:
            raise HTTPException(
                status_code = 500,
                detail = "Dgraph query failed: " + str(e)
            )
        finally:
            txn.discard()

        return result.json
