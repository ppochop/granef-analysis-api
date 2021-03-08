#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Singleton class providing Dgraph connection for Granef API. The code is inspired by Python Design patterns
available at https://refactoring.guru/design-patterns/singleton/python/example.
"""

import pydgraph  # Official communication module for Dgraph database


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


# TODO: resolve ssh query limit? (pagination)

class DgraphClient(metaclass=SingletonMeta):
    """
    The main Dgraph client class allowing to connect to the database and perform queries.

    :ivar client_stub: Pydgraph client variable to store connection details.
    :ivar dgraph: Initialized Pydgraph client object.
    """
    client_stub = None
    dgraph = None

    def connect(self, ip: str, port: int):
        """
        Establish connection to Dgraph database server.

        :param ip: IP address of the Dgraph server.
        :param port: Port of the Dgraph server.
        :raises: ConnectionError if connection was not established.
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
        """
        Perform query using established Dgraph connection. 

        :param query: Query string to perform.
        :return: Obtained response as a JSON string.
        :raises: RuntimeError if database is not connected or the transaction fails.
        """
        # Check if the database connection is initialized
        if not self.dgraph:
            raise RuntimeError("Dgraph database is not connected.")

        try:
            txn = self.dgraph.txn(read_only=True)
            result = txn.query(query, variables)
        except Exception as e:
            raise RuntimeError("Dgraph query failed: " + str(e))
        finally:
            txn.discard()

        return result.json
