#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Custom functions to ease data processing in Granef API.
"""

import re
import networkx as nx  # Graph creation and manipulation


class DgraphDataProcessing:
    """
    Input and output data processing allowing to process data according to given query type
    and visualization format requirements.

    :param type: Type of the query response format (should be "json" or "graph").
    :param layout: Layout format if "graph" query type is specified ("dot", "twopi", "fdp", "sfdp", "circo").
    :ivar __type: Requested query type.
    :ivar __layout: Requseted graph layout.
    :ivar __graph: Structure to store response as NetworkX graph.
    """
    __type: str = ""
    __layout: str = ""
    __graph: object = None


    def __init__(self, type: str, layout: str) -> None:
        self.__type = type
        # Set default layout if no layout is specified
        self.__layout = layout if layout else "sfdp"
    

    def process_query(self, query: str, attributes: [str] = ["uid", "dgraph.type"]) -> str:
        """
        Transform query according to the requirements specified by a type of the query.
        
        Query with type "json" is returned as is. Query with type "graph" is extended
        by specified attributes for each node.

        :param query: Dgraph query to process.
        :param attributes: List of attributes that should be added to the each query node if they are not present.
        :return: Query transformed according to the requirements specified by a type of the query.
        """
        # Save original query
        processed_query = query

        # If the response output should be graph, we need to add additional attributes 
        if self.__type == "graph":
            # Remove line endings and reduce spaces
            reduced_query = re.sub(" +", " ", re.sub("\n|\r|\t", "", processed_query))

            # Process query parts
            parts = re.split("{ *", reduced_query)
            for i, part in enumerate(parts):
                # Skip non attribute parts
                if (not part) or part.isspace() or ("func:" in part):
                    continue
                # Check if given attributes are specified and append missing ones
                append = ""
                for attribute in attributes:        
                    if not bool(re.search('(^| ){0} '.format(attribute), part)):
                        append = append + '{0} '.format(attribute)
                parts[i] = append + part    

            # Store updated query
            processed_query = "{".join(parts)    

        return processed_query
    

    def __get_node_colors(self, node_type: str) -> dict:
        """
        Returns dictionary with background and border color for a node according to the node type.

        Example of the return value {"background": "#d5e8d4", "border": "#82b366"}

        :param node_type: Type of the node (typically dgprah.type attribute).
        :return: Dictionary with background and border color definition.
        """
        if node_type == "Host":
            # Green
            return {"background": "#d5e8d4", "border": "#82b366"}
        elif node_type == "Connection":
            # Orange
            return {"background": "#ffe6cc", "border": "#d79b00"}
        elif node_type == "File" or node_type == "User_Agent" or node_type == "Hostname" or node_type == "X509":
            # Gray
            return {"background": "#f5f5f5", "border": "#666666"}
        else: 
            # Red as default color
            return {"background": "#f8cecc", "border": "#b85450"}


    def __process_response_node(self, node: dict, fixed: bool = False) -> None:
        """
        Recursive method to iteratively transform all response nodes and append them to NetworkX graph object.

        :param node: Currently processed response node.
        :param fixed: Bool value to indicate if node attribute "fixed" should be set to given value (used for visualization).
        :param layer: Indicator of the node layer.
        """
        self.__graph.add_node(node["uid"])
        self.__graph.nodes[node["uid"]]["fixed"] = fixed

        # Process node according to it type
        for key, value in node.items():
            if not isinstance(value, list):  # General attribute
                self.__graph.nodes[node["uid"]][key] = value
            elif not isinstance(value[0], dict):  # Attribute with and array of results
                if len(value) == 1:
                    self.__graph.nodes[node["uid"]][key] = value
                else:
                    self.__graph.nodes[node["uid"]][key] = "<br>"+'<br>'.join(value)
            else:  # Edge
                for next_node in value:
                    self.__graph.add_edge(node["uid"], next_node["uid"], name=key)
                    self.__process_response_node(next_node)       


    def __graph_to_dict(self) -> dict:
        """
        Transformation of the NetworkX graph object to the dictionary in the format requested by the results
        visualization method (see details at https://visjs.github.io/vis-network/docs/network/).

        The method allows to set nodes layout using the graphviz tool. For more details see
        https://networkx.github.io/documentation/stable/reference/generated/networkx.drawing.nx_pydot.graphviz_layout.html.

        :return: Graph in dictionary format with attributes required by the visualization.
        """
        # Set layout
        layout = nx.spring_layout(self.__graph)

        # Generate data
        graph_dict = {"nodes": [], "edges": []}
        for graph_node in self.__graph.nodes(data=True):
            # Create a new node
            node = {}
            node["id"] = graph_node[0]

            # Set computed coordinates according to the layout (multiplication allow wider layout)
            x, y = layout[graph_node[0]]
            node["x"] = x * 5
            node["y"] = y * 5

            # Set default node lable to avoid animation overload
            node["label"] = " "

            # Generare node attributes
            title = ""
            for key, value in graph_node[1].items():
                # Skip uid attribute as it is not necessary for visualization
                if key == "uid":
                    continue
                # Set name key as node label
                elif key == "label":
                    node["label"] = value
                # Set node collor according to its type
                elif key == "dgraph.type":
                    node["color"] = self.__get_node_colors(node_type=value[0])
                # For strating nodes set fixed attribute to disable their animation
                elif key == "fixed":
                    node["fixed"] = value
                # Join any other attributes into one title field
                else:
                    title += "<b>{0}:</b> {1}<br>".format(key, value)

            # Add created title to the node
            if "title" in node:
                node["title"] += title
            else:
                node["title"] = title

            # Append created node to resulting dictionary
            graph_dict["nodes"].append(node)

        # Generate graph edges
        for graph_edge in self.__graph.edges(data=True):
            # Check the right edge direction
            if graph_edge[2]["name"].startswith("~"):
                edge = {"id": graph_edge[1]+"-"+graph_edge[0], "from": graph_edge[1], "to": graph_edge[0], "arrows": "to", "label": graph_edge[2]["name"]}
            else:
                edge = {"id": graph_edge[0]+"-"+graph_edge[1], "from": graph_edge[0], "to": graph_edge[1], "arrows": "to", "label": graph_edge[2]["name"]}
            graph_dict["edges"].append(edge)
        
        return graph_dict


    def process_response(self, response: dict) -> dict:
        """
        Transform response according to the requirements specified by a type of the query.

        Response for type "json" is returned as is. Response for type "graph" is transformed
        according to visualization requirements.

        :param response: Dictionary with query response data.
        :return: Response transformed according to the requirements specified by a type of the query.
        """
        # Save original response
        processed_response = response

        # We need to process only graph response type, JSON is retrurned as is
        if self.__type == "graph":
            # Get result only for the first function
            data = list(response.values())[0]
            # Set graph and load data
            self.__graph = nx.DiGraph()
            for node in data:
                # Set the first response nodes as fixed
                self.__process_response_node(node, fixed=True)
            # Convert created graph to dictionary for visualization
            processed_response = self.__graph_to_dict()

        return processed_response
