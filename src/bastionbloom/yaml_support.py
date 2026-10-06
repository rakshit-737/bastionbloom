"""Bounded YAML loading with YAML 1.2-style booleans and source locations."""

from __future__ import annotations

import re
from dataclasses import dataclass

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


class ProjectLoader(yaml.SafeLoader):
    # PyYAML's YAML 1.1 resolver turns GitHub Actions' `on` key into True.
    yaml_implicit_resolvers = {
        key: [(tag, pattern) for tag, pattern in values if tag != "tag:yaml.org,2002:bool"]
        for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def __init__(self, stream):
        super().__init__(stream)
        self._nodes = 0
        self._depth = 0
        self._aliases = 0

    def compose_node(self, parent, index):
        self._nodes += 1
        self._depth += 1
        if self.check_event(yaml.AliasEvent):
            self._aliases += 1
        if self._nodes > 30_000 or self._depth > 80 or self._aliases > 100:
            raise yaml.YAMLError("YAML complexity limit exceeded")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


ProjectLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"), list("tTfF")
)


@dataclass
class Document:
    data: dict
    locations: dict[tuple, int]

    def line(self, *keys) -> int:
        while keys:
            if keys in self.locations:
                return self.locations[keys]
            keys = keys[:-1]
        return 1


def load_document(text: str) -> Document:
    loader = ProjectLoader(text)
    locations = {}

    def locate(node: Node, path: tuple, ancestors: frozenset[int] = frozenset()):
        if id(node) in ancestors:
            return
        locations[path] = node.start_mark.line + 1
        ancestors = ancestors | {id(node)}
        if len(locations) > 30_000:
            raise yaml.YAMLError("YAML location limit exceeded")
        if isinstance(node, MappingNode):
            for key, value in node.value:
                if isinstance(key, ScalarNode):
                    locate(value, (*path, key.value), ancestors)
        elif isinstance(node, SequenceNode):
            for index, value in enumerate(node.value):
                locate(value, (*path, index), ancestors)

    try:
        node = loader.get_single_node()
        if node is None:
            return Document({}, {})
        locate(node, ())
        data = loader.construct_document(node)
        if not isinstance(data, dict):
            raise yaml.YAMLError("Expected a YAML mapping")
        return Document(data, locations)
    finally:
        loader.dispose()
