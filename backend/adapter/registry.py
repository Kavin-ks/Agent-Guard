"""
Tool registry.

A tool is registered once with its security-relevant metadata (operation +
resource kind) and its callable. The executor uses that metadata to build the
evaluate request, so individual tool authors never write security checks — they
just register a plain function and call it through the guarded executor.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Tool:
    name: str
    operation: str          # read|write|delete|execute|network|transmit
    resource_kind: str      # file|url|db|process|other
    fn: Callable[..., object]
    description: str = ""


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool '{tool.name}' already registered")
        self._tools[tool.name] = tool

    def add(self, name: str, operation: str, resource_kind: str,
            fn: Callable[..., object], description: str = "") -> Tool:
        tool = Tool(name=name, operation=operation, resource_kind=resource_kind,
                    fn=fn, description=description)
        self.register(tool)
        return tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"tool '{name}' is not registered")
        return self._tools[name]

    def names(self) -> list[str]:
        return sorted(self._tools)
