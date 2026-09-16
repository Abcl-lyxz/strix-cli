"""Typed command dispatch used by terminal and browser transports."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any


type CommandHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]
type NamespaceCommandHandler = Callable[["Command"], Awaitable[dict[str, Any]]]


@dataclass(frozen=True, slots=True)
class Command:
    name: str
    payload: dict[str, Any]

    @property
    def namespace(self) -> str:
        return self.name.partition(".")[0]


class CommandRegistry:
    """Resolve command handlers without a central conditional dispatcher."""

    def __init__(self) -> None:
        self._handlers: dict[str, CommandHandler] = {}
        self._namespaces: dict[str, NamespaceCommandHandler] = {}

    def register(self, name: str, handler: CommandHandler) -> None:
        if name in self._handlers:
            raise ValueError(f"command already registered: {name}")
        self._handlers[name] = handler

    def register_namespace(self, namespace: str, handler: NamespaceCommandHandler) -> None:
        if namespace in self._namespaces:
            raise ValueError(f"command namespace already registered: {namespace}")
        self._namespaces[namespace] = handler

    async def dispatch(self, command: Command) -> dict[str, Any]:
        handler = self._handlers.get(command.name)
        if handler is not None:
            return await handler(command.payload)
        namespace_handler = self._namespaces.get(command.namespace)
        if namespace_handler is None:
            raise ValueError(f"Unknown command: {command.name}")
        return await namespace_handler(command)
