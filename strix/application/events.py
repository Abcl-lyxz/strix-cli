"""Small synchronous event bus used by application services."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable

from strix.domain.events import DomainEvent


logger = logging.getLogger(__name__)
EventHandler = Callable[[DomainEvent], None]


class EventBus:
    """Publish domain events without coupling use cases to presentation code."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, name: str, handler: EventHandler) -> Callable[[], None]:
        self._subscribers[name].append(handler)

        def unsubscribe() -> None:
            handlers = self._subscribers.get(name, [])
            if handler in handlers:
                handlers.remove(handler)

        return unsubscribe

    def publish(self, event: DomainEvent) -> None:
        handlers = [*self._subscribers.get(event.name, []), *self._subscribers.get("*", [])]
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                logger.exception("domain event subscriber failed for %s", event.name)
