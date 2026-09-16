"""Event publication port."""

from typing import Protocol

from strix.domain.events import DomainEvent


class EventPublisher(Protocol):
    def publish(self, event: DomainEvent) -> None: ...
