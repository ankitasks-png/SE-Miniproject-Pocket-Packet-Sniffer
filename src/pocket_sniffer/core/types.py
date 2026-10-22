from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Talker:
    host: str
    connection_count: int
    byte_count: int


@dataclass(frozen=True)
class Summary:
    protocol_breakdown: dict[str, int]
    top_talkers: tuple[Talker, ...]
    connection_count: int


@dataclass(frozen=True)
class Alert:
    timestamp: str
    source: str
    reason: str
    priority: str
