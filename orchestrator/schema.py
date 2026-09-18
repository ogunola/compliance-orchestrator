"""Common Finding record that every tool-specific parser normalizes into."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


VALID_STATUSES = {"pass", "fail", "error", "not_applicable", "unknown"}


@dataclass
class Finding:
    """One normalized result from one tool, about one target."""

    source_tool: str                      # caldera | atomic | prowler | openscap | pingcastle
    target: str                           # hostname, account id, domain, etc.
    check_id: str                         # tool-native id (ATT&CK technique, oscap rule id, prowler check id, ...)
    title: str
    status: str                           # one of VALID_STATUSES
    severity: Optional[str] = None
    attack_technique: Optional[str] = None  # normalized T#### if known/mappable
    secondary_tag: Optional[str] = None  # e.g. a garak probe id, for non-ATT&CK crosswalks (see ai_aggregator.py)
    raw: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            self.status = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
