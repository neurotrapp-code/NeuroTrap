"""Unified CADN alert event schema with validation."""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HoneypotSource(str, Enum):
    SCAPY = "scapy_monitor"
    COWRIE = "cowrie"
    DIONAEA = "dionaea"
    ZEEK = "zeek"


class AlertEvent(BaseModel):
    timestamp: str                       # ISO-8601 UTC
    src_ip: IPvAnyAddress
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)
    attack_type: str
    severity: Severity
    raw_payload: Optional[str] = None
    honeypot_source: HoneypotSource
    detail: Optional[str] = None

    @field_validator("timestamp")
    @classmethod
    def _check_ts(cls, v):
        datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return v

    @classmethod
    def now_ts(cls) -> str:
        return datetime.now(timezone.utc).isoformat()

    def to_json(self) -> str:
        return self.model_dump_json()

    def to_dict(self) -> dict:
        d = self.model_dump()
        d["src_ip"] = str(d["src_ip"])
        d["severity"] = self.severity.value
        d["honeypot_source"] = self.honeypot_source.value
        return d
