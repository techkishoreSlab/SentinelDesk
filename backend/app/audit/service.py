"""Append-only, hash-chained audit events (spec §5.1, §15.4).

Each event hash covers the previous event hash plus a canonical JSON encoding of the event.
Chain appends are serialized with a transaction-scoped advisory lock. The audit row is
written in the same transaction as the change it describes, so if the audit write fails the
change is rolled back (fail closed).
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.models import AuditEvent
from app.core.logging import correlation_id_var
from app.db.enums import ActorType, AuditResult

GENESIS_HASH = "0" * 64
_LOCK_KEY = 0x5E17_1AD0  # arbitrary constant identifying the audit chain lock
_METADATA_KEY = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_FORBIDDEN_KEY = re.compile(r"(password|secret|token|api_key|credential|cookie|prompt)")
_MAX_METADATA_KEYS = 20
_MAX_STRING = 200
_MAX_LIST = 20

MetadataValue = str | int | bool | None | list[str]


def _validate_metadata(metadata: dict[str, Any]) -> dict[str, MetadataValue]:
    if len(metadata) > _MAX_METADATA_KEYS:
        raise ValueError("too many audit metadata keys")
    clean: dict[str, MetadataValue] = {}
    for key, value in metadata.items():
        if not _METADATA_KEY.match(key) or _FORBIDDEN_KEY.search(key):
            raise ValueError(f"audit metadata key not allowed: {key!r}")
        if isinstance(value, bool | int) or value is None:
            clean[key] = value
        elif isinstance(value, str):
            clean[key] = value[:_MAX_STRING]
        elif isinstance(value, list) and all(isinstance(v, str) for v in value):
            clean[key] = [v[:_MAX_STRING] for v in value[:_MAX_LIST]]
        else:
            raise ValueError(f"audit metadata value type not allowed for {key!r}")
    return clean


def _hash_fields(event: AuditEvent) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "occurred_at": event.occurred_at.astimezone(UTC).isoformat(),
        "actor_type": event.actor_type,
        "actor_id": str(event.actor_id) if event.actor_id else None,
        "action": event.action,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "correlation_id": event.correlation_id,
        "source_ip": event.source_ip,
        "result": event.result,
        "reason_code": event.reason_code,
        "metadata": event.metadata_,
    }


def compute_event_hash(previous_hash: str, event: AuditEvent) -> str:
    canonical = json.dumps(
        _hash_fields(event), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(f"{previous_hash}|{canonical}".encode()).hexdigest()


async def record(
    session: AsyncSession,
    *,
    action: str,
    resource_type: str,
    result: AuditResult,
    actor_type: ActorType,
    actor_id: uuid.UUID | None = None,
    resource_id: str | uuid.UUID | None = None,
    reason_code: str | None = None,
    source_ip: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_KEY})
    previous = await session.scalar(
        select(AuditEvent.event_hash).order_by(AuditEvent.seq.desc()).limit(1)
    )
    event = AuditEvent(
        id=uuid.uuid4(),
        occurred_at=datetime.now(UTC),
        actor_type=actor_type.value,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        correlation_id=correlation_id_var.get(),
        source_ip=source_ip,
        result=result.value,
        reason_code=reason_code,
        metadata_=_validate_metadata(metadata or {}),
        previous_hash=previous or GENESIS_HASH,
    )
    event.event_hash = compute_event_hash(event.previous_hash, event)
    session.add(event)
    await session.flush()
    return event


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    events_checked: int
    first_invalid_seq: int | None


async def verify_chain(session: AsyncSession, batch_size: int = 500) -> ChainVerification:
    expected_previous = GENESIS_HASH
    checked = 0
    last_seq = 0
    while True:
        rows = (
            await session.scalars(
                select(AuditEvent)
                .where(AuditEvent.seq > last_seq)
                .order_by(AuditEvent.seq)
                .limit(batch_size)
            )
        ).all()
        if not rows:
            return ChainVerification(True, checked, None)
        for event in rows:
            if event.previous_hash != expected_previous or event.event_hash != compute_event_hash(
                event.previous_hash, event
            ):
                return ChainVerification(False, checked, event.seq)
            expected_previous = event.event_hash
            checked += 1
            last_seq = event.seq
