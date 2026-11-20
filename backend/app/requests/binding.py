"""Approval binding hash (spec section 10.2)."""

from __future__ import annotations

import hashlib
import json
import uuid


def approval_binding_hash(
    *,
    request_id: uuid.UUID,
    requester_id: uuid.UUID,
    device_id: uuid.UUID,
    software_id: uuid.UUID,
    catalogue_version_id: uuid.UUID,
    sha256: str,
    policy_revision: int | None,
    expires_at_iso: str,
    reason_code: str,
) -> str:
    payload = {
        "request_id": str(request_id),
        "requester_id": str(requester_id),
        "device_id": str(device_id),
        "software_id": str(software_id),
        "catalogue_version_id": str(catalogue_version_id),
        "sha256": sha256.lower(),
        "policy_revision": policy_revision,
        "expires_at": expires_at_iso,
        "reason_code": reason_code,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()
