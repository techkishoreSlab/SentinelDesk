"""Unit tests for mid-job progress recording."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.errors import AppError
from app.db.enums import JobStatus
from app.jobs import service as jobs


def _job(
    *,
    status: str = JobStatus.RUNNING.value,
    phase: str | None = None,
    done: int | None = None,
    total: int | None = None,
    updated_at: datetime | None = None,
) -> MagicMock:
    job = MagicMock()
    job.id = uuid.uuid4()
    job.device_id = uuid.uuid4()
    job.status = status
    job.expires_at = datetime.now(UTC) + timedelta(hours=1)
    job.progress_phase = phase
    job.progress_bytes_done = done
    job.progress_bytes_total = total
    job.progress_updated_at = updated_at
    return job


@pytest.mark.asyncio
async def test_record_progress_download_monotonic() -> None:
    job = _job(done=100, total=1000, phase="DOWNLOADING", updated_at=datetime.now(UTC) - timedelta(seconds=2))
    db = AsyncMock()
    db.scalar = AsyncMock(return_value=job)
    db.flush = AsyncMock()

    out = await jobs.record_progress(
        db,
        device_id=job.device_id,
        job_id=job.id,
        phase="DOWNLOADING",
        bytes_done=50,  # regresses — should clamp
        bytes_total=1000,
    )
    assert out["bytes_done"] == 100
    assert job.progress_bytes_done == 100


@pytest.mark.asyncio
async def test_record_progress_installing_clears_bytes() -> None:
    job = _job(done=500, total=1000, phase="DOWNLOADING", updated_at=datetime.now(UTC) - timedelta(seconds=2))
    db = AsyncMock()
    db.scalar = AsyncMock(return_value=job)
    db.flush = AsyncMock()

    out = await jobs.record_progress(
        db,
        device_id=job.device_id,
        job_id=job.id,
        phase="INSTALLING",
        bytes_done=500,
        bytes_total=1000,
    )
    assert out["phase"] == "INSTALLING"
    assert out["bytes_done"] is None
    assert job.progress_bytes_done is None


@pytest.mark.asyncio
async def test_record_progress_rejects_terminal_job() -> None:
    job = _job(status=JobStatus.SUCCEEDED.value)
    db = AsyncMock()
    db.scalar = AsyncMock(return_value=job)

    with pytest.raises(AppError) as exc:
        await jobs.record_progress(
            db,
            device_id=job.device_id,
            job_id=job.id,
            phase="DOWNLOADING",
            bytes_done=1,
            bytes_total=10,
        )
    assert exc.value.status_code == 409
