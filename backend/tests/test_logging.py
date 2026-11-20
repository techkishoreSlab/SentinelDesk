from __future__ import annotations

import json
import logging

from app.core.logging import JsonFormatter, correlation_id_var, redact_text


def _format(msg: str, **extra: object) -> dict[str, object]:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, msg, (), None)
    for k, v in extra.items():
        setattr(record, k, v)
    out: dict[str, object] = json.loads(JsonFormatter("backend", "test").format(record))
    return out


def test_json_shape_and_correlation_id() -> None:
    token = correlation_id_var.set("abc")
    try:
        out = _format("hello", request_id="r1")
    finally:
        correlation_id_var.reset(token)
    assert out["event"] == "hello"
    assert out["service"] == "backend"
    assert out["severity"] == "INFO"
    assert out["correlation_id"] == "abc"
    assert out["request_id"] == "r1"


def test_sensitive_extra_keys_redacted() -> None:
    out = _format(
        "x",
        api_key="AIzaSECRET",
        password="hunter2",
        enrollment_token="tok",
        nested={"client_secret": "s", "ok": "fine"},
    )
    serialized = json.dumps(out)
    for secret in ("AIzaSECRET", "hunter2", 'tok"', '"s"'):
        assert secret not in serialized
    assert out["nested"] == {"client_secret": "[REDACTED]", "ok": "fine"}


def test_secrets_in_message_text_redacted() -> None:
    text = redact_text(
        "auth Bearer eyJabc.def connect postgresql+asyncpg://user:pw123@db/x?token=zzz"
    )
    assert "eyJabc" not in text
    assert "pw123" not in text
    assert "zzz" not in text


def test_terminal_control_sequences_stripped() -> None:
    assert redact_text("ok \x1b[1mbold\x1b[0m\x07 done") == "ok bold done"
    out = _format("hello", color_message="\x1b[1mhello\x1b[0m")
    assert "color_message" not in out


def test_long_values_truncated() -> None:
    assert len(redact_text("a" * 10_000)) < 2100
