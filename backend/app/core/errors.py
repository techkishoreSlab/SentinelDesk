"""Stable public error codes and the standard error response format (spec §12.4, §21)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import correlation_id_var

logger = logging.getLogger("sentineldesk.errors")

PUBLIC_MESSAGES: dict[str, str] = {
    "SOFTWARE_BLOCKED_BY_POLICY": (
        "This software is blocked by your organisation's security policy. "
        "No installation was attempted."
    ),
    "SOFTWARE_NOT_IN_CATALOGUE": (
        "This software is not currently available in your organisation's catalogue."
    ),
    "DEVICE_NOT_COMPATIBLE": "This software version is not compatible with this device.",
    "APPROVAL_REQUIRED": "Your request is waiting for administrator approval.",
    "REQUEST_REJECTED": "Your software request was not approved.",
    "SECURITY_CHECK_UNAVAILABLE": (
        "Security verification is temporarily unavailable. Installation has been paused."
    ),
    "DEVICE_OFFLINE": (
        "This device is currently offline. The request may continue when it reconnects, "
        "provided it has not expired."
    ),
    "INSTALLATION_FAILED": "Installation could not be completed. No success has been recorded.",
    "FAILED_VERIFICATION": (
        "The installer finished, but SentinelDesk could not verify the requested version."
    ),
    "ALREADY_INSTALLED": "The requested version is already installed on this device.",
    "SELF_APPROVAL_FORBIDDEN": "You cannot approve or reject your own software request.",
    "ALREADY_DECIDED": "This request has already been decided or is no longer awaiting approval.",
    "REQUEST_EXPIRED": "This request has expired. Submit a new request.",
    "VERSION_CONFLICT": "The request changed while you were reviewing it. Refresh and try again.",
    "PACKAGE_METADATA_INCOMPLETE": (
        "This package cannot be activated until every mandatory catalogue field is set."
    ),
    "CONFLICT": "The resource conflicts with an existing record.",
    "INVALID_CREDENTIALS": "The email or password is incorrect.",
    "CSRF_FAILED": "The request could not be verified. Refresh the page and try again.",
    "LOCAL_AUTH_DISABLED": "Local sign-in is disabled. Use your organisation's sign-in.",
    "INTEGRATION_NOT_CONFIGURED": "This integration is not configured.",
    "LOGIN_FAILED": "Sign-in could not be completed. Please try again.",
    "ACCOUNT_LINK_REQUIRED": (
        "An account with this email already exists. Ask a platform administrator to link it."
    ),
    "ACCOUNT_DISABLED": "This account is disabled.",
    "SELF_ROLE_CHANGE_FORBIDDEN": "You cannot change your own roles.",
    "LAST_PLATFORM_ADMIN": "The last platform administrator cannot be removed.",
    "ENROLLMENT_TOKEN_INVALID": "The enrollment token is invalid, expired or already used.",
    "DEVICE_UNAUTHENTICATED": "Device authentication failed. Re-enroll the device.",
    "DEVICE_NOT_ACTIVE": (
        "This device is quarantined or revoked. Contact your administrator to re-enroll."
    ),
    "OWNER_NOT_ELIGIBLE": "The selected owner cannot receive devices.",
    "VALIDATION_ERROR": "The request was not valid.",
    "NOT_FOUND": "The requested resource was not found.",
    "METHOD_NOT_ALLOWED": "This method is not allowed for the resource.",
    "UNAUTHENTICATED": "Authentication is required.",
    "FORBIDDEN": "You are not allowed to perform this action.",
    "PAYLOAD_TOO_LARGE": "The request body is too large.",
    "RATE_LIMITED": "Too many requests. Please try again later.",
    "SERVICE_UNAVAILABLE": "The service is temporarily unavailable.",
    "INTERNAL_ERROR": "An unexpected error occurred.",
}

_HTTP_CODE_MAP = {
    400: "VALIDATION_ERROR",
    401: "UNAUTHENTICATED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    413: "PAYLOAD_TOO_LARGE",
    429: "RATE_LIMITED",
    503: "SERVICE_UNAVAILABLE",
}


class AppError(Exception):
    """Raised by services with a stable code; message is always the public one."""

    def __init__(self, code: str, status_code: int, details: dict[str, Any] | None = None):
        if code not in PUBLIC_MESSAGES:
            raise ValueError(f"unknown public error code {code}")
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.details = details


def error_body(code: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "code": code,
        "message": PUBLIC_MESSAGES[code],
        "correlation_id": correlation_id_var.get(),
    }
    if details:
        body["details"] = details
    return {"error": body}


def error_response(
    code: str, status_code: int, details: dict[str, Any] | None = None
) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=error_body(code, details))


async def _app_error(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AppError)
    return error_response(exc.code, exc.status_code, exc.details)


async def _validation_error(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    # Report field locations and error types only, never the submitted values.
    fields = [
        {"loc": [str(p) for p in err.get("loc", ())][:6], "type": str(err.get("type", ""))}
        for err in exc.errors()[:20]
    ]
    return error_response("VALIDATION_ERROR", 422, {"fields": fields})


async def _http_error(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    code = _HTTP_CODE_MAP.get(exc.status_code, "INTERNAL_ERROR")
    return error_response(code, exc.status_code)


async def _unhandled_error(_: Request, exc: Exception) -> JSONResponse:
    logger.error("unhandled_exception", exc_info=exc)
    return error_response("INTERNAL_ERROR", 500)


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(Exception, _unhandled_error)
