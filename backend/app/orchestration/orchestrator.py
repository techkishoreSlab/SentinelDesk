"""Deterministic preview orchestrator: Gemini never selects tools (D1)."""

from __future__ import annotations

import logging
import uuid
from typing import Literal

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.explain import decision_summary, deterministic_explanation
from app.ai.fallback import fallback_intent
from app.ai.gemini import GeminiClient, GeminiError, IntentExtractor
from app.ai.intent import SoftwareIntent
from app.core.config import Settings
from app.orchestration.schemas import IntentOut, MatchOut, PolicyOut, PreviewOut, PreviewStatus
from app.orchestration.tools import (
    TOOL_EVALUATE_POLICY,
    TOOL_EXPLAIN,
    TOOL_EXTRACT_INTENT,
    TOOL_PICK_VERSION,
    TOOL_RESOLVE_ALIAS,
    evaluate_policy_tool,
    load_owned_device,
    pick_catalogue_version,
    resolve_catalogue_alias,
)
from app.security.threat import CompositeThreatIntel

logger = logging.getLogger("sentineldesk.orchestrator")

_POLICY_STATUS: dict[str, PreviewStatus] = {
    "BLOCKED": "BLOCKED",
    "INCOMPATIBLE": "INCOMPATIBLE",
    "ALREADY_INSTALLED": "ALREADY_INSTALLED",
    "REQUIRE_APPROVAL": "REQUIRE_APPROVAL",
    "AUTO_APPROVE": "AUTO_APPROVE",
    "ALLOW": "ALLOW",
    "SECURITY_REVIEW": "SECURITY_REVIEW",
    "SECURITY_CHECK_UNAVAILABLE": "SECURITY_CHECK_UNAVAILABLE",
    "PACKAGE_NOT_APPROVED": "PACKAGE_NOT_APPROVED",
    "NOT_FOUND": "NOT_FOUND",
}


def _intent_out(intent: SoftwareIntent, source: Literal["gemini", "fallback"]) -> IntentOut:
    return IntentOut(
        intent=intent.intent,
        software_query=intent.software_query,
        edition=intent.edition,
        requested_version=intent.requested_version,
        platform_preference=intent.platform_preference,
        clarification_required=intent.clarification_required,
        clarification_question=intent.clarification_question,
        confidence=intent.confidence,
        source=source,
    )


async def extract_intent_tool(
    *,
    raw_request: str,
    settings: Settings,
    extractor: IntentExtractor | None,
) -> tuple[SoftwareIntent, Literal["gemini", "fallback"], str | None]:
    """Return (intent, source, model_name). Always falls back for exact demo phrases."""
    gemini_configured = bool(settings.gemini_api_key and settings.gemini_model)
    if extractor is not None and gemini_configured:
        try:
            intent = await extractor.extract_intent(raw_request)
            model = getattr(extractor, "model", settings.gemini_model)
            return intent, "gemini", model if isinstance(model, str) else settings.gemini_model
        except GeminiError as exc:
            logger.info(
                "gemini_intent_fallback",
                extra={"code": exc.code},
            )
    intent = fallback_intent(raw_request)
    return intent, "fallback", settings.gemini_model if gemini_configured else None


async def run_preview(
    db: AsyncSession,
    settings: Settings,
    threat: CompositeThreatIntel,
    *,
    owner_user_id: uuid.UUID,
    device_id: uuid.UUID,
    raw_request: str,
    http_client: httpx.AsyncClient | None = None,
    extractor: IntentExtractor | None = None,
    request_id: uuid.UUID | None = None,
) -> PreviewOut:
    """Run the deterministic preview/orchestrator loop (optionally bound to a request)."""
    trace: list[str] = []
    gemini_configured = bool(settings.gemini_api_key and settings.gemini_model)

    owned = await load_owned_device(db, device_id=device_id, owner_user_id=owner_user_id)
    if owned is None:
        from app.core.errors import AppError

        raise AppError("NOT_FOUND", 404)

    device, facts = owned

    # 1. extract_intent
    trace.append(TOOL_EXTRACT_INTENT)
    if extractor is None and gemini_configured and http_client is not None:
        try:
            extractor = GeminiClient(settings, http_client)
        except GeminiError:
            extractor = None
    intent, source, model = await extract_intent_tool(
        raw_request=raw_request, settings=settings, extractor=extractor
    )
    intent_payload = _intent_out(intent, source)

    if intent.intent != "INSTALL_SOFTWARE":
        msg = (
            intent.clarification_question
            or (
                "I'm Sentinel, your organisation's software provisioning agent. "
                "I help install approved software on your enrolled devices. "
                "How may I help you today?"
            )
        )
        return PreviewOut(
            status="UNKNOWN_INTENT",
            intent=intent_payload,
            explanation=msg,
            tool_trace=trace,
            gemini_configured=gemini_configured,
            model=model,
        )

    if intent.clarification_required:
        question = intent.clarification_question or (
            "I'm Sentinel — which approved software would you like to install on this device?"
        )
        return PreviewOut(
            status="NEEDS_CLARIFICATION",
            intent=intent_payload,
            explanation=question,
            tool_trace=trace,
            gemini_configured=gemini_configured,
            model=model,
        )

    # 2. resolve_catalogue_alias
    trace.append(TOOL_RESOLVE_ALIAS)
    resolution = await resolve_catalogue_alias(db, intent.software_query)
    if resolution.status == "NOT_FOUND":
        msg = "This software is not currently available in your organisation's catalogue."
        return PreviewOut(
            status="NOT_FOUND",
            intent=intent_payload,
            match=MatchOut(),
            explanation=deterministic_explanation(
                software_name=intent.software_query,
                version=None,
                outcome="NOT_FOUND",
                reason_code="SOFTWARE_NOT_IN_CATALOGUE",
                public_message=msg,
            ),
            tool_trace=trace,
            gemini_configured=gemini_configured,
            model=model,
        )
    if resolution.status == "AMBIGUOUS":
        question = resolution.clarification_question or (
            "Multiple catalogue matches were found. Which exact product should be installed?"
        )
        return PreviewOut(
            status="NEEDS_CLARIFICATION",
            intent=intent_payload.model_copy(
                update={"clarification_required": True, "clarification_question": question}
            ),
            explanation=question,
            tool_trace=trace,
            gemini_configured=gemini_configured,
            model=model,
        )

    hit = resolution.matches[0]

    # 3. pick_catalogue_version
    trace.append(TOOL_PICK_VERSION)
    pick = pick_catalogue_version(
        software=hit.software,
        versions=hit.versions,
        device=device,
        facts=facts,
        requested_version=intent.requested_version,
        stale_after_seconds=settings.device_stale_after_seconds,
    )
    if pick.status == "VERSION_NOT_FOUND":
        msg = (
            f"Version {intent.requested_version} for {hit.software.display_name} "
            "is not in the catalogue."
        )
        return PreviewOut(
            status="NOT_FOUND",
            intent=intent_payload,
            match=MatchOut(
                software_id=hit.software.id,
                software_slug=hit.software.slug,
                display_name=hit.software.display_name,
                matched_alias=hit.matched_alias,
            ),
            explanation=msg,
            tool_trace=trace,
            gemini_configured=gemini_configured,
            model=model,
        )
    if pick.status != "PICKED" or pick.version is None:
        msg = f"{hit.software.display_name} has no compatible version for this device."
        return PreviewOut(
            status="INCOMPATIBLE",
            intent=intent_payload,
            match=MatchOut(
                software_id=hit.software.id,
                software_slug=hit.software.slug,
                display_name=hit.software.display_name,
                matched_alias=hit.matched_alias,
            ),
            policy=PolicyOut(
                outcome="INCOMPATIBLE",
                reason_code=pick.reason_code or "OS_UNSUPPORTED",
                public_message=msg,
                compatible=False,
                compatibility_reason=pick.reason_code,
            ),
            explanation=msg,
            tool_trace=trace,
            gemini_configured=gemini_configured,
            model=model,
        )

    version = pick.version
    match = MatchOut(
        software_id=hit.software.id,
        software_slug=hit.software.slug,
        display_name=hit.software.display_name,
        matched_alias=hit.matched_alias,
        catalogue_version_id=version.id,
        version=version.version,
    )

    # 4. evaluate_policy (deterministic — never Gemini)
    trace.append(TOOL_EVALUATE_POLICY)
    evaluation = await evaluate_policy_tool(
        db,
        settings,
        threat,
        device=device,
        software=hit.software,
        version=version,
        request_id=request_id,
    )
    policy = PolicyOut(
        outcome=evaluation.outcome,
        reason_code=evaluation.reason_code,
        public_message=evaluation.public_message,
        compatible=evaluation.compatible,
        compatibility_reason=evaluation.compatibility_reason,
        threat_verdict=evaluation.threat_verdict,
        threat_provider=evaluation.threat_provider,
        policy_decision=evaluation.policy_decision,
        policy_revision=evaluation.policy_revision,
        auto_approve_eligible=evaluation.auto_approve_eligible,
        details=evaluation.details,
    )
    status: PreviewStatus = _POLICY_STATUS.get(evaluation.outcome, "READY")

    # 5. explain_decision
    trace.append(TOOL_EXPLAIN)
    summary = decision_summary(
        software_name=hit.software.display_name,
        version=version.version,
        outcome=evaluation.outcome,
        reason_code=evaluation.reason_code,
        public_message=evaluation.public_message,
    )
    explanation = deterministic_explanation(
        software_name=hit.software.display_name,
        version=version.version,
        outcome=evaluation.outcome,
        reason_code=evaluation.reason_code,
        public_message=evaluation.public_message,
    )
    if extractor is not None and source == "gemini":
        polished = await extractor.explain(summary)
        if polished:
            explanation = polished

    return PreviewOut(
        status=status,
        intent=intent_payload,
        match=match,
        policy=policy,
        explanation=explanation,
        tool_trace=trace,
        gemini_configured=gemini_configured,
        model=model,
    )
