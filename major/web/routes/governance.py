"""Governance routes — approvals, risk matrix, and immutable audit."""

from urllib.parse import urlencode

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import Response

from major.db import get_immutable_audit, list_approval_requests, verify_immutable_audit_chain
from major.governance import (
    format_risk_matrix,
    process_approval_decision,
    process_bulk_approval_decisions,
)
from major.web.app import templates

router = APIRouter(prefix="/governance")


@router.get("/")
async def governance_home(
    request: Request,
    status: str = "pending",
    campaign: str | None = None,
    tag: str | None = None,
):
    approvals = list_approval_requests(
        status=status,
        campaign=campaign,
        tag=tag,
        limit=100,
    )
    audit_check = verify_immutable_audit_chain()
    audit_events = get_immutable_audit(limit=50)
    query = urlencode(
        {k: v for k, v in {"status": status, "campaign": campaign, "tag": tag}.items() if v}
    )

    return templates.TemplateResponse(
        "governance.html",
        {
            "request": request,
            "active_page": "governance",
            "approvals": approvals,
            "current_status": status,
            "current_campaign": campaign,
            "current_tag": tag,
            "query_string": query,
            "audit_check": audit_check,
            "audit_events": audit_events,
            "risk_matrix": format_risk_matrix(),
        },
    )


@router.post("/approvals/{approval_id}/approve")
async def approve_request(
    approval_id: str,
    note: str = Form(default=""),
):
    result = process_approval_decision(
        approval_id=approval_id,
        approved=True,
        actor="web-ui:approve",
        note=note,
    )
    if result["status"] == "not_found":
        raise HTTPException(404, "Approval not found")
    if result["status"] == "already_resolved":
        raise HTTPException(409, "Approval is already resolved")
    if result["status"] == "error":
        raise HTTPException(500, "Could not update approval")

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/governance/"
    return response


@router.post("/approvals/{approval_id}/reject")
async def reject_request(
    approval_id: str,
    note: str = Form(default=""),
):
    result = process_approval_decision(
        approval_id=approval_id,
        approved=False,
        actor="web-ui:reject",
        note=note,
    )
    if result["status"] == "not_found":
        raise HTTPException(404, "Approval not found")
    if result["status"] == "already_resolved":
        raise HTTPException(409, "Approval is already resolved")
    if result["status"] == "error":
        raise HTTPException(500, "Could not update approval")

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/governance/"
    return response


@router.post("/approvals/bulk")
async def bulk_approval_decisions(
    campaign: str = Form(default=""),
    tag: str = Form(default=""),
    decision: str = Form(default="approve"),
    note: str = Form(default=""),
):
    campaign_value = campaign.strip() or None
    tag_value = tag.strip() or None
    approved = decision.strip().lower() == "approve"
    _ = process_bulk_approval_decisions(
        approved=approved,
        actor="web-ui:bulk-approve" if approved else "web-ui:bulk-reject",
        note=note,
        campaign=campaign_value,
        tag=tag_value,
        limit=500,
    )

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/governance/"
    return response
