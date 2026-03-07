"""Governance routes — approvals, risk matrix, and immutable audit."""

import json

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import Response

from major.db import (
    append_immutable_audit_event,
    get_approval_request,
    get_immutable_audit,
    list_approval_requests,
    resolve_approval_request,
    verify_immutable_audit_chain,
)
from major.governance import format_risk_matrix, queue_task_with_policy
from major.web.app import templates

router = APIRouter(prefix="/governance")


@router.get("/")
async def governance_home(request: Request, status: str = "pending"):
    approvals = list_approval_requests(status=status, limit=100)
    audit_check = verify_immutable_audit_chain()
    audit_events = get_immutable_audit(limit=50)

    return templates.TemplateResponse(
        "governance.html",
        {
            "request": request,
            "active_page": "governance",
            "approvals": approvals,
            "current_status": status,
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
    req = get_approval_request(approval_id)
    if not req:
        raise HTTPException(404, "Approval not found")
    if req["status"] != "pending":
        raise HTTPException(409, f"Approval is already {req['status']}")

    if not resolve_approval_request(
        approval_id, approved=True, decided_by="web-ui:operator", note=note
    ):
        raise HTTPException(500, "Could not update approval")

    task_args = json.loads(req.get("args") or "{}")
    decision = queue_task_with_policy(
        session_id=req["session_id"],
        task_type=req.get("task_type") or "shell",
        args=task_args,
        actor="web-ui:approve",
        approval_id=approval_id,
    )
    append_immutable_audit_event(
        actor="web-ui:approve",
        action="approval_decision",
        session_id=req.get("session_id"),
        approval_id=approval_id,
        risk_level=req.get("risk_level", "unknown"),
        policy_result="approved",
        details={"note": note, "queue_result": decision["status"]},
    )

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/governance/"
    return response


@router.post("/approvals/{approval_id}/reject")
async def reject_request(
    approval_id: str,
    note: str = Form(default=""),
):
    req = get_approval_request(approval_id)
    if not req:
        raise HTTPException(404, "Approval not found")
    if req["status"] != "pending":
        raise HTTPException(409, f"Approval is already {req['status']}")

    if not resolve_approval_request(
        approval_id, approved=False, decided_by="web-ui:operator", note=note
    ):
        raise HTTPException(500, "Could not update approval")

    append_immutable_audit_event(
        actor="web-ui:reject",
        action="approval_decision",
        session_id=req.get("session_id"),
        approval_id=approval_id,
        risk_level=req.get("risk_level", "unknown"),
        policy_result="rejected",
        details={"note": note},
    )

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/governance/"
    return response
