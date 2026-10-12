"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict[str, dict]:
    path = Path(__file__).resolve().parent.parent / "data" / "principals.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _parse_iso_utc(value: str) -> datetime | None:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except ValueError:
        return None


def check(context: PolicyContext) -> tuple[bool, str]:
    # Rule tối thiểu bắt buộc: dữ liệu restricted + egress enabled = deny.
    if context.data_classification == "restricted" and context.egress_enabled is True:
        return False, "restricted data cannot egress; egress_enabled=True is denied"

    principal = _load_principals().get(context.principal_id)
    if principal is None:
        return False, f"unknown principal_id={context.principal_id!r}"

    expires_at = _parse_iso_utc(context.expires_at)
    if expires_at is None or expires_at <= datetime.now(timezone.utc):
        return False, f"run expired or missing expiration: expires_at={context.expires_at!r}"

    if context.request_purpose not in principal.get("purposes", []):
        return False, (
            f"purpose {context.request_purpose!r} is not allowed for principal "
            f"{context.principal_id!r}; allowed={principal.get('purposes', [])}"
        )

    effective_scopes = set(principal.get("allowed_tools", [])) & set(context.agent_scopes)
    if context.delegation_depth > 0:
        if not context.parent_scopes:
            return False, "delegated call requires parent_scopes to constrain permissions"
        effective_scopes &= set(context.parent_scopes)

    if context.requested_tool:
        if context.requested_tool not in effective_scopes:
            return False, (
                f"requested_tool={context.requested_tool!r} is not in effective scopes for "
                f"principal={context.principal_id!r}; effective_scopes={sorted(effective_scopes)}"
            )

    return True, (
        f"principal={context.principal_id!r} allowed to call {context.requested_tool or 'tool'} "
        f"for purpose {context.request_purpose!r}"
    )
