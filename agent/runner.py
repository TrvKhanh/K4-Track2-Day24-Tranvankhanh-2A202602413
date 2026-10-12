"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _build_context(principal_id: str, requested_tool: str, *, data_classification: str,
                   request_purpose: str = "support-reply", agent_scopes: tuple[str, ...] = (),
                   parent_scopes: tuple[str, ...] = (), delegation_depth: int = 0,
                   egress_enabled: bool = False) -> policy.PolicyContext:
    return policy.PolicyContext(
        data_classification=data_classification,
        request_purpose=request_purpose,
        agent_owner="lab24-agent/run-b",
        delegation_depth=delegation_depth,
        egress_enabled=egress_enabled,
        principal_id=principal_id,
        requested_tool=requested_tool,
        agent_scopes=agent_scopes,
        parent_scopes=parent_scopes,
        expires_at="2099-01-01T00:00:00+00:00",
    )


def _append_entry(log_dir: Path, *, principal_id: str, requested_tool: str, allowed: bool,
                 reason: str, data_classification: str, request_purpose: str = "support-reply",
                 args: dict | None = None, agent_scopes: tuple[str, ...] = ()) -> dict:
    path = log_dir / "ledger.jsonl"
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_id": "lab24-agent",
        "run_id": f"{principal_id}-run",
        "tool": requested_tool,
        "args_hash": hashlib.sha256(
            json.dumps(args or {}, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest(),
        "classification": data_classification,
        "decision": "allow" if allowed else "deny",
        "reason": reason,
        "on_behalf_of": principal_id,
        "expires_at": "2099-01-01T00:00:00+00:00",
        "request_purpose": request_purpose,
        "agent_scopes": list(agent_scopes),
    }
    return ledger.append(record, path)


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    log_dir = Path(log_dir) if log_dir is not None else DEFAULT_LEDGER_PATH.parent
    log_dir.mkdir(parents=True, exist_ok=True)

    docs = tools.search_docs(message)
    search_context = _build_context(
        principal_id,
        "search_docs",
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_scopes=("search_docs", "read_customer"),
    )
    allowed, reason = policy.check(search_context)
    _append_entry(
        log_dir,
        principal_id=principal_id,
        requested_tool="search_docs",
        allowed=allowed,
        reason=reason,
        data_classification="internal",
        request_purpose="summarize-tickets",
        args={"query": message},
        agent_scopes=("search_docs", "read_customer"),
    )
    if not allowed:
        return llm.summarize([])

    _ = llm.find_injection("\n\n".join(doc["text"] for doc in docs))

    customer_ids: set[str] = set()
    for doc in docs:
        for match in re.findall(r"ticket-(\d+)", doc["id"]):
            ticket_id = int(match)
            customers = json.loads((Path(__file__).resolve().parent.parent / "data" / "customers.json").read_text(encoding="utf-8"))
            for customer in customers:
                if ticket_id in customer.get("related_tickets", []):
                    customer_ids.add(str(customer["customer_id"]))

    for customer_id in sorted(customer_ids):
        context = _build_context(
            principal_id,
            "read_customer",
            data_classification="restricted",
            request_purpose="support-reply",
            agent_scopes=("search_docs", "read_customer"),
        )
        allowed, reason = policy.check(context)
        _append_entry(
            log_dir,
            principal_id=principal_id,
            requested_tool="read_customer",
            allowed=allowed,
            reason=reason,
            data_classification="restricted",
            request_purpose="support-reply",
            args={"customer_id": customer_id},
            agent_scopes=("search_docs", "read_customer"),
        )
        if allowed:
            tools.read_customer(customer_id)

    return llm.summarize(docs)
