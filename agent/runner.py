"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

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

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
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

AGENT_ID = "lab24-agent"
_TICKET_ID_RE = re.compile(r"ticket-(\d+)", re.IGNORECASE)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _args_hash(args: dict) -> str:
    payload = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _log(ledger_path: Path, run_id: str, tool: str, args: dict, classification: str, allow: bool, reason: str) -> None:
    ledger.append(
        {
            "ts": _now(),
            "agent_id": AGENT_ID,
            "run_id": run_id,
            "tool": tool,
            "args_hash": _args_hash(args),
            "classification": classification,
            "decision": "allow" if allow else "deny",
            "reason": reason,
        },
        ledger_path,
    )


def _ticket_id_from_filename(doc_id: str) -> int | None:
    match = _TICKET_ID_RE.search(doc_id)
    return int(match.group(1)) if match else None


def _customer_for_ticket(ticket_id: int, customers: list[dict]) -> dict | None:
    for record in customers:
        if ticket_id in record.get("related_tickets", []):
            return record
    return None


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = (Path(log_dir) if log_dir is not None else REPORTS_DIR) / "ledger.jsonl"

    # --- Run A: chỉ chân "untrusted content". Không gọi read_customer/http_post. ---
    search_ctx = policy.PolicyContext(
        data_classification="internal",
        request_purpose="search-tickets",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_search, search_reason = policy.check(search_ctx)
    _log(ledger_path, "run-a", "search_docs", {"query": message}, "internal", allow_search, search_reason)
    if not allow_search:
        return "Không thể tra cứu ticket lúc này (bị chặn bởi policy)."

    docs = tools.search_docs(message)

    # find_injection() chỉ dùng để PHÁT HIỆN + LOG ý đồ tấn công. customer_ids
    # nó trả về là do attacker viết trong free text nên KHÔNG BAO GIỜ được
    # dùng để quyết định gọi read_customer nào (đó là lý do containment đứng
    # vững trước biến thể 5 trong khi một bộ filter chuỗi thì không).
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)
    if injected is not None:
        egress_ctx = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="attacker-instructed-egress",
            agent_owner="run-a",
            delegation_depth=0,
            egress_enabled=True,
        )
        allow_egress, egress_reason = policy.check(egress_ctx)
        _log(
            ledger_path,
            "run-a",
            "http_post",
            {"target_url": injected.target_url, "customer_ids_in_text": injected.customer_ids},
            "restricted",
            allow_egress,
            egress_reason,
        )
        # Policy tối thiểu (restricted + egress) luôn deny nên nhánh allow
        # không bao giờ chạy tới đây trong lab này; nếu policy.py bị nới lỏng
        # thì containment vẫn đứng vững vì không có customer nào được đọc từ
        # free text để mà gửi đi ở dưới.

    # --- Run B: chân "private data". Chỉ nhận typed ticket_id trích từ TÊN
    # FILE (nguồn tin cậy), tra ngược qua related_tickets trong
    # customers.json — không bao giờ tin customer_id do attacker viết. ---
    ticket_ids = sorted(
        {tid for d in docs if (tid := _ticket_id_from_filename(d["id"])) is not None}
    )
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))

    seen_customer_ids: set[str] = set()
    for ticket_id in ticket_ids:
        record = _customer_for_ticket(ticket_id, customers)
        if record is None:
            continue
        customer_id = record["customer_id"]
        if customer_id in seen_customer_ids:
            continue
        seen_customer_ids.add(customer_id)

        read_ctx = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="ticket-reconciliation",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=False,
        )
        allow_read, read_reason = policy.check(read_ctx)
        _log(ledger_path, "run-b", "read_customer", {"customer_id": customer_id}, "restricted", allow_read, read_reason)
        if not allow_read:
            continue
        tools.read_customer(customer_id)

    return llm.summarize(docs)
