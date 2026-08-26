"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# Neo theo từ khoá tiếng Việt đứng trước con số, vì độ dài số một mình
# không đủ phân biệt (CCCD 12 số có thể trùng độ dài với STK 12 số).
_CCCD_RE = re.compile(r"CCCD[^\d]{0,40}(\d{12})\b", re.IGNORECASE)
_PHONE_RE = re.compile(
    r"(?:SĐT|số điện thoại|điện thoại)[^\d]{0,60}(0\d{9})\b", re.IGNORECASE
)
_BANK_RE = re.compile(
    r"(?:STK|số tài khoản|tài khoản|chuyển khoản)[^\d]{0,40}(\d{8,16})\b",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    for regex, entity_type in (
        (_CCCD_RE, "VN_CCCD"),
        (_BANK_RE, "VN_BANK_ACCOUNT"),
        (_PHONE_RE, "VN_PHONE"),
    ):
        for match in regex.finditer(text):
            entities.append(
                {"type": entity_type, "start": match.start(1), "end": match.end(1)}
            )
    for match in _EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": match.start(), "end": match.end()})
    entities.sort(key=lambda e: e["start"])
    return entities


def redact(text: str) -> str:
    result = text
    for entity in sorted(detect(text), key=lambda e: e["start"], reverse=True):
        result = (
            result[: entity["start"]]
            + f"[REDACTED_{entity['type']}]"
            + result[entity["end"] :]
        )
    return result
