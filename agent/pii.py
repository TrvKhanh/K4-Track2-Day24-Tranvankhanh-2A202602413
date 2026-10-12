"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
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

_EMAIL_RE = re.compile(
    r"(?i)(?<![\w.])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w.])"
)
_CCCD_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")
_PHONE_RE = re.compile(r"(?<!\d)(0(?:[ .-]?\d){9})(?!\d)")
_BANK_CONTEXT_RE = re.compile(
    r"(?ix)(?:stk|so\s*tai\s*khoan|số\s*tài\s*khoản|số\s*tk|so\s*tk)"
    r"\s*[:.-]?\s*(\d{8,16})"
)


def _dedupe(matches: list[dict]) -> list[dict]:
    matches = sorted(matches, key=lambda item: (item["start"], -(item["end"] - item["start"])))
    kept: list[dict] = []
    for item in matches:
        if any(item["start"] < prev["end"] and prev["start"] < item["end"] for prev in kept):
            continue
        kept.append(item)
    kept.sort(key=lambda item: item["start"])
    return kept


def detect(text: str) -> list[dict]:
    matches: list[dict] = []

    for pattern, type_name in ((
        _EMAIL_RE,
        "EMAIL",
    ), (
        _BANK_CONTEXT_RE,
        "VN_BANK_ACCOUNT",
    ), (
        _CCCD_RE,
        "VN_CCCD",
    ), (
        _PHONE_RE,
        "VN_PHONE",
    )):
        for match in pattern.finditer(text):
            if type_name == "EMAIL":
                start, end = match.span(1)
            else:
                start, end = match.span(1) if match.lastindex else match.span()
            if start == end:
                continue
            matches.append({"type": type_name, "start": start, "end": end})

    # Loại các số không phải là thông tin nhạy cảm: số điện thoại không lấy làm STK/CCCD.
    result = _dedupe(matches)
    filtered: list[dict] = []
    for item in result:
        if item["type"] == "VN_BANK_ACCOUNT":
            value = text[item["start"] : item["end"]]
            if len(value.replace(" ", "")) < 8:
                continue
        filtered.append(item)
    return filtered


def redact(text: str) -> str:
    matches = detect(text)
    if not matches:
        return text

    redacted = text
    for item in sorted(matches, key=lambda m: (m["start"], m["end"]), reverse=True):
        value = redacted[item["start"] : item["end"]]
        if value:
            redacted = redacted[: item["start"]] + f"[REDACTED_{item['type']}]" + redacted[item["end"] :]
    return redacted
