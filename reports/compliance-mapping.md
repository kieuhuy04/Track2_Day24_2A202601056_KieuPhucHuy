# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | chưa implement — không có API/cascade xoá 1 `customer_id` khỏi `data/customers.json` kèm giữ nguyên `ledger.jsonl` (xem Guide.md stretch #3) | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | data-flow inventory cho mọi nơi PII có thể chảy tới, bao gồm API model provider nếu dùng `--model` | `reports/dpia-lite.md` §3 |
| ASI03 — privilege abuse | mỗi tool call mang identity riêng (`agent_id`, `run_id`) + PEP kiểm tra trước khi chạy, không có identity dùng chung giữa Run A/Run B | `agent/policy.py:31-36` (`PolicyContext.agent_owner`/`delegation_depth`), `agent/runner.py:80-93` (`_log()` ghi `agent_id`/`run_id` vào mỗi dòng ledger trước khi tool chạy) |
| ASI01 — goal hijack | trifecta split: Run A chỉ đọc `search_docs`, không bao giờ gọi `read_customer`/`http_post`; Run B chỉ nhận `ticket_id` kiểu `int` trích từ **tên file** (không phải free text) rồi tra `related_tickets` — customer_id do attacker viết trong nội dung ticket không bao giờ được dùng | `agent/runner.py:158-161` (trích `ticket_id` từ filename qua `_ticket_id_from_filename`), `agent/runner.py:163-186` (Run B tra `related_tickets` qua `_customer_for_ticket`, chỉ gọi `read_customer` khi khớp); kết quả 5/5 biến thể bị chặn: `reports/attack-after.log` (rỗng) + `pytest tests/test_injection.py` PASS + `pytest tests/test_split.py` PASS (containment thật — `KH-000777` chỉ được attacker nhắc trong free text không bao giờ bị `read_customer` gọi tới) |
| ISO 42001 Clause 5-6 | policy-as-code tách riêng khỏi runner (một file, một interface `check()` duy nhất), rule tối thiểu viết tường minh chứ không suy luận ngầm trong `runner.py` — dễ review độc lập với logic điều phối agent | rule tối thiểu tại `agent/policy.py:40-45`; interface `PolicyContext`/`check()` tại `agent/policy.py:31-39`; sau khi commit, `git log --oneline -- agent/policy.py` sẽ cho lịch sử review từng thay đổi rule (1 commit/thay đổi, xem quy ước commit của repo) |
