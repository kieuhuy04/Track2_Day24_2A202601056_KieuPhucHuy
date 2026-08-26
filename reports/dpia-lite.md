# DPIA-lite (1 trang)

## 1. Dữ liệu gì

Agent chạm vào 2 nguồn dữ liệu, qua 2 tool riêng biệt (`agent/tools.py`):

- `search_docs()` đọc `corpus/*.md` — nội dung ticket hỗ trợ khách hàng,
  **không đáng tin cậy** (attacker có thể ghi vào đây). Có thể chứa
  customer_id dạng text tự do do người viết ticket (kể cả attacker) gõ vào.
- `read_customer()` đọc `data/customers.json` — dữ liệu cá nhân thật của
  khách hàng (synthetic trong lab, nhưng cấu trúc giống dữ liệu thật):
  `name` (họ tên), `cccd` (số CCCD), `phone` (SĐT), `bank_account` (STK),
  `email`. Đây là dữ liệu **restricted** theo `PolicyContext.data_classification`
  (`agent/policy.py`).

`agent/pii.py` phát hiện được 4 loại PII trong text tự do: `VN_CCCD`,
`VN_PHONE`, `VN_BANK_ACCOUNT`, `EMAIL` — dùng để redact trước khi log/log
tràn ra ngoài nếu cần (chưa được runner.py gọi tới trong luồng hiện tại vì
runner không log nguyên văn PII, chỉ log `customer_id` + hash của args).

## 2. Mục đích gì

Người dùng yêu cầu "Tổng hợp các ticket còn mở tuần này" — agent cần:
1. Tìm các ticket liên quan (search_docs) để biết ticket nào đang mở.
2. Tra cứu thông tin khách hàng tương ứng (read_customer) **chỉ cho
   những khách có ticket thật sự thuộc về họ** (qua `related_tickets`
   trong `customers.json`, không phải customer_id do ai đó gõ trong nội
   dung ticket) — phục vụ mục đích đối soát/tổng hợp nội bộ
   (`request_purpose="ticket-reconciliation"`, `agent/runner.py:173-179`).

Agent **không có nhu cầu nghiệp vụ hợp lệ nào để gọi `http_post`** trong
luồng "tổng hợp ticket" này — egress chỉ từng được yêu cầu bởi chỉ thị
injection giả mạo trong nội dung ticket, và bị `policy.check()` deny
(`agent/policy.py:40-45`, dữ liệu `restricted` + `egress_enabled=True`).

## 3. Chảy đi đâu

- **Log nội bộ**: `reports/ledger.jsonl` — chỉ ghi `customer_id`,
  `args_hash` (sha256 của args, không phải PII thô), `classification`,
  `decision`, `reason`. Không ghi CCCD/SĐT/STK/email nguyên văn.
- **Sink (`localhost:9999`, mô phỏng exfil trong lab)**: allowlist cứng
  trong `agent/tools.py:http_post()` — chỉ nhận `http://localhost:9999/*`,
  raise `ToolError` với host/port khác. Trong luồng đã contain
  (`agent/runner.py`), **không có code path nào gọi `http_post` thật**
  cho dữ liệu khách hàng — mọi chỉ thị egress từ nội dung ticket đều bị
  deny trước khi tool chạy. Bằng chứng: `reports/attack-after.log` rỗng
  sau khi replay cả 5 biến thể injection.
- **API model provider (nếu chạy `--model claude-...` thay vì `--mock`)**:
  `agent/llm.py:RealLLM.summarize()` gửi **toàn văn** nội dung các ticket
  khớp (`docs`) sang Anthropic API để tóm tắt — đây LÀ chuyển dữ liệu
  xuyên biên giới theo NĐ 356/2025 nếu provider đặt máy chủ ở nước ngoài,
  vì nội dung ticket có thể chứa customer_id và (nếu quy trình khác đưa
  PII vào ticket) cả PII khác. Lab này **luôn được chấm bằng `--mock`**
  (fake LLM chạy local, không có network call nào ra ngoài `localhost`),
  nên trong chế độ chấm điểm không có luồng xuyên biên giới nào xảy ra.
  Nếu triển khai thật với `--model`, cần: (a) chỉ gửi bản đã `pii.redact()`
  nếu ticket có thể chứa PII của bên thứ ba, và (b) có DPA/điều khoản
  chuyển dữ liệu với provider trước khi bật `--model` cho dữ liệu thật.
