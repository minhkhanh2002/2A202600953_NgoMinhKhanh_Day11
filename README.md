# Assignment 11 — Production Defense-in-Depth Pipeline

**Môn:** AICB-P1 — AI Agent Development · **Tác giả:** Ngô Minh Khánh
**Framework:** Pure Python + `google-genai` (Gemini)

Xây dựng một **pipeline phòng thủ đa lớp** cho trợ lý AI ngân hàng VinBank: nối nhiều
lớp an toàn độc lập để lớp này bỏ sót thì lớp sau bắt được, kèm audit và monitoring.

---

## Kiến trúc — 6 lớp

```
Đầu vào người dùng
  -> [1] Rate Limiter        (giới hạn tần suất theo user — chặn lạm dụng/flood)
  -> [2] Input Guardrails     (regex chống injection + lọc chủ đề — chặn prompt xấu)
  -> [3] LLM (Gemini)         (sinh câu trả lời)
  -> [4] Output Guardrails    (che PII/bí mật — chặn rò rỉ dữ liệu)
  -> [5] LLM-as-Judge         (chấm điểm 4 tiêu chí: Safety/Relevance/Accuracy/Tone)
  -> [6] Audit + Monitoring   (ghi log mọi thứ, cảnh báo khi vượt ngưỡng)
  -> Câu trả lời
```

| # | Lớp | Bắt được gì mà lớp khác bỏ sót |
|---|-----|--------------------------------|
| 1 | Rate Limiter | lớp duy nhất thấy *tần suất* request của mỗi user |
| 2 | Input Guardrails | cổng duy nhất *trước* LLM → chặn tấn công đã biết với chi phí thấp |
| 3 | Output Guardrails | bảo vệ *đầu ra* bất kể đầu vào lọt qua kiểu gì |
| 4 | LLM-as-Judge | hiểu *ngữ nghĩa* (gây hại tinh vi, lạc đề, bịa đặt) — regex không làm được |
| 5 | Audit Log | lớp duy nhất lưu hồ sơ phục vụ điều tra |
| 6 | Monitoring | lớp duy nhất thấy *tổng hợp* (tấn công phối hợp, thoái hóa mô hình) |

---

## Cấu trúc thư mục

```
2A202600953_NgoMinhKhanh_Day11/
├── notebooks/
│   ├── assignment11_defense_pipeline.ipynb   # ★ BÀI NỘP CHÍNH (Part A) — đã có output thật
│   ├── security_audit.json                   # nhật ký kiểm toán xuất ra khi chạy
│   ├── lab11_guardrails_hitl.ipynb           # notebook lab gốc (tham khảo)
│   └── attack_defense_arena.ipynb            # game tấn công–phòng thủ (hoạt động riêng)
├── report.md                                 # ★ BÁO CÁO (Part B) — 5 câu hỏi
├── assignment11_defense_pipeline.md          # đề bài gốc
├── src/                                      # code lab gốc (13 TODO, tham khảo)
├── build_notebook.py                         # script dựng notebook (tiện tái lập)
├── validate_logic.py                         # kiểm thử các lớp Python thuần (không cần key)
├── requirements.txt
└── README.md
```

---

## Cách chạy

**Yêu cầu:** Python 3, `google-genai`, và một `GOOGLE_API_KEY` (lấy tại
https://aistudio.google.com/apikey).

```bash
pip install "google-genai>=1.0.0"
```

Mở `notebooks/assignment11_defense_pipeline.ipynb` (Colab hoặc Jupyter/VSCode) rồi
**Run All**. API key được nạp linh hoạt theo thứ tự: biến môi trường `GOOGLE_API_KEY`
→ Colab Secrets → nhập tay qua ô `getpass`.

> **Model:** dùng `gemini-2.5-flash`. (Free-tier của `gemini-2.5-flash-lite` chỉ
> 20 request/ngày nên dễ cạn; quota tính riêng theo model.) `call_llm` có retry +
> backoff đọc `retryDelay`, và lệnh gọi judge được bọc try/except để lỗi quota không
> làm hỏng notebook.

Kiểm thử nhanh các lớp logic **không cần API key**:

```bash
python validate_logic.py     # rate limiter, injection/topic filter, content filter
```

---

## Kết quả thực thi (đã nhúng trong notebook)

| Test | Kết quả |
|------|---------|
| Test 1 — câu hỏi an toàn | **5/5 PASS**, mỗi câu có điểm judge 4 tiêu chí |
| Test 2 — 7 tấn công | **7/7 BỊ CHẶN** ở Input layer (in đúng pattern khớp) |
| Test 3 — giới hạn tần suất | **10 PASS / 5 BỊ CHẶN** (kèm thời gian chờ) |
| Test 4 — trường hợp biên | **5/5 BỊ CHẶN** (rỗng, quá dài, emoji, SQLi, lạc đề) |
| Output guardrail | che sạch password / API key / DB string / phone / email |
| Monitoring | bắn cảnh báo khi block-rate vượt ngưỡng; xuất `security_audit.json` |

---

## Ánh xạ tới thang điểm

**Part A — Notebook (60đ)**

| Tiêu chí | Điểm | Vị trí |
|----------|------|--------|
| Pipeline chạy end-to-end | 10 | `DefensePipeline` (mục 9) |
| Rate Limiter | 8 | Lớp 1 + Test 3 |
| Input Guardrails | 12 | Lớp 2 + Test 2 (in pattern) |
| Output Guardrails | 12 | Lớp 3 + demo trước/sau (mục 14) |
| LLM-as-Judge đa tiêu chí | 12 | Lớp 4 + điểm judge ở Test 1 |
| Code comments | 6 | docstring "làm gì + bắt attack nào" cho mọi class/hàm |

**Part B — Báo cáo (40đ):** xem `report.md` — phân tích lớp, false-positive,
phân tích lỗ hổng (3 attack vượt pipeline + lớp đề xuất), sẵn-sàng-production,
phản tư đạo đức.

---

## Bối cảnh

Bài tập dựa trên **Lab 11 (Guardrails, HITL & Responsible AI)** — tài liệu lab gốc
(`src/`, `lab11_guardrails_hitl.ipynb`, `assignment11_defense_pipeline.md`) được giữ
nguyên để tham khảo. Notebook nộp được xây mới hoàn toàn bằng Pure Python theo đúng
yêu cầu "tự chọn framework" của đề.

## Tham khảo
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Google Gemini API — Rate limits](https://ai.google.dev/gemini-api/docs/rate-limits)
- [AI Safety Fundamentals](https://aisafetyfundamentals.com/)
