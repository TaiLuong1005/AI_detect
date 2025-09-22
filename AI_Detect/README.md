# AI-Detector (Unsupervised) – Brute-force & SQLi from Logs

Starter kit khớp workflow: **WAF/Access log → AI (Isolation Forest) → Wazuh → Fail2ban**.

## Thành phần
- `features_poc.py`: trích đặc trưng từ access log (Nginx combined) + heuristic SQLi.
- `train_iforest.py`: huấn luyện Isolation Forest không giám sát từ dữ liệu nền.
- `serve_infer.py`: FastAPI nhận sự kiện log, trả anomaly score.
- `log_replay.py`: tail access.log, gọi AI, ghi alert JSON cho Wazuh, (tuỳ chọn) ban IP.
- `config.yaml`: ngưỡng + đường dẫn log/alert (có thể override bằng CLI).
- `actions/ban_ip.sh`: script ban IP (Fail2ban), đồng thời ghi `ban.log`.
- `wazuh-integration/local_decoder.xml` + `local_rules.xml`: để Wazuh đọc alert JSON.
- `docker-compose.yml` (template): chạy AI service + logtailer (tự chỉnh volume/log path).

## Cài đặt nhanh
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### (A) Thu thập dữ liệu nền & Train mô hình
Chạy trong lúc hệ thống có traffic bình thường (30–120 phút là ổn cho demo):
```bash
# 1) Mở AI service tạm thời với model "rỗng" (bỏ qua, nếu đã có model)
# 2) Gom features nền (không tạo alert, chỉ ghi đặc trưng)
python log_replay.py --dry-run --emit-features features_train.jsonl
# ... để chạy một thời gian, sau đó:
python train_iforest.py --input features_train.jsonl --model iforest_sqlbf.joblib
```

### (B) Chạy phát hiện (Realtime)
```bash
# tab 1: mở API
uvicorn serve_infer:app --host 0.0.0.0 --port 8000

# tab 2: bắt đầu đọc log và tạo alert
python log_replay.py --access-log /var/log/nginx/access.log                              --infer-url http://127.0.0.1:8000/score
```
Kiểm tra:
```bash
tail -f /var/log/ai-security/alerts.log
```

### (C) Tích hợp Wazuh
- Thêm localfile JSON vào `ossec.conf` để đọc `/var/log/ai-security/alerts.log`.
- Copy 2 file trong `wazuh-integration/` vào đúng thư mục Wazuh (`/var/ossec/etc/...`) rồi restart.

### (D) Tích hợp Fail2ban (tuỳ chọn)
- Sửa `actions/ban_ip.sh` cho đúng jail (hoặc giữ cơ chế ghi ban.log và để Fail2ban đọc).
- `chmod +x actions/ban_ip.sh`

## Thử nghiệm
- **Brute-force**: bắn POST liên tục vào `/login` (VD: hydra).
- **SQLi**: dùng sqlmap (`--risk 2 --level 2`) – sẽ thấy điểm bất thường tăng, rule Wazuh sinh alert, và (nếu bật) ban IP.

## Ghi chú
- Mặc định parser là **Nginx combined log**. Nếu bạn dùng Apache hoặc format khác, chỉnh `features_poc.parse_nginx()`.
- Trường `waf.anomaly` mặc định 0 trừ khi bạn tự tích hợp parser ModSecurity. Không bắt buộc để chạy demo.
- Dự án minh hoạ mục đích học thuật; chỉ thử nghiệm trong lab hợp pháp (VD: DVWA).
