# 1.Log thô sinh ra từ web server / WAF

# 2.features_poc.py → tiền xử lý & trích xuất đặc trưng

# 3.train_iforest.py → huấn luyện Isolation Forest (dựa vào log sạch)

# 4.serve_infer.py → chạy mô hình trên log mới để phát hiện anomaly

# 5.actions/ban_ip.sh → nếu phát hiện IP xấu → block

# 6.wazuh-integration → SIEM nhận alert, hiển thị dashboard & correlation

# 7.log_replay.py → test lại hệ thống bằng cách phát lại log cũ

# 8.docker-compose.yml & config.yaml → môi trường triển khai + cấu hình
