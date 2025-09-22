#!/usr/bin/env bash
set -euo pipefail
IP="${1:-}"
MINUTES="${2:-30}"

if [[ -z "$IP" ]]; then
  echo "Usage: $0 <ip> [minutes]" >&2
  exit 1
fi

# Ghi lại log để Fail2ban có thể đọc nếu muốn
mkdir -p /var/log/ai-security
echo "$(date -u +%FT%TZ) BAN $IP ${MINUTES}m" >> /var/log/ai-security/ban.log

# Nếu có fail2ban, ban trực tiếp qua jail 'ai-jail' (đổi tên jail nếu cần)
if command -v fail2ban-client >/dev/null 2>&1; then
  sudo fail2ban-client set ai-jail banip "$IP" || true
fi
