#!/usr/bin/env bash
set -euo pipefail

# Start Tor in background
tor &

# Wait for SOCKS port to answer
echo "Waiting for Tor (SOCKS) on 127.0.0.1:9050 ..."
for i in {1..60}; do
  if nc -z 127.0.0.1 9050; then
    echo "Tor is up."
    break
  fi
  sleep 1
done

# Optional: pre-accept the EULA to avoid prompt in headless runs
if [[ "${AGREEMENT_ACCEPTED:-0}" == "1" ]]; then
  echo "Agreement Accepted" > /app/Agreement.txt
fi

# Hand off to your tool (interactive)
exec python /app/Main.py
