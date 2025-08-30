ARG BASE_TAG=1.17.0-rolling
FROM kasmweb/ubuntu-jammy-desktop:${BASE_TAG}

USER root

# Kasm environment variables (present in base image)
ENV HOME=/home/kasm-default-profile \
    STARTUPDIR=/dockerstartup \
    INST_SCRIPTS=/dockerstartup/install

WORKDIR /opt/darkus

# --- System packages: Tor + Python toolchain ---
RUN apt-get update && apt-get install -y --no-install-recommends \
      tor python3 python3-pip python3-venv \
      ca-certificates curl netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# --- Python deps (pin to modern libs that work well behind Tor) ---
COPY requirements.txt /opt/darkus/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /opt/darkus/requirements.txt

# --- Darkus source code & assets ---
# Expect Main.py, Banner/ (with Banner.txt), Install.sh, etc. in build context.
COPY . /opt/darkus

# Pre-create output dir and accept Darkus agreement (non-interactive)
RUN mkdir -p /opt/darkus/output /opt/darkus/Banner \
 && echo "Agreement Accepted" > /opt/darkus/Agreement.txt

# Minimal Tor configuration (SOCKS5 on 9050; DNS via Tor because Darkus uses socks5h)
RUN mkdir -p /var/lib/tor && chown -R kasm-user:kasm-user /var/lib/tor
COPY torrc /etc/tor/torrc

# --- Convenience: 'db' command in PATH for analysts ---
# Usage: db <engine|all> "<query>" [--encode] [--images 1|2] ...
# Examples:
#   db all "stolen data"
#   db ahmia "telegram leaks"
RUN bash -lc 'cat >/usr/local/bin/db << "EOF"\n\
#!/usr/bin/env bash\n\
set -euo pipefail\n\
export AGREEMENT_ACCEPTED=1\n\
# Tor endpoint vars (Darkus reads these)\n\
export TOR_SOCKS_HOST=127.0.0.1\n\
export TOR_SOCKS_PORT=9050\n\
cd /opt/darkus\n\
# Start Tor in the background if not already running\n\
if ! nc -z 127.0.0.1 9050 >/dev/null 2>&1; then\n\
  tor >/tmp/tor.log 2>&1 &\n\
  for i in {1..60}; do nc -z 127.0.0.1 9050 && break; sleep 1; done\n\
fi\n\
exec python3 /opt/darkus/Main.py "$@"\n\
EOF\n\
&& chmod +x /usr/local/bin/db'

# --- Nice-to-have: open a terminal on session start with a hint banner ---
# Kasm runs scripts in $STARTUPDIR automatically. This opens xfce4-terminal
# and shows how to use the 'db' command without forcing anything on the user.
RUN bash -lc 'cat > ${STARTUPDIR}/custom_startup.sh << "EOF"\n\
#!/usr/bin/env bash\n\
set -e\n\
# Don\'t block Kasm startup; launch a terminal after the desktop loads\n\
( sleep 1; xfce4-terminal --geometry=120x30 --command bash -lc \\\n\
  \"clear; echo; echo \'Darkus ready. Examples:\'; \\\n\
   echo \'  db all \\\"stolen data\\\" \'; \\\n\
   echo \'  db ahmia \\\"telegram leaks\\\" \'; \\\n\
   echo; exec bash\" >/dev/null 2>&1 ) &\n\
exit 0\n\
EOF\n\
&& chmod +x ${STARTUPDIR}/custom_startup.sh'

# Drop privileges back to the default Kasm user
USER kasm-user

# Default env for Darkus/Tor at runtime (can be overridden per-workspace)
ENV TOR_SOCKS_HOST=127.0.0.1 \
    TOR_SOCKS_PORT=9050 \
    AGREEMENT_ACCEPTED=1

# The base image provides the proper ENTRYPOINT/CMD for Kasm sessions.
# Analysts will land on the desktop with a terminal popped open and can type:
#   db all "your keywords"
