FROM ghcr.io/zaproxy/zaproxy:stable

USER root

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    tcpdump \
    && pip3 install --break-system-packages scapy \
    && rm -rf /var/lib/apt/lists/*

USER zap