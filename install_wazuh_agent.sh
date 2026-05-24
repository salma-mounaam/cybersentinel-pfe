#!/bin/bash
set -e

AGENT_NAME="$1"
MANAGER_IP="$2"

if [ -z "$AGENT_NAME" ] || [ -z "$MANAGER_IP" ]; then
  echo "Usage: sudo bash install_wazuh_agent.sh <AGENT_NAME> <MANAGER_IP>"
  exit 1
fi

echo "=== Installation Wazuh Agent ==="
echo "Agent name : $AGENT_NAME"
echo "Manager IP : $MANAGER_IP"

apt-get update
apt-get install -y curl gnupg apt-transport-https lsb-release

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list

apt-get update

WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" \
  apt-get install -y wazuh-agent

systemctl daemon-reload
systemctl enable --now wazuh-agent

echo "✅ Agent Wazuh installé : $AGENT_NAME → $MANAGER_IP"
systemctl status wazuh-agent --no-pager || true

