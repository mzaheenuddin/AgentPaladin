#!/bin/sh
set -eu

GATEWAY_IP="${GATEWAY_IP:-172.31.240.2}"
GATEWAY_PORT="${GATEWAY_PORT:-24080}"
EGRESS_PROXY_ENABLED="${EGRESS_PROXY_ENABLED:-0}"
EGRESS_PROXY_IP="${EGRESS_PROXY_IP:-172.31.240.4}"
EGRESS_PROXY_PORT="${EGRESS_PROXY_PORT:-24128}"
BROKER_ENABLED="${BROKER_ENABLED:-0}"
BROKER_IP="${BROKER_IP:-172.31.240.5}"
BROKER_PORT="${BROKER_PORT:-24443}"

iptables -w 5 -F
iptables -w 5 -X || true
iptables -w 5 -P INPUT DROP
iptables -w 5 -P FORWARD DROP
iptables -w 5 -P OUTPUT DROP

# Docker injects an embedded DNS resolver at 127.0.0.11 even on internal
# networks. The generated /etc/resolv.conf points elsewhere, but a process can
# still query 127.0.0.11 directly. That would allow name resolution and a DNS
# exfiltration channel through the loopback ACCEPT rule below.
iptables -w 5 -A OUTPUT -d 127.0.0.11/32 -j DROP
iptables -w 5 -A INPUT -s 127.0.0.11/32 -j DROP

iptables -w 5 -A INPUT -i lo -j ACCEPT
iptables -w 5 -A OUTPUT -o lo -j ACCEPT
iptables -w 5 -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w 5 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# The only outbound capabilities are the authenticated LLM gateway and,
# when explicitly enabled by a profile, the scoped egress proxies.
iptables -w 5 -A OUTPUT -d "$GATEWAY_IP" -p tcp --dport "$GATEWAY_PORT" -j ACCEPT

if [ "$EGRESS_PROXY_ENABLED" = "1" ]; then
  iptables -w 5 -A OUTPUT -d "$EGRESS_PROXY_IP" -p tcp --dport "$EGRESS_PROXY_PORT" -j ACCEPT
fi

if [ "$BROKER_ENABLED" = "1" ]; then
  iptables -w 5 -A OUTPUT -d "$BROKER_IP" -p tcp --dport "$BROKER_PORT" -j ACCEPT
fi

# Lockdown IPv6 in the network namespace if ip6tables is present
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -w 5 -F 2>/dev/null || true
  ip6tables -w 5 -X 2>/dev/null || true
  ip6tables -w 5 -P INPUT DROP 2>/dev/null || true
  ip6tables -w 5 -P FORWARD DROP 2>/dev/null || true
  ip6tables -w 5 -P OUTPUT DROP 2>/dev/null || true
  ip6tables -w 5 -A INPUT -i lo -j ACCEPT 2>/dev/null || true
  ip6tables -w 5 -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
  ip6tables -w 5 -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  ip6tables -w 5 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
fi

printf 'sandbox firewall applied:\n'
iptables -w 5 -S

# The rules deliberately persist in the shared network namespace after this
# one-shot container exits. A later sandbox container has no NET_ADMIN.
