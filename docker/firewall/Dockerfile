FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f

RUN apk add --no-cache iptables

COPY docker/firewall/lockdown.sh /usr/local/bin/lockdown.sh
RUN chmod 0755 /usr/local/bin/lockdown.sh

ENTRYPOINT ["/usr/local/bin/lockdown.sh"]
