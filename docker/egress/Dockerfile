FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f

RUN apk add --no-cache squid ca-certificates netcat-openbsd \
    && mkdir -p /var/log/squid /var/cache/squid /run/squid \
    && chown -R squid:squid /var/log/squid /var/cache/squid /run/squid

COPY docker/egress/squid.conf /etc/squid/squid.conf

USER squid
EXPOSE 24128
ENTRYPOINT ["squid", "-N", "-f", "/etc/squid/squid.conf"]
