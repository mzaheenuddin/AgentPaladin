FROM caddy:2.10-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d

USER root

# The stock Caddy binary carries cap_net_bind_service. The gateway binds an
# unprivileged port and runs with no-new-privileges + cap_drop ALL, so a file
# capability would make exec fail with EPERM.
RUN apk add --no-cache libcap \
    && setcap -r /usr/bin/caddy

COPY docker/gateway/Caddyfile /etc/caddy/Caddyfile
COPY docker/gateway/entrypoint.sh /usr/local/bin/gateway-entrypoint.sh

RUN chmod 0755 /usr/local/bin/gateway-entrypoint.sh

USER 1000:1000
ENTRYPOINT ["/usr/local/bin/gateway-entrypoint.sh"]
