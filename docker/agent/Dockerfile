FROM ghcr.io/anomalyco/opencode:2.1.4@sha256:6176a71bf7c1352d9aa9e7f112a4ef38443079a2f435789a33dd5ae809acea1a

ARG AGENT_UID=1000
ARG AGENT_GID=1000

USER root

RUN if [ "${AGENT_UID}" = "0" ] || [ "${AGENT_GID}" = "0" ]; then \
      echo "refusing to build an agent image for root UID/GID" >&2; \
      exit 1; \
    fi \
    && apk add --no-cache \
      bash \
      ca-certificates \
      curl \
      git \
      iproute2 \
      jq \
      less \
      netcat-openbsd \
      ripgrep \
      util-linux \
    && if grep -q ":${AGENT_GID}:" /etc/group; then \
         AGENT_GROUP="$(grep ":${AGENT_GID}:" /etc/group | cut -d: -f1)"; \
       else \
         addgroup -g "${AGENT_GID}" -S agent; \
         AGENT_GROUP=agent; \
       fi \
    && if ! grep -q ":${AGENT_UID}:" /etc/passwd; then \
         adduser -u "${AGENT_UID}" -G "${AGENT_GROUP}" -h /home/agent -D -s /bin/bash agent; \
       fi \
    && mkdir -p /home/agent /workspace /etc/opencode /etc/git/empty-hooks /usr/local/bin \
    && (chmod u-s /bin/mount /bin/umount 2>/dev/null || true) \
    && chown -R "${AGENT_UID}:${AGENT_GID}" /home/agent /workspace

COPY docker/agent/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/agent/verify-security.sh /usr/local/bin/verify-security.sh

RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/verify-security.sh

USER ${AGENT_UID}:${AGENT_GID}
WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
