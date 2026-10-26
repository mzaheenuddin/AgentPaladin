FROM docker.litellm.ai/berriai/litellm:v1.98.0@sha256:20b5044b619055374061a6d5b7b08754cad75aeabbf82ddf4f69cc0cf80ddaf4

COPY docker/litellm/entrypoint.sh /usr/local/bin/litellm-entrypoint.sh
RUN chmod 0755 /usr/local/bin/litellm-entrypoint.sh

USER 101:101
ENTRYPOINT ["/usr/local/bin/litellm-entrypoint.sh"]
