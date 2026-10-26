FROM python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d

RUN adduser -D -H -u 10002 broker

WORKDIR /app
COPY scripts/dlp_patterns.py /app/dlp_patterns.py
COPY docker/egress-broker/app.py /app/app.py
COPY docker/egress-broker/admin.py /app/admin.py
COPY docker/egress-broker/leak_test.py /app/leak_test.py

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10002:10002
EXPOSE 24443

ENTRYPOINT ["python", "/app/app.py"]
