FROM python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d

RUN adduser -D -H -u 10001 app

WORKDIR /app
COPY scripts/dlp_patterns.py /app/dlp_patterns.py
COPY docker/prompt-dlp/app.py /app/app.py
COPY docker/prompt-dlp/leak_test.py /app/leak_test.py

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
EXPOSE 24081

ENTRYPOINT ["python", "/app/app.py"]
