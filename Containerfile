# syntax=docker/dockerfile:1

FROM python:3.14-slim-trixie AS builder

ENV UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    UV_COMPILE_BYTECODE=1

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /bin/

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
RUN uv sync --frozen --no-dev

FROM python:3.14-slim-trixie

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates curl gnupg \
    && curl --fail --silent --show-error --location \
        --output /tmp/microsoft.asc https://packages.microsoft.com/keys/microsoft-2025.asc \
    && gpg --batch --dearmor --output /usr/share/keyrings/microsoft-prod.gpg \
        /tmp/microsoft.asc \
    && rm /tmp/microsoft.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/13/prod trixie main" \
        > /etc/apt/sources.list.d/microsoft-prod.list \
    && apt-get update \
    && apt-get install --no-install-recommends --yes azure-cli \
    && apt-get purge --auto-remove --yes curl gnupg \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/.venv /opt/spyglass/venv

RUN groupadd --gid 65532 spyglass \
    && useradd --uid 65532 --gid spyglass --create-home --home-dir /home/spyglass \
        --shell /usr/sbin/nologin spyglass \
    && install --directory --owner=spyglass --group=spyglass /work

ENV HOME=/home/spyglass \
    PATH=/opt/spyglass/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /work
USER 65532:65532
ENTRYPOINT ["spyglass"]
CMD ["--help"]
