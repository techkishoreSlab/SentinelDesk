# syntax=docker/dockerfile:1
# Official 7-Zip build (Igor Pavlov), pinned by version and SHA-256 per architecture.
# Used only by the sandboxed package inspector to read DMG images without mounting them.
FROM python:3.12-slim-bookworm AS sevenzip
ARG TARGETARCH
ARG SEVENZIP_VERSION=24.09
ARG SEVENZIP_SHA256_AMD64=914c7e20ad5ef8e4d3cf08620ff8894b28fe11b7eb99809d6930870fbe48a281
ARG SEVENZIP_SHA256_ARM64=fbe331697c9417bbc06fc92d3f4576dca6a5a1442fad7ae810304446a9153e2c
RUN python - <<'EOF'
import hashlib, os, tarfile, urllib.request
arch = os.environ.get("TARGETARCH") or "amd64"
version = os.environ["SEVENZIP_VERSION"]
name = {"amd64": "x64", "arm64": "arm64"}[arch]
want = os.environ["SEVENZIP_SHA256_AMD64" if arch == "amd64" else "SEVENZIP_SHA256_ARM64"]
url = f"https://github.com/ip7z/7zip/releases/download/{version}/7z{version.replace('.', '')}-linux-{name}.tar.xz"
data = urllib.request.urlopen(url, timeout=120).read()
got = hashlib.sha256(data).hexdigest()
if got != want:
    raise SystemExit(f"7-Zip digest mismatch: {got} != {want}")
open("/tmp/7z.tar.xz", "wb").write(data)
with tarfile.open("/tmp/7z.tar.xz") as tar:
    member = tar.getmember("7zz")
    member.name = "7zz"
    tar.extract(member, "/out", filter="data")
os.chmod("/out/7zz", 0o755)
EOF

FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv
COPY --from=sevenzip /out/7zz /usr/local/bin/7zz

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./
RUN uv sync --frozen --no-dev

RUN useradd --system --uid 10001 --no-create-home sentinel
USER sentinel

ENV PATH="/opt/venv/bin:$PATH"
EXPOSE 8000
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
