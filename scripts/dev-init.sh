#!/usr/bin/env bash
# Create or upgrade a local .env with random development secrets and an Ed25519 job-signing
# keypair. Never overwrites existing secret values (an existing .env is backed up before any
# upgrade edit). Never prints secret values.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"
KEY_DIR="$ROOT/dev-keys"
LEGACY_REDIRECT="ENTRA_REDIRECT_URI=http://localhost:8000/api/v1/auth/callback"

pick_openssl() {
  for candidate in /usr/local/opt/openssl@3/bin/openssl /opt/homebrew/opt/openssl@3/bin/openssl openssl; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" genpkey -algorithm ed25519 -out /dev/null 2>/dev/null; then
      echo "$candidate"
      return
    fi
  done
  echo "ERROR: no OpenSSL with Ed25519 support found (brew install openssl@3)" >&2
  exit 1
}

# `head` closing the pipe makes `tr` exit with SIGPIPE, which pipefail would treat as failure.
rand() { (set +o pipefail; LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"); }

env_value() { awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE"; }

set_env() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp "$ROOT/.env.tmp.XXXXXX")"
  if grep -q "^${key}=" "$ENV_FILE"; then
    awk -F= -v k="$key" -v v="$value" 'BEGIN{OFS="="} $1 == k { print k, v; next } { print }' "$ENV_FILE" >"$tmp"
  else
    cat "$ENV_FILE" >"$tmp"
    printf '%s=%s\n' "$key" "$value" >>"$tmp"
  fi
  chmod 600 "$tmp"
  mv "$tmp" "$ENV_FILE"
}

umask 077

if [[ ! -f "$KEY_DIR/job_signing_private.pem" ]]; then
  OPENSSL="$(pick_openssl)"
  mkdir -p "$KEY_DIR"
  "$OPENSSL" genpkey -algorithm ed25519 -out "$KEY_DIR/job_signing_private.pem"
  "$OPENSSL" pkey -in "$KEY_DIR/job_signing_private.pem" -pubout -out "$KEY_DIR/job_signing_public.pem"
  # The backend container runs as an unprivileged user and must read the mounted key.
  chmod 644 "$KEY_DIR/job_signing_private.pem" "$KEY_DIR/job_signing_public.pem"
  chmod 700 "$KEY_DIR"
  echo "Generated Ed25519 job-signing keypair in dev-keys/ (git-ignored)."
else
  echo "dev-keys/ already exists; keeping existing keypair."
fi

if [[ ! -f "$ENV_FILE" ]]; then
  sed \
    -e "s|^SESSION_SECRET=.*|SESSION_SECRET=$(rand 64)|" \
    -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(rand 32)|" \
    -e "s|^APP_DB_PASSWORD=.*|APP_DB_PASSWORD=$(rand 32)|" \
    -e "s|^JOB_SIGNING_PRIVATE_KEY_PATH=.*|JOB_SIGNING_PRIVATE_KEY_PATH=${KEY_DIR}/job_signing_private.pem|" \
    -e "s|^JOB_SIGNING_PUBLIC_KEY_PATH=.*|JOB_SIGNING_PUBLIC_KEY_PATH=${KEY_DIR}/job_signing_public.pem|" \
    "$ROOT/.env.example" >"$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "Created .env with random development secrets (mode 600)."
else
  echo ".env exists; checking for settings added since it was created."
fi

# Upgrade path: add settings introduced after the .env was first generated.
needs_upgrade=0
[[ -n "$(env_value APP_DB_PASSWORD)" ]] || needs_upgrade=1
[[ -n "$(env_value MIGRATION_DATABASE_URL)" ]] || needs_upgrade=1
grep -qx "$LEGACY_REDIRECT" "$ENV_FILE" && needs_upgrade=1

if [[ "$needs_upgrade" == 1 ]]; then
  backup="$ROOT/.env.backup-$(date +%Y%m%d%H%M%S)"
  cp -p "$ENV_FILE" "$backup"
  echo "Backed up existing .env to $(basename "$backup") (git-ignored)."
  [[ -n "$(env_value APP_DB_PASSWORD)" ]] || set_env APP_DB_PASSWORD "$(rand 32)"
  pg_user="$(env_value POSTGRES_USER)"
  pg_pass="$(env_value POSTGRES_PASSWORD)"
  pg_db="$(env_value POSTGRES_DB)"
  app_pass="$(env_value APP_DB_PASSWORD)"
  set_env MIGRATION_DATABASE_URL "postgresql+asyncpg://${pg_user}:${pg_pass}@localhost:5432/${pg_db}"
  set_env DATABASE_URL "postgresql+asyncpg://sentinel_app:${app_pass}@localhost:5432/${pg_db}"
  grep -qx "$LEGACY_REDIRECT" "$ENV_FILE" && set_env ENTRA_REDIRECT_URI ""
  echo "Upgraded .env: runtime role credentials and migration URL added."
fi
echo "Done. Fill optional integrations later; never commit .env."
