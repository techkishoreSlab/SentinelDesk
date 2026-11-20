# SentinelDesk

Policy-governed, AI-assisted enterprise software provisioning. Source of truth:
[`MASTER_PRODUCT_SPEC.md`](MASTER_PRODUCT_SPEC.md).

| Path | Component |
|---|---|
| `backend/` | FastAPI control plane (Python 3.12, SQLAlchemy 2, Alembic) |
| `web/` | React + TypeScript web app (Vite) |
| `endpoint/` | Rust endpoint workspace (`sentinel-protocol`, `sentinel-agent`) |
| `compose.yaml` | PostgreSQL 17, migrations, backend |
| `docs/` | Plan, progress scorecard, test report, known issues, environment setup |

Quick start: see [`docs/ENVIRONMENT_SETUP.md`](docs/ENVIRONMENT_SETUP.md).

```bash
make init && make up && make check
```

Current status: see [`docs/PROJECT_PROGRESS.md`](docs/PROJECT_PROGRESS.md).
