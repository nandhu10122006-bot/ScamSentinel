# CyberSentry Threat Intelligence

CyberSentry is an evidence-first URL and QR-code risk assessment app. It analyzes URL structure and local indicators, optionally checks configured providers, records findings and provider availability, and generates finding-specific recommendations. It never fetches or opens a submitted destination. An unknown reputation is not classified as safe or malicious.

## Run locally

Python 3.12 is recommended.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 3000 --no-access-log
```

Open the local server at `http://localhost:3000`. Development/test defaults to `./data/cybersentry.db` (SQLite). Every other `APP_ENV` requires a PostgreSQL `DATABASE_URL`; missing or SQLite DSNs fail closed instead of silently storing production data on ephemeral container disk. For PostgreSQL, set `DATABASE_URL` to a DSN such as `postgresql+psycopg://user:password@host:5432/cybersentry`, then run `alembic upgrade head`. Keep secrets in the runtime environment; never commit `.env`.

To import the reserved-domain test fixture into a local development SQLite database only, run:

```bash
python -m app.cli import-sample
```

The fixture uses `.invalid`, is labeled `CyberSentry Test Fixture (LOCAL ONLY)`, and is refused when `APP_ENV` is not `development` or the database is not SQLite. It is not real threat intelligence. To synchronize an authorized configured feed, run `python -m app.cli sync-feeds`.

## API

- `POST /api/v1/scans` with JSON `{"url":"https://example.org/path"}`
- `GET /api/v1/scans?limit=25&offset=0`
- `GET /api/v1/scans/{scan_id}` and `/api/v1/scans/{scan_id}/report`
- `DELETE /api/v1/scans/{scan_id}`
- `POST /api/v1/qr/decode` as multipart form data with a `file` field
- `GET /api/v1/threats/lookup?url=https%3A%2F%2Fexample.org`
- `GET /api/v1/threat-feeds/status`
- `POST /api/v1/admin/threat-feeds/sync` (requires `X-CyberSentry-Admin-Token`)
- `GET /api/v1/recommendations` and `/api/v1/dashboard/stats`
- `GET /healthz`

`CYBERSENTRY_ACCESS_TOKEN` protects scan, history, report, lookup and dashboard APIs using `X-CyberSentry-Token` or `Authorization: Bearer ...`. It is optional only for local development and required in every other `APP_ENV`; the production container defaults to `APP_ENV=production` and fails closed without it. Configure a separate `CYBERSENTRY_ADMIN_TOKEN` to enable protected feed sync. The UI saves tokens in the browser's local storage. This is a single-install shared token, not per-user or multi-tenant identity; place a production deployment behind an appropriate identity/access gateway. The admin endpoint is unavailable when no admin token is configured.

CORS is disabled unless exact trusted origins are supplied in `TRUSTED_ORIGINS`. All API routes are limited to `RATE_LIMIT_API_REQUESTS_PER_MINUTE` (default 120 per minute per client/process); URL scans and QR decoding have tighter separate limits. These guards are in-process, so deployments with multiple workers/replicas should also enforce edge rate limits.

## Provider configuration

Provider credentials are optional and no real credentials were available to validate live integrations. Provider checks remain `not_configured` until the corresponding API key and authorized-use setting are configured. A configured URL may be disclosed to the provider. Review [provider-specific terms and setup](docs/THREAT_SOURCES.md) before enabling any integration. VirusTotal Public is non-commercial only and limited to 4 requests/minute and 500/day; it is disabled unless `VIRUSTOTAL_USAGE=noncommercial` is explicitly set. For a properly licensed premium account use `VIRUSTOTAL_USAGE=premium`. Google Safe Browsing is non-commercial only; commercial products should use Web Risk, which is not implemented here. URLhaus requires an Auth-Key for feed downloads; configure `URLHAUS_USAGE=noncommercial` or `commercial-authorized` only if your use is allowed. URLhaus sync is limited to no more than once per five minutes and feed scheduling is opt-in. PhishTank/OpenPhish stays disabled pending applicable current license/access review.

Set `AUTO_FEED_SYNC=true` and `FEED_SYNC_INTERVAL_HOURS` to enable the optional in-process scheduled maintenance loop. Default is off. Feed downloads never run as part of a scan. For multi-replica deployments, use one external scheduler/worker instead of enabling the loop in every replica.

## Risk and privacy

The score is a configurable rule-based index, not a probability. Defaults and finding descriptions are documented in [the scoring model](docs/SCORING.md). `RISK_WEIGHTS_JSON` may override only known finding-code weights with integer values from 0 to 100. The risk classification and confidence are stored separately from the score. Confidence is based on local/provider coverage and reliability.

CyberSentry stores the normalized hostname/domain and a SHA-256 fingerprint. It strips fragments and URL credentials from stored destinations and redacts values for sensitive query parameter names. Other URL components may still identify users; set `RETENTION_DAYS` to suit your policy. Old scans are purged by scheduled maintenance and the CLI; users can also delete a scan through the API. Original QR images and raw non-URL QR text are not persisted. The immediate QR response may show extracted content back to the uploader. Provider API calls may transmit the URL when enabled.

Direct destination fetching, redirect resolution, TLS certificate inspection and arbitrary URL browsing are not implemented. Therefore, CyberSentry does not claim a certificate error based on a scan. HTTPS is transport encryption, not proof of legitimacy.

## Tests and container

```bash
.venv/bin/pytest -q
.venv/bin/ruff check app tests alembic
```

The test suite uses isolated SQLite fixtures and mocked provider/feed responses. It does not depend on the public feed being stable. The Dockerfile runs as a non-root user, applies Alembic migrations at startup and listens on `PORT` (default 3000). Production persistence requires a durable PostgreSQL service/DSN and appropriate backup, access, rate-limit and secret-management controls.
