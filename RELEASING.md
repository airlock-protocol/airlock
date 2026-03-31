# Releasing Airlock (PyPI + npm)

Use this when you are ready to go **public**. Nothing here runs automatically until secrets and registry ownership are configured.

## Release checklist (before tagging)

1. **CI green** on `main` (Python matrix + **Docker build** + npm `build:js`).
2. **Public production gate** (if shipping an internet-facing gateway): confirm **[docs/deploy/internal.md](docs/deploy/internal.md)** checklist — `AIRLOCK_ENV=production`, seed, `AIRLOCK_SERVICE_TOKEN`, `AIRLOCK_SESSION_VIEW_SECRET`, explicit CORS + issuer allowlist, Redis when `AIRLOCK_EXPECT_REPLICAS` > 1, single-writer LanceDB story documented for operators.
3. **Bump versions** in lockstep where needed:
   - `pyproject.toml` → `version`
   - `sdks/typescript/package.json` → `version`
   - `integrations/airlock-mcp/package.json` → `version` (and dependency range on `airlock-client` if you bump major)
4. **Changelog / release notes** (GitHub Release body): breaking changes, new env vars (`AIRLOCK_ENV`, `AIRLOCK_SERVICE_TOKEN`, `AIRLOCK_SESSION_VIEW_SECRET`, `AIRLOCK_PUBLIC_BASE_URL`, `AIRLOCK_REDIS_URL`, `AIRLOCK_ADMIN_TOKEN`, signed `/feedback` and `/heartbeat`).
5. **PyPI**: trusted publisher linked (see below); optional GitHub Environment `pypi` for approval.
6. **npm**: repository secret **`NPM_TOKEN`** (Automation publish).
7. Create GitHub **Release** with tag `vX.Y.Z` (or run workflows manually via `workflow_dispatch`).

### Container image (GHCR)

Workflow **`publish-ghcr.yml`** runs on **published Releases** (tags the image as `vX.Y.Z` and `latest`) and supports **`workflow_dispatch`** for ad-hoc tags. Images: `ghcr.io/shivdeep1/airlock-protocol:<tag>` (owner/repo are lowercased from GitHub).

- One-time: repo **Settings → Actions → General → Workflow permissions** must allow **read and write** for packages (or use a PAT with `write:packages` if you restrict `GITHUB_TOKEN`).
- **Packages** visibility: repo **Packages** sidebar → package settings → make **Internal** or **Public** as appropriate.
- Pull: `docker pull ghcr.io/shivdeep1/airlock-protocol:v0.1.0`

**Internal deploy** (private gateway image) is separate from npm/PyPI: see **[docs/deploy/internal.md](docs/deploy/internal.md)** — `docker compose` + `.env.example`.

**Dependabot** (`.github/dependabot.yml`) opens weekly PRs for GitHub Actions, pip, and npm — review and merge before releases when practical.

## Python — `airlock-protocol` on PyPI

1. **Create** the project on [pypi.org](https://pypi.org) (or claim the name if unused).
2. **Trusted publishing** (recommended, no long-lived PyPI password in GitHub):
   - PyPI → your project → **Manage** → **Publishing** → add a trusted publisher.
   - Provider: **GitHub**, repository (owner/name), workflow: `publish-pypi.yml`, environment: leave unspecified unless you add one later.
3. **GitHub** (optional hardening): add an Environment named `pypi` with required reviewers; then set `environment: pypi` on the publish job in `.github/workflows/publish-pypi.yml`.
4. **Ship**: create a [GitHub Release](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases) (tag e.g. `v0.1.0`) or run workflow **Publish PyPI** manually (`workflow_dispatch`).

Local check: `pip install hatch && hatch build` → artifacts under `dist/`.

## JavaScript — `airlock-client` + `airlock-mcp` on npm

1. **Names**: [`airlock-client`](https://www.npmjs.com/package/airlock-client) and [`airlock-mcp`](https://www.npmjs.com/package/airlock-mcp) must be available under your npm account (or org).
2. **Token**: npm → **Access Tokens** → create an **Automation** (classic) token with **Publish**.
3. **GitHub**: **Settings → Secrets and variables → Actions** → create repository secret **`NPM_TOKEN`** with that token.
4. **Ship**: run workflow **Publish npm** (or trigger via release; same workflow). Publishes workspace order: `airlock-client`, then `airlock-mcp`.

Dry run locally:

```bash
npm ci
npm run build:js
npm publish -w airlock-client --access public --dry-run
npm publish -w airlock-mcp --access public --dry-run
```

## Version bumps

- **Python**: edit `version` in `pyproject.toml`, tag the release, then publish.
- **npm**: bump `version` in `sdks/typescript/package.json` and `integrations/airlock-mcp/package.json` (keep compatible semver for the `^0.1.0` dependency range, or bump both and widen the range in `airlock-mcp` if needed).

## Marketing alias (`airlock-sdk`)

To reserve an alternate name later without duplicating code: publish a tiny package that **re-exports** `airlock-client` or depends on it and documents the preferred import path.
