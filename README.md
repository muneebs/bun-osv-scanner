# bun-security-scanner

[![npm version](https://badge.fury.io/js/%40nebzdev%2Fbun-security-scanner.svg)](https://badge.fury.io/js/%40nebzdev%2Fbun-security-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Powered by OSV](https://img.shields.io/badge/powered%20by-OSV-4285F4.svg)](https://osv.dev)
[![Powered by Snyk](https://img.shields.io/badge/powered%20by-Snyk-4C4A73.svg)](https://snyk.io)
![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/muneebs/bun-security-scanner?utm_source=oss&utm_medium=github&utm_campaign=muneebs%2Fbun-security-scanner&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)

A [Bun security scanner](https://bun.com/docs/pm/security-scanner-api) that checks your dependencies against vulnerability databases before they get installed. Uses [Google's OSV database](https://osv.dev) by default — no API keys required.

- 🔍 **Automatic scanning**: runs transparently on every `bun install`
- ⚡ **Fast**: per-package lockfile cache (24h by default, configurable) means repeat installs skip the network entirely
- 🔀 **Two backends**: OSV (free, no setup) or Snyk (commercial, broader coverage)
- 🔒 **Fail-open by default**: a downed API never blocks your install
- 🎯 **CVSS fallback**: falls back to score-based severity when a label isn't available
- 🙈 **Ignore file**: suppress false positives and accepted risks with `.bun-security-ignore`
- ⚙️ **Configurable**: tune behaviour via environment variables

---

## 📦 Installation

```sh
bun add -d @nebzdev/bun-security-scanner
```

Then register it in your project's `bunfig.toml`:

```toml
[install.security]
scanner = "@nebzdev/bun-security-scanner"
```

That's it. The scanner runs automatically on the next `bun install`.

---

## 🔀 Backends

The scanner ships with two backends, controlled by the `SCANNER_BACKEND` environment variable.

### OSV (default)

Queries [Google's OSV database](https://osv.dev) — free, no credentials required.

```toml
[install.security]
scanner = "@nebzdev/bun-security-scanner"
```

### Snyk

Queries [Snyk's vulnerability database](https://security.snyk.io) — commercial, often surfaces issues earlier. Requires a Snyk account.

```toml
# bunfig.toml
[install.security]
scanner = "@nebzdev/bun-security-scanner"
```

```sh
# .env
SCANNER_BACKEND=snyk
SNYK_TOKEN=your-token
SNYK_ORG_ID=your-org-id
```

---

## 🛡️ How it works

When `bun install` runs, Bun calls the scanner with the full list of packages to be installed. The scanner:

1. Filters non-resolvable versions — workspace, git, file, and path dependencies are skipped
2. Checks the cache — packages seen within the cache TTL (24h by default) skip the network entirely
3. Queries the backend for any uncached packages
4. Returns advisories to Bun, which surfaces them as warnings or fatal errors

---

## ⚠️ Advisory levels

| Level | Trigger | Bun behaviour |
|-------|---------|---------------|
| `fatal` | CRITICAL or HIGH severity; or CVSS score >= 7.0 | Installation halts |
| `warn` | MODERATE or LOW severity; or CVSS score < 7.0 | User is prompted; auto-cancelled in CI |

---

## ⚙️ Configuration

All options are set via environment variables — in your shell, or in a `.env` file at the project root (Bun loads it automatically).

### Shared

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_BACKEND` | `osv` | Backend to use: `osv` or `snyk` |

### OSV backend

| Variable | Default | Description |
|----------|---------|-------------|
| `OSV_FAIL_CLOSED` | `false` | Throw on network error instead of failing open |
| `OSV_NO_CACHE` | `false` | Always query OSV fresh, bypassing the local cache |
| `OSV_CACHE_FILE` | `.osv.lock` | Path to the cache file |
| `OSV_CACHE_TTL_MS` | `86400000` | Cache TTL in milliseconds (default: 24 hours) |
| `OSV_TIMEOUT_MS` | `10000` | Per-request timeout in milliseconds |
| `OSV_API_BASE` | `https://api.osv.dev/v1` | OSV API base URL |
| `OSV_NO_IGNORE` | `false` | Disable `.bun-security-ignore` processing |

### Snyk backend

| Variable | Default | Description |
|----------|---------|-------------|
| `SNYK_TOKEN` | — | **Required.** Snyk API token |
| `SNYK_ORG_ID` | — | **Required.** Snyk organization ID |
| `SNYK_FAIL_CLOSED` | `false` | Throw on network error instead of failing open |
| `SNYK_NO_CACHE` | `false` | Always query Snyk fresh, bypassing the local cache |
| `SNYK_CACHE_FILE` | `.snyk.lock` | Path to the cache file |
| `SNYK_CACHE_TTL_MS` | `86400000` | Cache TTL in milliseconds (default: 24 hours) |
| `SNYK_TIMEOUT_MS` | `10000` | Per-request timeout in milliseconds |
| `SNYK_RATE_LIMIT` | `160` | Max requests per minute (hard cap: 180) |
| `SNYK_CONCURRENCY` | `10` | Max concurrent connections |
| `SNYK_API_BASE` | `https://api.snyk.io/rest` | Regional endpoint override |
| `SNYK_API_VERSION` | `2024-04-29` | Snyk REST API version date |

### Fail-open vs fail-closed

By default the scanner fails open: if the backend is unreachable the scan is skipped and installation proceeds normally. Set `OSV_FAIL_CLOSED=true` or `SNYK_FAIL_CLOSED=true` to invert this.

```sh
# .env -- strict mode
OSV_FAIL_CLOSED=true
```

---

## 🗄️ Cache

Results are cached per `package@version` in a lock file at the project root. Because a published package version is immutable, its vulnerability profile is stable within the cache window.

| Backend | Lock file | TTL env var |
|---------|-----------|-------------|
| OSV | `.osv.lock` | `OSV_CACHE_TTL_MS` |
| Snyk | `.snyk.lock` | `SNYK_CACHE_TTL_MS` |

The default TTL is 24 hours. In CI environments where cold-start scan time is a concern, increase it:

```sh
# .env.ci
OSV_CACHE_TTL_MS=604800000   # 7 days
SNYK_CACHE_TTL_MS=604800000  # 7 days
```

The lock files are designed to be committed to git. Like a lockfile, committing them means your team and CI share the cache from day one without waiting for a warm-up scan.

```sh
git add .osv.lock   # or .snyk.lock
```

To force a fresh scan:

```sh
OSV_NO_CACHE=true bun install
# or
SNYK_NO_CACHE=true bun install
```

---

## 🙈 Ignore file

Not every advisory is actionable. A vulnerability may affect a code path your project doesn't use, have no fix available yet, or be a false positive. The `.bun-security-ignore` file lets you acknowledge these cases without blocking installs permanently.

### Format

```toml
# .bun-security-ignore

[[ignore]]
package    = "lodash"
advisories = ["GHSA-35jh-r3h4-6jhm"]
reason     = "Only affects the cloneDeep path, which we do not use."
expires    = "2026-12-31"   # optional -- re-surfaces automatically after this date

[[ignore]]
package    = "minimist"
advisories = ["*"]           # wildcard -- suppress all advisories for this package
reason     = "Transitive only, no direct usage, no fix available."
```

### Behaviour

| Advisory level | Session type | Effect |
|----------------|--------------|--------|
| `fatal` matched | Interactive (no `CI=true`, stdin is a TTY) | Downgraded to `warn` — visible in output but no longer blocks the install |
| `fatal` matched | CI / non-interactive | Suppressed entirely — logged to stderr but not returned |
| `warn` matched | Any | Suppressed entirely — logged to stderr but not returned |

All suppressions are logged to stderr so they remain visible in CI output. Ignored advisories are never silently swallowed.

- `expires` -- entries re-activate at UTC midnight on the given date, so you're reminded when to reassess
- `advisories = ["*"]` -- wildcard suppresses all advisories for the package
- `reason` -- encouraged but not required; a notice is printed to stderr if omitted
- `OSV_NO_IGNORE=true` -- disables all ignore file processing for strict environments
- `BUN_SECURITY_IGNORE_FILE` -- override the default `.bun-security-ignore` path

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BUN_SECURITY_IGNORE_FILE` | `.bun-security-ignore` | Path to the ignore file |
| `OSV_NO_IGNORE` | `false` | Disable all ignore file processing |

### Committing the file

The ignore file should be committed alongside your lockfile. It documents deliberate risk-acceptance decisions for your whole team and CI.

---

## 🛠️ Development

### Setup

```sh
git clone https://github.com/muneebs/bun-security-scanner.git
cd bun-security-scanner
bun install
bunx lefthook install
```

### Local development

Point `bunfig.toml` directly at the entry file using an absolute or relative path:

```toml
[install.security]
scanner = "../bun-security-scanner/src/index.ts"
```

### Commands

```sh
bun test              # Run all tests
bun run lint          # Lint source files
bun run format        # Check formatting
bun run format:write  # Auto-fix formatting
bun run check         # Lint + format check together
bun run check:write   # Lint + format, auto-fix what it can
```

### Project structure

```
bun-security-scanner/
├── src/
│   ├── __tests__/     # Test suite (bun:test)
│   ├── snyk/          # Snyk backend
│   ├── cache.ts       # Lockfile cache (configurable TTL)
│   ├── client.ts      # OSV API client
│   ├── config.ts      # OSV constants and env vars
│   ├── display.ts     # TTY progress spinner
│   ├── ignore.ts      # .bun-security-ignore loader and matcher
│   ├── index.ts       # Entry point -- dispatches to OSV or Snyk
│   ├── osv.ts         # OSV scanner implementation
│   ├── scanner.ts     # Shared scanner factory (cache + ignore orchestration)
│   └── severity.ts    # OSV level classification
├── dist/              # Compiled output (published to npm)
├── bunfig.toml
└── package.json
```

### Backend comparison

| | OSV | Snyk |
|---|---|---|
| API key required | No | Yes |
| Batch endpoint | Yes (1000/req) | No (per-package, 180 req/min) |
| Coverage | Community feeds + GitHub Advisory | Snyk's proprietary database |
| Cache file | `.osv.lock` | `.snyk.lock` |

---

## ⚠️ Limitations

- Only scans npm packages with concrete semver versions. `workspace:`, `file:`, `git:`, and range-only specifiers are skipped.
- OSV aggregates GitHub Advisory, NVD, and other feeds, so coverage may lag slightly behind a vulnerability's public disclosure.
- The OSV batch API has a hard limit of 1,000 queries per request. Larger projects are split across multiple requests automatically.
- Snyk's per-package endpoint is rate-limited to 180 req/min. At that rate, a project with 2,000+ packages will take several minutes on the first scan.

---

## 📄 License

MIT © [Muneeb Samuels](https://github.com/muneebs)

---

## 🔗 Links

- [📦 npm](https://www.npmjs.com/package/@nebzdev/bun-security-scanner)
- [🐛 Issue tracker](https://github.com/muneebs/bun-security-scanner/issues)
- [🔍 OSV database](https://osv.dev)
- [📖 Bun security scanner docs](https://bun.com/docs/pm/security-scanner-api)