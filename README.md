# bun-osv-scanner

Checks packages against [Google's OSV database](https://osv.dev) during `bun install`. No API keys required.

## Setup

```toml
# bunfig.toml
[install]
securityScanner = "bun-osv-scanner"
```

Or to test locally before publishing:

```sh
cd bun-osv-scanner && bun link
cd your-project && bun link bun-osv-scanner
```

## How it works

When `bun install` runs, the scanner receives the full list of packages to be installed and:

1. Checks a local 24-hour cache — already-seen packages skip the network entirely
2. Queries the [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/) for any uncached packages (up to 1000 per request)
3. Fetches full vulnerability details in parallel for any hits
4. Returns advisories to Bun, which surfaces them to the user

If the OSV API is unreachable, the scan is skipped and installation proceeds — a downed API should never block a `bun install`.

## Advisory levels

| Level | Trigger | Bun behaviour |
|-------|---------|---------------|
| `fatal` | CRITICAL or HIGH severity (CVSS ≥ 7.0) | Installation halts immediately |
| `warn` | MODERATE or LOW severity | User is prompted; auto-cancelled in CI |

## Cache

Results are cached per `package@version` at `~/.cache/bun-osv-scanner.json` with a 24-hour TTL. Because a published package version is immutable, its vulnerability profile is stable within that window.

To clear the cache:

```sh
rm ~/.cache/bun-osv-scanner.json
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `OSV_FAIL_CLOSED` | `false` | Throw on network error instead of failing open |
| `OSV_NO_CACHE` | `false` | Disable the local cache, always query OSV fresh |
| `OSV_TIMEOUT_MS` | `10000` | Request timeout in milliseconds |
| `OSV_API_BASE` | `https://api.osv.dev/v1` | OSV API base URL |

By default the scanner **fails open** — if OSV is unreachable, the scan is skipped and installation proceeds normally. Set `OSV_FAIL_CLOSED=true` to invert this: any network failure cancels the install, ensuring packages are never installed without a successful scan.

```toml
# bunfig.toml — strict mode for security-sensitive projects
[install]
securityScanner = "bun-osv-scanner"

[install.env]
OSV_FAIL_CLOSED = "true"
OSV_TIMEOUT_MS = "5000"
```

## Limitations

- Only scans npm packages with concrete semver versions. Workspace, git, file, and local path dependencies are skipped.
- Vulnerability data is sourced from OSV, which aggregates GitHub Advisory, NVD, and other feeds. Coverage may lag behind a vulnerability's public disclosure.
