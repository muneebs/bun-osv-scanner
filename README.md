# bun-osv-scanner

[![npm version](https://badge.fury.io/js/%40bun-security-scanner%2Fosv-os.svg)](https://badge.fury.io/js/%40bun-security-scanner%2Fosv-os)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Powered by OSV](https://img.shields.io/badge/powered%20by-OSV-4285F4.svg)](https://osv.dev)

A [Bun security scanner](https://bun.sh/docs/install/security) that checks your dependencies against [Google's OSV database](https://osv.dev) before they get installed. No API keys. No external services to configure.

- 🔍 **Automatic scanning**: runs transparently on every `bun install`
- ⚡ **Fast**: 24-hour per-package cache means repeat installs skip the network entirely
- 📦 **No API keys**: OSV is a free, open vulnerability database
- 🔒 **Fail-open by default**: a downed API never blocks your install
- 🎯 **CVSS fallback**: uses score-based severity when a label isn't available
- 🛠️ **Configurable**: tune behaviour via environment variables

---

## 📦 Installation

```sh
bun add -d @bun-security-scanner/osv-os
```

Then register it in your project's `bunfig.toml`:

```toml
[install.security]
scanner = "@bun-security-scanner/osv-os"
```

That's it. The scanner runs automatically on the next `bun install`.

### Local development

To test a local build against your own project:

```sh
# In the scanner repo
bun link

# In your project
bun link @bun-security-scanner/osv-os
```

Then point `bunfig.toml` at the local entry point:

```toml
[install.security]
scanner = "./node_modules/@bun-security-scanner/osv-os"
```

---

## 🛡️ How it works

When `bun install` runs, Bun calls the scanner with the full list of packages to be installed. The scanner:

1. **Filters** non-resolvable versions — workspace, git, file, and path dependencies are skipped
2. **Checks the cache** — packages seen within the last 24 hours skip the network entirely
3. **Queries OSV** in batches of up to 1,000 packages per request via the [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/)
4. **Fetches vulnerability details** in parallel for any hits
5. **Returns advisories** to Bun, which surfaces them as warnings or fatal errors

---

## ⚠️ Advisory levels

| Level | Trigger | Bun behaviour |
|-------|---------|---------------|
| `fatal` | CRITICAL or HIGH severity; or CVSS score ≥ 7.0 | Installation halts |
| `warn` | MODERATE or LOW severity; or CVSS score < 7.0 | User is prompted; auto-cancelled in CI |

Severity is sourced from `database_specific.severity` on the OSV record. When that field is absent, the scanner falls back to the CVSS score. When neither is present, the advisory defaults to `warn`.

---

## ⚙️ Configuration

All options are set via environment variables. They can be placed in your shell profile or scoped to a project via `bunfig.toml`.

| Variable | Default | Description |
|----------|---------|-------------|
| `OSV_FAIL_CLOSED` | `false` | Throw on network error instead of failing open |
| `OSV_NO_CACHE` | `false` | Always query OSV fresh, bypassing the local cache |
| `OSV_TIMEOUT_MS` | `10000` | Per-request timeout in milliseconds |
| `OSV_API_BASE` | `https://api.osv.dev/v1` | OSV API base URL |

### Fail-open vs fail-closed

By default the scanner **fails open**: if OSV is unreachable the scan is skipped and installation proceeds normally. This prevents a downed API from blocking your team.

Set `OSV_FAIL_CLOSED=true` to invert this — any network failure cancels the install, ensuring packages are never installed without a successful scan. Recommended for security-sensitive projects.

```toml
# bunfig.toml — strict mode
[install.security]
scanner = "@bun-security-scanner/osv-os"

[install.env]
OSV_FAIL_CLOSED = "true"
OSV_TIMEOUT_MS = "5000"
```

---

## 🗄️ Cache

Results are cached per `package@version` at `~/.cache/bun-osv-scanner.json` with a 24-hour TTL. Because a published package version is immutable, its vulnerability profile is stable within that window.

To force a fresh scan, clear the cache:

```sh
rm ~/.cache/bun-osv-scanner.json
```

Or disable caching entirely for a single run:

```sh
OSV_NO_CACHE=true bun install
```

---

## 🛠️ Development

### Setup

```sh
git clone https://github.com/muneebs/bun-osv-scanner.git
cd bun-osv-scanner
bun install
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
bun-osv-scanner/
├── src/
│   ├── __tests__/     # Test suite (bun:test)
│   ├── cache.ts       # 24h filesystem cache
│   ├── client.ts      # OSV API client
│   ├── config.ts      # Constants and env vars
│   ├── display.ts     # TTY progress spinner
│   ├── index.ts       # Scanner entry point
│   └── severity.ts    # Level classification
├── bunfig.toml
└── package.json
```

---

## ⚠️ Limitations

- Only scans npm packages with concrete semver versions. `workspace:`, `file:`, `git:`, and range-only specifiers are skipped.
- Vulnerability data is sourced from OSV, which aggregates GitHub Advisory, NVD, and other feeds. Coverage may lag slightly behind a vulnerability's public disclosure.
- The OSV batch API has a hard limit of 1,000 queries per request. Projects with more than 1,000 resolvable dependencies are split across multiple requests automatically.

---

## 📄 License

MIT © [Muneeb Samuels](https://github.com/muneebs)

---

## 🔗 Links

- [📦 npm](https://www.npmjs.com/package/@bun-security-scanner/osv-os)
- [🐛 Issue tracker](https://github.com/muneebs/bun-osv-scanner/issues)
- [🔍 OSV database](https://osv.dev)
- [📖 Bun security scanner docs](https://bun.sh/docs/install/security)
