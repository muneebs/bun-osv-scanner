/**
 * `.bun-security-ignore` loader and matcher.
 *
 * File format (TOML):
 *
 * ```toml
 * [[ignore]]
 * package   = "lodash"
 * advisories = ["GHSA-35jh-r3h4-6jhm"]
 * reason    = "Only affects cloneDeep, which we do not use."
 * expires   = "2026-12-31"   # optional ISO date
 *
 * [[ignore]]
 * package   = "minimist"
 * advisories = ["*"]          # wildcard — suppresses all advisories for this package
 * reason    = "Transitive only, no direct usage, no fix available."
 * ```
 *
 * Behaviour:
 * - `fatal` advisories matched by an active ignore entry are handled by mode:
 *   - Interactive (no `CI=true` env var, stdin is a TTY): downgraded to `warn`.
 *   - CI / non-interactive: suppressed entirely (logged to stderr, not returned).
 * - `warn` advisories matched by an active ignore entry are dropped entirely.
 * - All suppressions are logged to stderr regardless of mode.
 * - Entries with an `expires` date re-activate after that date (UTC midnight).
 * - A missing `reason` is accepted but a notice is printed to stderr.
 * - `OSV_NO_IGNORE=true` disables all ignore file processing.
 */

export interface IgnoreEntry {
  package: string;
  advisories: string[]; // advisory IDs or ["*"] wildcard
  reason?: string;
  expires?: string; // ISO date string "YYYY-MM-DD"
}

export interface IgnoreList {
  entries: IgnoreEntry[];
}

const IGNORE_FILE = Bun.env.BUN_SECURITY_IGNORE_FILE ?? '.bun-security-ignore';
export const NO_IGNORE = Bun.env.OSV_NO_IGNORE === 'true';

// ── Parser ────────────────────────────────────────────────────────────────────

/**
 * Parse `.bun-security-ignore` using Bun's built-in TOML parser.
 * Handles the full TOML spec (inline comments, multiline strings, dates, etc.).
 */
function parseIgnoreToml(source: string): IgnoreEntry[] {
  const parsed = Bun.TOML.parse(source) as Record<string, unknown>;
  const raw = parsed.ignore;
  if (!Array.isArray(raw)) return [];

  const entries: IgnoreEntry[] = [];

  for (const item of raw) {
    if (typeof item !== 'object' || item === null) continue;
    const row = item as Record<string, unknown>;

    if (typeof row.package !== 'string' || !row.package) continue;

    const advisories = Array.isArray(row.advisories)
      ? (row.advisories as unknown[]).filter(
          (a): a is string => typeof a === 'string'
        )
      : [];

    const entry: IgnoreEntry = { package: row.package, advisories };

    if (typeof row.reason === 'string') entry.reason = row.reason;

    // `expires` may be a quoted string or a bare TOML local date (parsed as Date).
    if (typeof row.expires === 'string') {
      entry.expires = row.expires;
    } else if (row.expires instanceof Date) {
      entry.expires = row.expires.toISOString().slice(0, 10);
    }

    entries.push(entry);
  }

  return entries;
}

// ── Loader ────────────────────────────────────────────────────────────────────

export async function loadIgnoreList(): Promise<IgnoreList> {
  if (NO_IGNORE) return { entries: [] };

  let text: string;
  try {
    text = await Bun.file(IGNORE_FILE).text();
  } catch {
    // File doesn't exist — that's fine
    return { entries: [] };
  }

  let entries: IgnoreEntry[];
  try {
    entries = parseIgnoreToml(text);
  } catch (err) {
    process.stderr.write(
      `[@nebzdev/bun-security-scanner] Warning: failed to parse "${IGNORE_FILE}" — ${err instanceof Error ? err.message : err}. All ignore entries will be skipped.\n`
    );
    return { entries: [] };
  }

  for (const entry of entries) {
    if (!entry.reason) {
      process.stderr.write(
        `[@nebzdev/bun-security-scanner] Warning: ignore entry for "${entry.package}" has no reason — consider documenting why.\n`
      );
    }
  }

  return { entries };
}

// ── Matcher ───────────────────────────────────────────────────────────────────

/**
 * Returns true if an ignore entry is still active (not yet expired).
 */
function isActive(entry: IgnoreEntry): boolean {
  if (!entry.expires) return true;
  const expiryDate = new Date(`${entry.expires}T00:00:00Z`);
  return Date.now() < expiryDate.getTime();
}

/**
 * Extract a normalised advisory ID from a URL.
 * Handles NVD (CVE-...) and GitHub Advisory (GHSA-...) URL patterns.
 */
function extractId(url: string | null | undefined): string {
  return url?.split('/').pop()?.toUpperCase() ?? '';
}

export type ApplyResult =
  | { action: 'keep' }
  | { action: 'downgrade'; reason: string }
  | { action: 'drop'; reason: string };

/**
 * Determine what to do with an advisory given the loaded ignore list.
 *
 * - `keep`      — advisory is not ignored; return it as-is
 * - `downgrade` — `fatal` advisory matched; return it as `warn`
 * - `drop`      — `warn` advisory matched; suppress it entirely
 */
export function applyIgnoreList(
  advisory: Bun.Security.Advisory,
  ignoreList: IgnoreList
): ApplyResult {
  const advId = extractId(advisory.url);

  for (const entry of ignoreList.entries) {
    if (entry.package !== advisory.package) continue;
    if (!isActive(entry)) continue;

    const wildcard = entry.advisories.includes('*');
    const matched =
      wildcard || entry.advisories.map((a) => a.toUpperCase()).includes(advId);

    if (!matched) continue;

    const reason = entry.reason ?? '(no reason provided)';

    if (advisory.level === 'fatal') {
      return { action: 'downgrade', reason };
    }
    return { action: 'drop', reason };
  }

  return { action: 'keep' };
}
