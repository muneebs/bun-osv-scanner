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
 * expires   = "2025-12-31"   # optional ISO date
 *
 * [[ignore]]
 * package   = "minimist"
 * advisories = ["*"]          # wildcard — suppresses all advisories for this package
 * reason    = "Transitive only, no direct usage, no fix available."
 * ```
 *
 * Behaviour:
 * - `fatal` advisories matched by an active ignore entry are downgraded to `warn`.
 * - `warn` advisories matched by an active ignore entry are dropped entirely.
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

/** Remove text after the first # that is not inside a quoted string. */
function stripInlineComment(val: string): string {
  let inStr = false;
  let q = '';
  for (let i = 0; i < val.length; i++) {
    const c = val[i];
    if (inStr) {
      if (c === q) inStr = false;
    } else if (c === '"' || c === "'") {
      inStr = true;
      q = c;
    } else if (c === '#') {
      return val.slice(0, i).trimEnd();
    }
  }
  return val;
}

/**
 * Minimal TOML parser for the [[ignore]] array-of-tables format.
 * Only handles the subset of TOML used by `.bun-security-ignore`.
 */
function parseIgnoreToml(source: string): IgnoreEntry[] {
  const entries: IgnoreEntry[] = [];
  let current: Partial<IgnoreEntry> | null = null;

  const pushCurrent = () => {
    if (current?.package) {
      entries.push({
        ...current,
        advisories: current.advisories ?? [],
      } as IgnoreEntry);
    }
  };

  for (const rawLine of source.split('\n')) {
    const line = rawLine.trim();

    if (line === '' || line.startsWith('#')) continue;

    if (line === '[[ignore]]') {
      pushCurrent();
      current = {};
      continue;
    }

    if (!current) continue;

    const eqIdx = line.indexOf('=');
    if (eqIdx === -1) continue;

    const key = line.slice(0, eqIdx).trim();
    const rawVal = stripInlineComment(line.slice(eqIdx + 1).trim());

    if (key === 'package' || key === 'reason' || key === 'expires') {
      // Unquoted or single/double-quoted string
      const str = rawVal.replace(/^["']|["']$/g, '');
      (current as Record<string, string>)[key] = str;
    } else if (key === 'advisories') {
      // Inline array: ["GHSA-xxx", "CVE-yyy"] or ["*"]
      const inner = rawVal.replace(/^\[|\]$/g, '');
      current.advisories = inner
        .split(',')
        .map((s) => s.trim().replace(/^["']|["']$/g, ''))
        .filter(Boolean);
    }
  }

  pushCurrent();

  return entries;
}

// ── Loader ────────────────────────────────────────────────────────────────────

export async function loadIgnoreList(): Promise<IgnoreList> {
  if (NO_IGNORE) return { entries: [] };

  try {
    const text = await Bun.file(IGNORE_FILE).text();
    const entries = parseIgnoreToml(text);

    for (const entry of entries) {
      if (!entry.reason) {
        process.stderr.write(
          `[@nebzdev/bun-security-scanner] Warning: ignore entry for "${entry.package}" has no reason — consider documenting why.\n`
        );
      }
    }

    return { entries };
  } catch {
    // File doesn't exist or can't be read — that's fine
    return { entries: [] };
  }
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
