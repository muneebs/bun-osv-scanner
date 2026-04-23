import { isFresh, readCache, writeCache } from './cache';
import { isResolvable } from './client';
import { startSpinner } from './display';
import { applyIgnoreList, type IgnoreList, loadIgnoreList } from './ignore';

export interface Backend {
  readonly name: string;
  readonly cacheFile: string;
  readonly ttl: number;
  readonly noCache: boolean;
  readonly failClosed: boolean;
  validateConfig?(): void;
  fetchAdvisories(
    packages: Bun.Security.Package[],
    onStatus: (message: string) => void
  ): Promise<Map<string, Bun.Security.Advisory[]>>;
}

export function createScanner(backend: Backend): Bun.Security.Scanner {
  return {
    version: '1',

    async scan({ packages }) {
      backend.validateConfig?.();

      const queryable = packages.filter(
        (p) => p.name && isResolvable(p.version)
      );
      if (queryable.length === 0) return [];

      const [cache, ignoreList] = await Promise.all([
        backend.noCache
          ? Promise.resolve({} as Awaited<ReturnType<typeof readCache>>)
          : readCache(backend.cacheFile),
        loadIgnoreList(),
      ]);

      const cachedAdvisories: Bun.Security.Advisory[] = [];
      const toQuery: Bun.Security.Package[] = [];

      for (const pkg of queryable) {
        const entry = cache[`${pkg.name}@${pkg.version}`];
        if (entry && isFresh(entry, backend.ttl)) {
          cachedAdvisories.push(...entry.advisories);
        } else {
          toQuery.push(pkg);
        }
      }

      if (toQuery.length === 0)
        return stripNonBlockingInCI(applyIgnores(cachedAdvisories, ignoreList));

      const hitCount = queryable.length - toQuery.length;
      const spinner = startSpinner(
        hitCount > 0
          ? `Scanning ${toQuery.length} packages via ${backend.name} (${hitCount} cached)...`
          : `Scanning ${queryable.length} packages via ${backend.name}...`
      );

      try {
        const advisoryMap = await backend.fetchAdvisories(toQuery, (msg) =>
          spinner.update(msg)
        );

        spinner.stop();

        for (const [key, advisories] of advisoryMap) {
          cache[key] = { advisories, cachedAt: Date.now() };
        }
        if (!backend.noCache) void writeCache(cache, backend.cacheFile);

        return stripNonBlockingInCI(
          applyIgnores(
            [...cachedAdvisories, ...[...advisoryMap.values()].flat()],
            ignoreList
          )
        );
      } catch (err) {
        spinner.stop();

        if (backend.failClosed) {
          throw new Error(
            `${backend.name} scan failed: ${err instanceof Error ? err.message : err}`
          );
        }

        process.stderr.write(
          `\n${backend.name} scan failed (${err instanceof Error ? err.message : err}), skipping.\n`
        );
        return stripNonBlockingInCI(applyIgnores(cachedAdvisories, ignoreList));
      }
    },
  };
}

/**
 * In CI / non-interactive sessions, Bun still prompts ("Continue anyway? [y/N]")
 * for `warn`-level advisories — which hangs or fails the install. Drop them from
 * the returned set (logging to stderr) so only `fatal` advisories block.
 * Interactive sessions keep `warn` so the user can see and decide.
 */
function stripNonBlockingInCI(
  advisories: Bun.Security.Advisory[]
): Bun.Security.Advisory[] {
  const interactive =
    process.env.CI !== 'true' && (process.stdin?.isTTY ?? false);
  if (interactive) return advisories;

  return advisories.filter((advisory) => {
    if (advisory.level === 'warn') {
      process.stderr.write(
        `[@nebzdev/bun-security-scanner] WARN ${advisory.package}: ${advisory.description ?? ''} (${advisory.url})\n`
      );
      return false;
    }
    return true;
  });
}

/**
 * Apply the ignore list to a set of advisories:
 * - `fatal` advisories that are ignored are downgraded to `warn` in
 *   interactive sessions so the user can make a final call.
 * - In non-interactive / CI environments (process.env.CI or no stdin TTY),
 *   ignored `fatal` advisories are dropped entirely — downgrading to `warn`
 *   would still auto-cancel the install in CI, defeating the ignore file.
 * - `warn` advisories that are ignored are always dropped.
 * - All suppressions are logged to stderr for visibility regardless of mode.
 */
function applyIgnores(
  advisories: Bun.Security.Advisory[],
  ignoreList: IgnoreList
): Bun.Security.Advisory[] {
  if (ignoreList.entries.length === 0) return advisories;

  const interactive =
    process.env.CI !== 'true' && (process.stdin?.isTTY ?? false);

  const result: Bun.Security.Advisory[] = [];

  for (const advisory of advisories) {
    const decision = applyIgnoreList(advisory, ignoreList);

    if (decision.action === 'keep') {
      result.push(advisory);
    } else if (decision.action === 'downgrade' && interactive) {
      process.stderr.write(
        `[@nebzdev/bun-security-scanner] Downgrading ${advisory.package} fatal advisory to warn (${advisory.url}) — ${decision.reason}\n`
      );
      result.push({ ...advisory, level: 'warn' });
    } else {
      // drop: warn advisories always, fatal advisories in CI/non-interactive
      process.stderr.write(
        `[@nebzdev/bun-security-scanner] Suppressing ${advisory.package} advisory (${advisory.url}) — ${decision.reason}\n`
      );
    }
  }

  return result;
}
