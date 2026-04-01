import { isFresh, readCache, writeCache } from './cache';
import { isResolvable } from './client';
import { startSpinner } from './display';

export interface Backend {
  readonly name: string;
  readonly cacheFile: string;
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

      const cache = backend.noCache ? {} : await readCache(backend.cacheFile);

      const cachedAdvisories: Bun.Security.Advisory[] = [];
      const toQuery: Bun.Security.Package[] = [];

      for (const pkg of queryable) {
        const entry = cache[`${pkg.name}@${pkg.version}`];
        if (entry && isFresh(entry)) {
          cachedAdvisories.push(...entry.advisories);
        } else {
          toQuery.push(pkg);
        }
      }

      if (toQuery.length === 0) return cachedAdvisories;

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

        return [...cachedAdvisories, ...[...advisoryMap.values()].flat()];
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
        return cachedAdvisories;
      }
    },
  };
}
