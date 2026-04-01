import { CACHE_FILE, FAIL_CLOSED, NO_CACHE } from './config';
import { readCache, writeCache, isFresh } from './cache';
import { isResolvable, batchQuery, fetchVuln } from './client';
import { severityLevel, advisoryUrl } from './severity';
import { startSpinner } from './display';
import type { OsvVulnerability } from './client';

export const scanner: Bun.Security.Scanner = {
  version: '1',

  async scan({ packages }) {
    const queryable = packages.filter((p) => p.name && isResolvable(p.version));
    if (queryable.length === 0) return [];

    const cache = NO_CACHE ? {} : await readCache(CACHE_FILE);

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
        ? `Scanning ${toQuery.length} packages via OSV (${hitCount} cached)...`
        : `Scanning ${queryable.length} packages via OSV...`
    );

    try {
      const batchResults = await batchQuery(toQuery);

      const affected: Array<{ pkg: Bun.Security.Package; vulnId: string }> = [];
      for (let i = 0; i < toQuery.length; i++) {
        for (const { id } of batchResults[i]?.vulns ?? []) {
          affected.push({ pkg: toQuery[i], vulnId: id });
        }
      }

      // Keyed by pkg@version so cache writes are always attributed to the right version.
      const freshByKey = new Map<string, Bun.Security.Advisory[]>();
      for (const pkg of toQuery) {
        freshByKey.set(`${pkg.name}@${pkg.version}`, []);
      }

      if (affected.length > 0) {
        const uniqueIds = [...new Set(affected.map((a) => a.vulnId))];
        const vulnById = new Map<string, OsvVulnerability>();

        spinner.update(
          `Fetching details for ${uniqueIds.length} ${uniqueIds.length === 1 ? 'vulnerability' : 'vulnerabilities'}...`
        );

        await Promise.all(
          uniqueIds.map(async (id) => {
            const vuln = await fetchVuln(id);
            if (vuln) vulnById.set(id, vuln);
          })
        );

        for (const { pkg, vulnId } of affected) {
          const vuln = vulnById.get(vulnId);
          if (vuln) {
            freshByKey.get(`${pkg.name}@${pkg.version}`)?.push({
              level: severityLevel(vuln),
              package: pkg.name,
              url: advisoryUrl(vuln),
              description: vuln.summary ?? vuln.id,
            });
          }
        }
      }

      spinner.stop();

      for (const [key, advisories] of freshByKey) {
        cache[key] = { advisories, cachedAt: Date.now() };
      }
      if (!NO_CACHE) void writeCache(cache, CACHE_FILE);

      return [...cachedAdvisories, ...[...freshByKey.values()].flat()];
    } catch (err) {
      spinner.stop();

      if (FAIL_CLOSED) {
        throw new Error(
          `OSV scan failed: ${err instanceof Error ? err.message : err}`
        );
      }

      process.stderr.write(
        `\nOSV scan failed (${err instanceof Error ? err.message : err}), skipping.\n`
      );
      return cachedAdvisories;
    }
  },
};
