import { FAIL_CLOSED, NO_CACHE } from './config';
import { validateConfig, batchFetchIssues } from './client';
import { severityLevel, advisoryUrl } from './severity';
import { readCache, writeCache, isFresh } from '../cache';
import { isResolvable } from '../client';
import { startSpinner } from '../display';

export const scanner: Bun.Security.Scanner = {
  version: '1',

  async scan({ packages }) {
    validateConfig();

    const queryable = packages.filter((p) => p.name && isResolvable(p.version));
    if (queryable.length === 0) return [];

    const cache = NO_CACHE ? {} : await readCache();

    const cachedAdvisories: Bun.Security.Advisory[] = [];
    const toQuery: Bun.Security.Package[] = [];

    for (const pkg of queryable) {
      const entry = cache[`snyk:${pkg.name}@${pkg.version}`];
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
        ? `Scanning ${toQuery.length} packages via Snyk (${hitCount} cached)...`
        : `Scanning ${queryable.length} packages via Snyk...`,
    );

    try {
      const issueMap = await batchFetchIssues(toQuery, (done, total) => {
        spinner.update(`Scanning packages via Snyk (${done}/${total})...`);
      });

      spinner.stop();

      const freshByKey = new Map<string, Bun.Security.Advisory[]>();
      for (const pkg of toQuery) {
        const key = `${pkg.name}@${pkg.version}`;
        const issues = issueMap.get(key) ?? [];
        const advisories = issues.map((issue) => ({
          level: severityLevel(issue),
          package: pkg.name,
          url: advisoryUrl(issue),
          description: issue.attributes.title,
        }));
        freshByKey.set(key, advisories);
      }

      for (const [key, advisories] of freshByKey) {
        cache[`snyk:${key}`] = { advisories, cachedAt: Date.now() };
      }
      if (!NO_CACHE) void writeCache(cache);

      return [...cachedAdvisories, ...[...freshByKey.values()].flat()];
    } catch (err) {
      spinner.stop();

      if (FAIL_CLOSED) {
        throw new Error(
          `Snyk scan failed: ${err instanceof Error ? err.message : err}`,
        );
      }

      process.stderr.write(
        `\nSnyk scan failed (${err instanceof Error ? err.message : err}), skipping.\n`,
      );
      return cachedAdvisories;
    }
  },
};
