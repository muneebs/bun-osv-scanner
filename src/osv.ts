import type { OsvVulnerability } from './client';
import { batchQuery, fetchVuln } from './client';
import { CACHE_FILE, FAIL_CLOSED, NO_CACHE } from './config';
import { type Backend, createScanner } from './scanner';
import { advisoryUrl, severityLevel } from './severity';

const backend: Backend = {
  name: 'OSV',
  cacheFile: CACHE_FILE,
  noCache: NO_CACHE,
  failClosed: FAIL_CLOSED,

  async fetchAdvisories(packages, onStatus) {
    const batchResults = await batchQuery(packages);

    const affected: Array<{ pkg: Bun.Security.Package; vulnId: string }> = [];
    for (let i = 0; i < packages.length; i++) {
      for (const { id } of batchResults[i]?.vulns ?? []) {
        affected.push({ pkg: packages[i], vulnId: id });
      }
    }

    const result = new Map<string, Bun.Security.Advisory[]>();
    for (const pkg of packages) {
      result.set(`${pkg.name}@${pkg.version}`, []);
    }

    if (affected.length > 0) {
      const uniqueIds = [...new Set(affected.map((a) => a.vulnId))];
      const vulnById = new Map<string, OsvVulnerability>();

      onStatus(
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
          result.get(`${pkg.name}@${pkg.version}`)?.push({
            level: severityLevel(vuln),
            package: pkg.name,
            url: advisoryUrl(vuln),
            description: vuln.summary ?? vuln.id,
          });
        }
      }
    }

    return result;
  },
};

export { backend };
export const scanner = createScanner(backend);
