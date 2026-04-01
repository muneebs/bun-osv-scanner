import { SNYK_API_BASE, SNYK_API_VERSION, SNYK_TOKEN, SNYK_ORG_ID, FETCH_TIMEOUT_MS, CONCURRENCY } from './config';

export interface SnykIssue {
  id: string;
  attributes: {
    title: string;
    type: string;
    effective_severity_level: 'critical' | 'high' | 'medium' | 'low';
    description?: string;
    problems?: Array<{ id: string; source: string }>;
  };
}

interface SnykResponse {
  data: SnykIssue[];
  links?: { next?: string };
}

function fetchWithTimeout(url: string, options?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  return fetch(url, { ...options, signal: controller.signal }).finally(() =>
    clearTimeout(timer),
  );
}

export function validateConfig(): void {
  if (!SNYK_TOKEN) throw new Error('SNYK_TOKEN is required for the Snyk scanner');
  if (!SNYK_ORG_ID) throw new Error('SNYK_ORG_ID is required for the Snyk scanner');
}

function buildPurl(name: string, version: string): string {
  // Scoped packages: @scope/name -> pkg:npm/scope/name@version (PURL spec §7)
  if (name.startsWith('@')) {
    const slash = name.indexOf('/', 1);
    const scope = name.slice(1, slash);
    const pkg = name.slice(slash + 1);
    return `pkg:npm/${scope}/${pkg}@${version}`;
  }
  return `pkg:npm/${name}@${version}`;
}

export async function fetchPackageIssues(
  name: string,
  version: string,
): Promise<SnykIssue[]> {
  const purl = encodeURIComponent(buildPurl(name, version));
  const url = `${SNYK_API_BASE}/orgs/${SNYK_ORG_ID}/packages/${purl}/issues?version=${SNYK_API_VERSION}&limit=1000`;

  const res = await fetchWithTimeout(url, {
    headers: {
      Authorization: `token ${SNYK_TOKEN}`,
      'Content-Type': 'application/vnd.api+json',
    },
  });

  if (res.status === 404) return [];

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Snyk API ${res.status}: ${body || res.statusText}`);
  }

  const { data } = (await res.json()) as SnykResponse;
  return data ?? [];
}

export async function batchFetchIssues(
  packages: Bun.Security.Package[],
): Promise<Map<string, SnykIssue[]>> {
  const results = new Map<string, SnykIssue[]>();

  for (let i = 0; i < packages.length; i += CONCURRENCY) {
    await Promise.all(
      packages.slice(i, i + CONCURRENCY).map(async (pkg) => {
        const issues = await fetchPackageIssues(pkg.name, pkg.version);
        results.set(`${pkg.name}@${pkg.version}`, issues);
      }),
    );
  }

  return results;
}
