import {
  CONCURRENCY,
  FETCH_TIMEOUT_MS,
  RATE_LIMIT,
  SNYK_API_BASE,
  SNYK_API_VERSION,
  SNYK_ORG_ID,
  SNYK_TOKEN,
} from './config';

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

// Sliding window rate limiter — tracks request timestamps within the last minute.
class RateLimiter {
  private readonly timestamps: number[] = [];
  private readonly windowMs = 60_000;

  constructor(private readonly limit: number) {}

  async acquire(): Promise<void> {
    const now = Date.now();
    while (
      this.timestamps.length > 0 &&
      now - this.timestamps[0] >= this.windowMs
    ) {
      this.timestamps.shift();
    }
    if (this.timestamps.length < this.limit) {
      this.timestamps.push(Date.now());
      return;
    }
    // Wait until the oldest request falls outside the window, then retry.
    const waitMs = this.windowMs - (Date.now() - this.timestamps[0]) + 10;
    await Bun.sleep(waitMs);
    return this.acquire();
  }
}

const rateLimiter = new RateLimiter(RATE_LIMIT);

function fetchWithTimeout(
  url: string,
  options?: RequestInit
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  return fetch(url, { ...options, signal: controller.signal }).finally(() =>
    clearTimeout(timer)
  );
}

export function validateConfig(): void {
  if (!SNYK_TOKEN)
    throw new Error('SNYK_TOKEN is required for the Snyk scanner');
  if (!SNYK_ORG_ID)
    throw new Error('SNYK_ORG_ID is required for the Snyk scanner');
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

async function fetchPackageIssues(
  name: string,
  version: string,
  retries = 3
): Promise<SnykIssue[]> {
  await rateLimiter.acquire();

  const purl = encodeURIComponent(buildPurl(name, version));
  const url = `${SNYK_API_BASE}/orgs/${SNYK_ORG_ID}/packages/${purl}/issues?version=${SNYK_API_VERSION}&limit=1000`;

  const res = await fetchWithTimeout(url, {
    headers: {
      Authorization: `token ${SNYK_TOKEN}`,
      'Content-Type': 'application/vnd.api+json',
    },
  });

  if (res.status === 429 && retries > 0) {
    const retryAfter = res.headers.get('Retry-After');
    const waitMs = retryAfter ? Number(retryAfter) * 1000 : 60_000;
    await Bun.sleep(waitMs);
    return fetchPackageIssues(name, version, retries - 1);
  }

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
  onProgress?: (completed: number, total: number) => void
): Promise<Map<string, SnykIssue[]>> {
  const results = new Map<string, SnykIssue[]>();
  let completed = 0;

  for (let i = 0; i < packages.length; i += CONCURRENCY) {
    await Promise.all(
      packages.slice(i, i + CONCURRENCY).map(async (pkg) => {
        const issues = await fetchPackageIssues(pkg.name, pkg.version);
        results.set(`${pkg.name}@${pkg.version}`, issues);
        onProgress?.(++completed, packages.length);
      })
    );
  }

  return results;
}
