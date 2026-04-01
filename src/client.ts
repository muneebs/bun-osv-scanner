import { FETCH_TIMEOUT_MS, OSV_API_BASE, OSV_BATCH_SIZE } from './config';

export interface OsvBatchResponse {
  results: Array<{
    vulns?: Array<{ id: string; modified: string }>;
    next_page_token?: string;
  }>;
}

export interface OsvVulnerability {
  id: string;
  summary?: string;
  references?: Array<{ type: string; url: string }>;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: {
    severity?: string;
    cvss?: { score?: number };
    [key: string]: unknown;
  };
}

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

// workspace:, file:, git:, and range specifiers cause a 400 for the whole batch.
export function isResolvable(version: string): boolean {
  return /^v?\d+\.\d+/.test(version);
}

export async function batchQuery(
  packages: Bun.Security.Package[]
): Promise<OsvBatchResponse['results']> {
  const results: OsvBatchResponse['results'] = [];

  for (let i = 0; i < packages.length; i += OSV_BATCH_SIZE) {
    const chunk = packages.slice(i, i + OSV_BATCH_SIZE);
    const res = await fetchWithTimeout(`${OSV_API_BASE}/querybatch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        queries: chunk.map((p) => ({
          version: p.version,
          package: { name: p.name, ecosystem: 'npm' },
        })),
      }),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`OSV API ${res.status}: ${body || res.statusText}`);
    }

    const { results: chunkResults } = (await res.json()) as OsvBatchResponse;
    results.push(...chunkResults);
  }

  return results;
}

export async function fetchVuln(id: string): Promise<OsvVulnerability | null> {
  const res = await fetchWithTimeout(`${OSV_API_BASE}/vulns/${id}`);
  if (!res.ok) return null;
  return res.json() as Promise<OsvVulnerability>;
}
