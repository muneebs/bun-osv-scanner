export const SNYK_API_BASE = Bun.env.SNYK_API_BASE ?? 'https://api.snyk.io/rest';
export const SNYK_API_VERSION = Bun.env.SNYK_API_VERSION ?? '2024-04-29';
export const SNYK_TOKEN = Bun.env.SNYK_TOKEN;
export const SNYK_ORG_ID = Bun.env.SNYK_ORG_ID;
export const FETCH_TIMEOUT_MS = Number(Bun.env.SNYK_TIMEOUT_MS) || 10_000;
export const FAIL_CLOSED = Bun.env.SNYK_FAIL_CLOSED === 'true';
export const NO_CACHE = Bun.env.SNYK_NO_CACHE === 'true';
// Max concurrent connections (independent of rate limit)
export const CONCURRENCY = Number(Bun.env.SNYK_CONCURRENCY) || 10;
// Requests per minute — hard ceiling is 180; default leaves headroom
export const RATE_LIMIT = Math.min(Number(Bun.env.SNYK_RATE_LIMIT) || 160, 180);

export const CACHE_FILE = Bun.env.SNYK_CACHE_FILE ?? '.snyk.lock';
export const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
