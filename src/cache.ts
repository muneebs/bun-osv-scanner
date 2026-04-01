import { rename } from 'node:fs/promises';
import { CACHE_TTL_MS } from './config';

export interface CacheEntry {
  advisories: Bun.Security.Advisory[];
  cachedAt: number;
}

type Cache = Record<string, CacheEntry>;

function isValidCache(data: unknown): data is Cache {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return false;
  return Object.values(data).every(
    (entry) =>
      typeof entry === 'object' &&
      entry !== null &&
      Array.isArray((entry as CacheEntry).advisories) &&
      typeof (entry as CacheEntry).cachedAt === 'number',
  );
}

export async function readCache(cacheFile: string): Promise<Cache> {
  try {
    const data: unknown = JSON.parse(await Bun.file(cacheFile).text());
    return isValidCache(data) ? data : {};
  } catch {
    return {};
  }
}

export async function writeCache(cache: Cache, cacheFile: string): Promise<void> {
  try {
    // Write to a temp file first, then rename — prevents partial-write corruption
    // if the process is killed or two installs run concurrently.
    const tmp = `${cacheFile}.tmp`;
    await Bun.write(tmp, JSON.stringify(cache, null, 2));
    await rename(tmp, cacheFile);
  } catch {}
}

export function isFresh(entry: CacheEntry): boolean {
  return Date.now() - entry.cachedAt < CACHE_TTL_MS;
}
