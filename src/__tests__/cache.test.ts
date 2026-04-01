import { afterEach, beforeEach, describe, expect, mock, spyOn, test } from "bun:test";
import * as fsPromises from "node:fs/promises";
import { isFresh, readCache, writeCache } from "../cache";
import type { CacheEntry } from "../cache";

const DAY_MS = 24 * 60 * 60 * 1000;

describe("isFresh", () => {
  test("entry cached now is fresh", () => {
    const entry: CacheEntry = { advisories: [], cachedAt: Date.now() };
    expect(isFresh(entry)).toBe(true);
  });

  test("entry cached 23h ago is fresh", () => {
    const entry: CacheEntry = { advisories: [], cachedAt: Date.now() - 23 * 60 * 60 * 1000 };
    expect(isFresh(entry)).toBe(true);
  });

  test("entry cached exactly 24h ago is stale", () => {
    const entry: CacheEntry = { advisories: [], cachedAt: Date.now() - DAY_MS };
    expect(isFresh(entry)).toBe(false);
  });

  test("entry cached 25h ago is stale", () => {
    const entry: CacheEntry = { advisories: [], cachedAt: Date.now() - 25 * 60 * 60 * 1000 };
    expect(isFresh(entry)).toBe(false);
  });
});

describe("readCache", () => {
  let fileSpy: ReturnType<typeof spyOn<typeof Bun, "file">>;

  beforeEach(() => {
    fileSpy = spyOn(Bun, "file");
  });

  afterEach(() => {
    fileSpy.mockRestore();
  });

  test("returns empty object when file does not exist", async () => {
    fileSpy.mockReturnValue({
      text: async () => {
        throw new Error("ENOENT");
      },
    } as unknown as ReturnType<typeof Bun.file>);

    expect(await readCache()).toEqual({});
  });

  test("returns empty object when file contains invalid JSON", async () => {
    fileSpy.mockReturnValue({
      text: async () => "not valid json {{",
    } as unknown as ReturnType<typeof Bun.file>);

    expect(await readCache()).toEqual({});
  });

  test("returns empty object when file contains valid JSON with wrong structure", async () => {
    fileSpy.mockReturnValue({
      text: async () => JSON.stringify({ "lodash@4.17.4": "not-an-entry" }),
    } as unknown as ReturnType<typeof Bun.file>);

    expect(await readCache()).toEqual({});
  });

  test("returns empty object when file contains a JSON array", async () => {
    fileSpy.mockReturnValue({
      text: async () => JSON.stringify([{ advisories: [], cachedAt: 0 }]),
    } as unknown as ReturnType<typeof Bun.file>);

    expect(await readCache()).toEqual({});
  });

  test("returns parsed cache on valid file", async () => {
    const now = Date.now();
    const stored = { "lodash@4.17.4": { advisories: [], cachedAt: now } };
    fileSpy.mockReturnValue({
      text: async () => JSON.stringify(stored),
    } as unknown as ReturnType<typeof Bun.file>);

    const cache = await readCache();
    expect(cache["lodash@4.17.4"]?.cachedAt).toBe(now);
  });
});

describe("writeCache", () => {
  let writeSpy: ReturnType<typeof spyOn<typeof Bun, "write">>;
  let renameSpy: ReturnType<typeof spyOn<typeof fsPromises, "rename">>;

  beforeEach(() => {
    writeSpy = spyOn(Bun, "write");
    writeSpy.mockResolvedValue(0);
    renameSpy = spyOn(fsPromises, "rename");
    renameSpy.mockResolvedValue(undefined);
  });

  afterEach(() => {
    writeSpy.mockRestore();
    renameSpy.mockRestore();
  });

  test("writes serialised cache to a temp file then renames it", async () => {
    const cache = { "express@4.18.2": { advisories: [], cachedAt: 12345 } };
    await writeCache(cache);

    expect(writeSpy).toHaveBeenCalledTimes(1);
    const [path, content] = writeSpy.mock.calls[0] as unknown as [string, string];
    expect(path).toContain(".tmp");
    expect(JSON.parse(content)).toEqual(cache);
    expect(renameSpy).toHaveBeenCalledTimes(1);
  });

  test("does not throw if write fails", async () => {
    writeSpy.mockRejectedValue(new Error("EACCES"));
    await expect(writeCache({})).resolves.toBeUndefined();
  });
});
