import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import { batchQuery, fetchVuln, isResolvable } from "../client";

function pkg(name: string, version: string): Bun.Security.Package {
  return { name, version, tarball: "", requestedRange: version };
}

describe("isResolvable", () => {
  test.each(["1.0.0", "1.2.3", "2.0.0-beta.1", "0.0.1", "v1.2.3", "10.0.0-rc.1"])(
    'accepts "%s"',
    v => expect(isResolvable(v)).toBe(true),
  );

  test.each([
    "workspace:*",
    "workspace:^1.0.0",
    "file:../foo",
    "git+https://github.com/x/y",
    "link:../bar",
    "*",
    "latest",
    "^1.0.0",
    "~2.0.0",
    "",
  ])('rejects "%s"', v => expect(isResolvable(v)).toBe(false));
});

describe("batchQuery", () => {
  let fetchSpy: ReturnType<typeof spyOn<typeof globalThis, "fetch">>;

  beforeEach(() => {
    fetchSpy = spyOn(globalThis, "fetch");
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  test("sends packages as OSV querybatch payload with npm ecosystem", async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ results: [{ vulns: [] }] })),
    );

    await batchQuery([pkg("lodash", "4.17.4")]);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, options] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/querybatch");
    expect(JSON.parse(options.body as string)).toEqual({
      queries: [{ version: "4.17.4", package: { name: "lodash", ecosystem: "npm" } }],
    });
  });

  test("returns results in the same order as the input packages", async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          results: [
            { vulns: [{ id: "GHSA-aaa-bbb-cccc", modified: "" }] },
            { vulns: [] },
          ],
        }),
      ),
    );

    const results = await batchQuery([
      pkg("lodash", "4.17.4"),
      pkg("express", "4.18.2"),
    ]);

    expect(results).toHaveLength(2);
    expect(results[0].vulns?.[0].id).toBe("GHSA-aaa-bbb-cccc");
    expect(results[1].vulns).toHaveLength(0);
  });

  test("throws on non-OK response", async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response('{"code":3,"message":"Too many queries."}', { status: 400 }),
    );

    await expect(batchQuery([pkg("x", "1.0.0")])).rejects.toThrow("OSV API 400");
  });

  test("splits packages into chunks of 1000", async () => {
    const packages = Array.from({ length: 1001 }, (_, i) => pkg(`pkg-${i}`, "1.0.0"));

    fetchSpy
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ results: Array(1000).fill({ vulns: [] }) })),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ results: [{ vulns: [] }] })),
      );

    const results = await batchQuery(packages);

    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(results).toHaveLength(1001);
  });
});

describe("fetchVuln", () => {
  let fetchSpy: ReturnType<typeof spyOn<typeof globalThis, "fetch">>;

  beforeEach(() => {
    fetchSpy = spyOn(globalThis, "fetch");
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  test("fetches from the correct endpoint", async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ id: "GHSA-test", database_specific: {} })),
    );

    await fetchVuln("GHSA-test");

    const [url] = fetchSpy.mock.calls[0] as [string];
    expect(url).toContain("/vulns/GHSA-test");
  });

  test("returns parsed vulnerability on success", async () => {
    const mockVuln = {
      id: "GHSA-aaa-bbb-cccc",
      summary: "Prototype Pollution",
      database_specific: { severity: "HIGH" },
    };
    fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify(mockVuln)));

    const result = await fetchVuln("GHSA-aaa-bbb-cccc");
    expect(result?.id).toBe("GHSA-aaa-bbb-cccc");
    expect(result?.summary).toBe("Prototype Pollution");
  });

  test("returns null on non-OK response", async () => {
    fetchSpy.mockResolvedValueOnce(new Response("Not Found", { status: 404 }));
    expect(await fetchVuln("GHSA-missing")).toBeNull();
  });
});
