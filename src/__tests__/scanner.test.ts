import { afterEach, beforeEach, describe, expect, mock, spyOn, test } from "bun:test";

// Mock the cache before index.ts is loaded so tests never touch the filesystem.
mock.module("../cache", () => ({
  readCache: async () => ({}),
  writeCache: async () => {},
  isFresh: () => false,
}));

const { scanner } = await import("../index");

function pkg(name: string, version: string): Bun.Security.Package {
  return { name, version, tarball: "", requestedRange: version };
}

function makeOsvVuln(id: string, severity: string, summary: string) {
  return {
    id,
    summary,
    references: [{ type: "ADVISORY", url: `https://osv.dev/vulnerability/${id}` }],
    database_specific: { severity },
  };
}

function mockOsvResponses(
  fetchSpy: ReturnType<typeof spyOn<typeof globalThis, "fetch">>,
  vulnIds: string[],
  vulnDetails: ReturnType<typeof makeOsvVuln>[],
) {
  // First call: batch query
  fetchSpy.mockResolvedValueOnce(
    new Response(
      JSON.stringify({
        results: [{ vulns: vulnIds.map(id => ({ id, modified: "" })) }],
      }),
    ),
  );
  // Subsequent calls: individual vuln details
  for (const detail of vulnDetails) {
    fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify(detail)));
  }
}

describe("scanner.scan", () => {
  let fetchSpy: ReturnType<typeof spyOn<typeof globalThis, "fetch">>;

  beforeEach(() => {
    fetchSpy = spyOn(globalThis, "fetch");
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  test("returns empty array when no packages provided", async () => {
    expect(await scanner.scan({ packages: [] })).toEqual([]);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("skips packages with non-resolvable versions", async () => {
    fetchSpy.mockResolvedValue(
      new Response(JSON.stringify({ results: [{ vulns: [] }] })),
    );

    await scanner.scan({
      packages: [
        pkg("app", "workspace:*"),
        pkg("local", "file:../local"),
        pkg("safe", "1.0.0"),
      ],
    });

    // Only "safe@1.0.0" should have been queried.
    const body = JSON.parse(
      (fetchSpy.mock.calls[0] as [string, RequestInit])[1].body as string,
    );
    expect(body.queries).toHaveLength(1);
    expect(body.queries[0].package.name).toBe("safe");
  });

  test("returns empty array when no vulnerabilities found", async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ results: [{ vulns: [] }] })),
    );

    const advisories = await scanner.scan({
      packages: [pkg("express", "4.18.2")],
    });

    expect(advisories).toEqual([]);
  });

  test("returns advisory for a vulnerable package", async () => {
    mockOsvResponses(
      fetchSpy,
      ["GHSA-aaa-bbb-cccc"],
      [makeOsvVuln("GHSA-aaa-bbb-cccc", "HIGH", "Prototype Pollution")],
    );

    const advisories = await scanner.scan({
      packages: [pkg("lodash", "4.17.4")],
    });

    expect(advisories).toHaveLength(1);
    expect(advisories[0]).toMatchObject({
      level: "fatal",
      package: "lodash",
      description: "Prototype Pollution",
    });
  });

  test.each([
    ["CRITICAL", "fatal"],
    ["HIGH", "fatal"],
    ["MODERATE", "warn"],
    ["LOW", "warn"],
  ] as const)("%s severity maps to level %s", async (severity, expectedLevel) => {
    mockOsvResponses(
      fetchSpy,
      ["GHSA-test"],
      [makeOsvVuln("GHSA-test", severity, "Test vuln")],
    );

    const [advisory] = await scanner.scan({
      packages: [pkg("pkg", "1.0.0")],
    });

    expect(advisory?.level).toBe(expectedLevel);
  });

  test("returns advisories for multiple vulnerable packages", async () => {
    // Two packages, each with one vuln.
    fetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          results: [
            { vulns: [{ id: "GHSA-aaa", modified: "" }] },
            { vulns: [{ id: "GHSA-bbb", modified: "" }] },
          ],
        }),
      ),
    );
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(makeOsvVuln("GHSA-aaa", "HIGH", "Vuln A"))),
    );
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(makeOsvVuln("GHSA-bbb", "MODERATE", "Vuln B"))),
    );

    const advisories = await scanner.scan({
      packages: [
        pkg("pkg-a", "1.0.0"),
        pkg("pkg-b", "2.0.0"),
      ],
    });

    expect(advisories).toHaveLength(2);
    expect(advisories.find(a => a.package === "pkg-a")?.level).toBe("fatal");
    expect(advisories.find(a => a.package === "pkg-b")?.level).toBe("warn");
  });

  test("deduplicates vuln detail fetches when the same ID affects multiple packages", async () => {
    // Both packages share the same vuln ID.
    fetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          results: [
            { vulns: [{ id: "GHSA-shared", modified: "" }] },
            { vulns: [{ id: "GHSA-shared", modified: "" }] },
          ],
        }),
      ),
    );
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(makeOsvVuln("GHSA-shared", "HIGH", "Shared vuln"))),
    );

    const advisories = await scanner.scan({
      packages: [
        pkg("pkg-a", "1.0.0"),
        pkg("pkg-b", "1.0.0"),
      ],
    });

    // One batch call + one detail call (not two).
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(advisories).toHaveLength(2);
  });

  test("fails open on network error by default", async () => {
    fetchSpy.mockRejectedValueOnce(new Error("ECONNREFUSED"));

    const advisories = await scanner.scan({
      packages: [pkg("pkg", "1.0.0")],
    });

    expect(advisories).toEqual([]);
  });
});
