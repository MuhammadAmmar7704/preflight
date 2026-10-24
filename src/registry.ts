import { promises as fs } from "node:fs";
import semver from "semver";
import { sha512Base64 } from "./util.js";

export interface Packument {
  "dist-tags": Record<string, string>;
  versions: Record<string, any>;
}

const REGISTRY = (process.env.PREFLIGHT_REGISTRY ?? "https://registry.npmjs.org").replace(
  /\/$/,
  ""
);

export async function fetchPackument(name: string): Promise<Packument> {
  const encoded = name.startsWith("@") ? name.replace("/", "%2F") : name;
  const res = await fetch(`${REGISTRY}/${encoded}`, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(20_000),
  });
  if (!res.ok) {
    throw new Error(`registry returned ${res.status} for ${name}`);
  }
  return (await res.json()) as Packument;
}

export function pickVersion(
  packument: Packument,
  range: string,
  name: string
): string {
  if (range === "latest" || range === "") {
    const latest = packument["dist-tags"]?.latest;
    if (!latest) throw new Error(`no latest dist-tag for ${name}`);
    return latest;
  }

  if (packument.versions[range]) return range;

  const candidates = Object.keys(packument.versions);
  const picked = semver.maxSatisfying(candidates, range);
  if (!picked) {
    throw new Error(`no version of ${name} satisfies "${range}"`);
  }
  return picked;
}

export async function downloadTarball(
  url: string,
  integrity: string | undefined,
  dest: string
): Promise<{ bytes: number; verified: boolean }> {
  const res = await fetch(url, { signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`tarball download failed: ${res.status}`);

  const buf = Buffer.from(await res.arrayBuffer());

  let verified = false;
  if (integrity?.startsWith("sha512-")) {
    const actual = `sha512-${sha512Base64(buf)}`;
    if (actual !== integrity) {
      throw new Error(
        `integrity mismatch for ${url}: expected ${integrity}, got ${actual}`
      );
    }
    verified = true;
  }

  await fs.writeFile(dest, buf);
  return { bytes: buf.length, verified };
}
