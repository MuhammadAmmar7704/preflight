import semver from "semver";
import type { Packument } from "./registry.js";
import type { Target } from "./types.js";

function matchesField(field: unknown, value: string): boolean {
  if (!field) return true;
  const values = (Array.isArray(field) ? field : [field]).map(String);
  const denied = values
    .filter((item) => item.startsWith("!"))
    .map((item) => item.slice(1));
  const allowed = values.filter((item) => !item.startsWith("!"));

  if (denied.includes(value)) return false;
  if (allowed.length > 0 && !allowed.includes(value)) return false;
  return true;
}

export function declaredCompatible(meta: any, target: Target): boolean {
  if (!matchesField(meta.os, target.os)) return false;
  if (!matchesField(meta.cpu, target.arch)) return false;
  if (!matchesField(meta.libc, target.libc)) return false;

  if (typeof meta.engines?.node === "string") {
    const nodeVersion = `${target.node}.0.0`;
    if (!semver.satisfies(nodeVersion, meta.engines.node, { includePrerelease: true })) {
      return false;
    }
  }

  return true;
}

export function listCandidateVersions(
  packument: Packument,
  range: string,
  target: Target,
  limit = 8
): string[] {
  const all = Object.keys(packument.versions);

  let candidates: string[];
  if (range === "latest" || range === "") {
    const latest = packument["dist-tags"]?.latest;
    candidates = [latest, ...all.filter((v) => v !== latest)].filter(
      (v): v is string => typeof v === "string"
    );
  } else if (packument.versions[range]) {
    candidates = [range];
  } else {
    candidates = all.filter((v) => semver.satisfies(v, range));
  }

  return [...new Set(candidates)]
    .filter((v) => semver.valid(v))
    .sort(semver.rcompare)
    .filter((v) => declaredCompatible(packument.versions[v], target))
    .slice(0, limit);
}
