import semver from "semver";
import { Ledger } from "./evidence.js";
import type { Packument } from "./registry.js";
import type { Severity, Vulnerability } from "./types.js";

export interface OsvResult {
  ok: boolean;
  error?: string;
  vulns: Vulnerability[];
}

function normalizeSeverity(raw: string): Severity {
  const s = raw.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "moderate" || s === "medium") return "medium";
  if (s === "low") return "low";
  return "medium";
}

function severityOf(v: any): Severity {
  const raw =
    v.database_specific?.severity ??
    v.affected?.[0]?.database_specific?.severity;
  if (raw) return normalizeSeverity(String(raw));

  const score = v.severity?.find((s: any) =>
    String(s.type ?? "").startsWith("CVSS")
  )?.score;
  if (typeof score === "number") {
    if (score >= 9) return "critical";
    if (score >= 7) return "high";
    if (score >= 4) return "medium";
    return "low";
  }
  return "medium";
}

function fixedVersionsOf(v: any): string[] {
  const fixed = new Set<string>();
  for (const affected of v.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) fixed.add(event.fixed);
      }
    }
  }
  return [...fixed];
}

export async function queryOsv(
  name: string,
  version: string
): Promise<OsvResult> {
  try {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        package: { name, ecosystem: "npm" },
        version,
      }),
      signal: AbortSignal.timeout(20_000),
    });

    if (!res.ok) {
      return { ok: false, error: `OSV returned ${res.status}`, vulns: [] };
    }

    const data = (await res.json()) as { vulns?: any[] };
    const vulns: Vulnerability[] = (data.vulns ?? []).map((v) => ({
      id: v.id,
      aliases: v.aliases ?? [],
      summary: v.summary ?? v.details?.slice(0, 160) ?? "No summary",
      severity: severityOf(v),
      fixedVersions: fixedVersionsOf(v),
    }));

    return { ok: true, vulns };
  } catch (err) {
    return {
      ok: false,
      error: (err as Error).message,
      vulns: [],
    };
  }
}

export function recordVulns(ledger: Ledger, vulns: Vulnerability[]): void {
  const important = vulns.filter(
    (v) => v.severity === "critical" || v.severity === "high"
  );
  const rest = vulns.filter(
    (v) => v.severity !== "critical" && v.severity !== "high"
  );

  for (const v of [...important, ...rest].slice(0, 15)) {
    ledger.add({
      source: "osv",
      claim: "vulnerability",
      severity: v.severity,
      confidence: 0.95,
      message: `${v.id}: ${v.summary}`,
      hard: v.severity === "critical",
      data: { aliases: v.aliases, fixedVersions: v.fixedVersions },
    });
  }

  if (vulns.length > 15) {
    ledger.add({
      source: "osv",
      claim: "vulnerability.more",
      severity: "info",
      confidence: 0.95,
      message: `${vulns.length - 15} additional advisories omitted`,
      data: { total: vulns.length },
    });
  }
}

export async function recommendVersion(
  name: string,
  current: string,
  vulns: Vulnerability[],
  packument: Packument
): Promise<string | undefined> {
  const fixed = [
    ...new Set(vulns.flatMap((v) => v.fixedVersions)),
  ]
    .filter((v) => semver.valid(v) && semver.gt(v, current))
    .sort(semver.rcompare);

  const candidates =
    fixed.length > 0
      ? fixed.slice(0, 3)
      : Object.keys(packument.versions)
          .filter((v) => semver.valid(v) && semver.gt(v, current))
          .sort(semver.rcompare)
          .slice(0, 3);

  for (const candidate of candidates) {
    const result = await queryOsv(name, candidate);
    const bad = result.vulns.some(
      (v) => v.severity === "critical" || v.severity === "high"
    );
    if (result.ok && !bad) return candidate;
  }

  return undefined;
}
