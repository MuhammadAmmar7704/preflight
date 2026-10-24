import { promises as fs } from "node:fs";
import path from "node:path";
import { Ledger } from "./evidence.js";
import type { FileEntry } from "./indexer.js";
import type { Severity } from "./types.js";

interface Rule {
  id: string;
  re: RegExp;
  severity: Severity;
  confidence: number;
  message: string;
}

const RULES: Rule[] = [
  {
    id: "shell.exec",
    re: /\bchild_process\b|\bexecSync\b|\bspawnSync\b|\bexecFileSync\b/,
    severity: "high",
    confidence: 0.85,
    message: "Shell execution capability",
  },
  {
    id: "code.eval",
    re: /\beval\s*\(|\bnew\s+Function\s*\(/,
    severity: "high",
    confidence: 0.8,
    message: "Dynamic code evaluation",
  },
  {
    id: "net.egress",
    re: /\bhttps?\.(request|get)\b|\bnet\.(connect|createConnection)\b|\bdns\.(lookup|resolve)[A-Za-z]*\b|\bfetch\s*\(/,
    severity: "medium",
    confidence: 0.65,
    message: "Network access",
  },
  {
    id: "env.access",
    re: /\bprocess\.env\b/,
    severity: "low",
    confidence: 0.6,
    message: "Environment variable access",
  },
  {
    id: "credential.path",
    re: /\.npmrc|\.ssh|id_rsa|\.aws\/credentials|\.git-credentials/,
    severity: "high",
    confidence: 0.9,
    message: "Credential path reference",
  },
  {
    id: "payload.encoded",
    re: /eval\s*\(\s*atob\s*\(|Buffer\.from\([^)]*,\s*["']base64["']\s*\)/,
    severity: "high",
    confidence: 0.8,
    message: "Encoded payload execution",
  },
  {
    id: "require.dynamic",
    re: /require\s*\(\s*[^"'`\s]/,
    severity: "medium",
    confidence: 0.55,
    message: "Dynamic require",
  },
  {
    id: "remote.shell",
    re: /curl\s+[^|]*\|\s*(sh|bash)|wget\s+[^|]*\|\s*(sh|bash)/,
    severity: "critical",
    confidence: 0.95,
    message: "Remote shell execution",
  },
];

export interface StaticResult {
  hasInstallScripts: boolean;
  hasBindingGyp: boolean;
  findings: number;
}

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split("\n").length;
}

export async function scanStatic(
  root: string,
  pkg: any,
  meta: any,
  index: FileEntry[],
  ledger: Ledger
): Promise<StaticResult> {
  let findings = 0;
  let hasInstallScripts = false;
  let hasBindingGyp = false;

  const scripts = pkg.scripts ?? {};
  for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
    const script = scripts[hook];
    if (typeof script !== "string") continue;

    hasInstallScripts = true;
    const risky = /(curl|wget|https?:\/\/|base64|node\s+-e|child_process)/i.test(
      script
    );
    ledger.add({
      source: "static",
      claim: `install_script.${hook}`,
      severity: risky ? "critical" : hook === "prepare" ? "low" : "high",
      confidence: 0.9,
      message: `${hook} script runs: ${script}`,
      data: { script },
    });
    findings++;
  }

  if (pkg.gypfile === true || index.some((f) => f.rel.endsWith("binding.gyp"))) {
    hasBindingGyp = true;
    ledger.add({
      source: "static",
      claim: "native.build",
      severity: "medium",
      confidence: 0.9,
      message: "Package builds a native addon with node-gyp",
    });
    findings++;
  }

  if (typeof pkg.deprecated === "string") {
    ledger.add({
      source: "registry",
      claim: "package.deprecated",
      severity: "low",
      confidence: 0.95,
      message: `Package is deprecated: ${pkg.deprecated}`,
    });
  }

  if (!meta?.dist?.attestations) {
    ledger.add({
      source: "registry",
      claim: "provenance.missing",
      severity: "low",
      confidence: 0.8,
      message: "No npm provenance attestation published",
    });
  }

  const deps = { ...(pkg.dependencies ?? {}), ...(pkg.optionalDependencies ?? {}) };
  for (const [dep, spec] of Object.entries(deps)) {
    if (typeof spec === "string" && /^(git\+|https?:|github:)/.test(spec)) {
      ledger.add({
        source: "static",
        claim: "dependency.remote",
        severity: "medium",
        confidence: 0.85,
        message: `Remote dependency ${dep}: ${spec}`,
      });
    }
  }

  const seen = new Set<string>();

  for (const file of index) {
    if (!["js", "ts", "shell"].includes(file.kind)) continue;
    if (file.size > 1_500_000) continue;

    const text = await fs.readFile(path.join(root, file.rel), "utf8");
    for (const rule of RULES) {
      const match = text.match(rule.re);
      if (!match || match.index === undefined) continue;

      const key = `${rule.id}:${file.rel}`;
      if (seen.has(key)) continue;
      seen.add(key);

      ledger.add({
        source: "static",
        claim: rule.id,
        severity: rule.severity,
        confidence: rule.confidence,
        message: `${rule.message} in ${file.rel}`,
        hard: rule.id === "remote.shell",
        file: file.rel,
        line: lineOf(text, match.index),
        data: { snippet: text.slice(Math.max(0, match.index - 60), match.index + 120) },
      });
      findings++;
      if (findings >= 100) return { hasInstallScripts, hasBindingGyp, findings };
    }
  }

  return { hasInstallScripts, hasBindingGyp, findings };
}
