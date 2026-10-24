export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Source = "registry" | "static" | "elf" | "osv" | "sandbox" | "llm";

export interface Evidence {
  id: string;
  source: Source;
  claim: string;
  severity: Severity;
  confidence: number;
  message: string;
  hard?: boolean;
  file?: string;
  line?: number;
  data?: Record<string, unknown>;
}

export interface Target {
  os: string;
  arch: string;
  libc: "glibc" | "musl";
  libcVersion: string;
  node: string;
  abi: number;
}

export interface Coverage {
  vulnChecked: boolean;
  nativeExpected: boolean;
  nativeInspected: boolean;
  sandboxed: boolean;
  transitiveChecked: boolean;
}

export interface Compatibility {
  status: "compatible" | "incompatible" | "unknown";
  reasons: string[];
}

export interface Verdict {
  package: string;
  version: string;
  target: Target;
  status: "SAFE" | "VULNERABLE";
  decision: "allow" | "allow_with_warnings" | "review" | "block";
  riskScore: number;
  compatibility: Compatibility;
  recommendedVersion?: string;
  evidence: Evidence[];
  coverage: Coverage;
  summary: string;
}

export interface Vulnerability {
  id: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  fixedVersions: string[];
}
