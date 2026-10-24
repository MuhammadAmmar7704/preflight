import type { ElfInfo } from "./elf.js";
import { Ledger } from "./evidence.js";
import type {
  Compatibility,
  Coverage,
  Severity,
  Target,
  Verdict,
  Vulnerability,
} from "./types.js";
import { compareVersions } from "./util.js";

export interface PolicyRule {
  rule: string;
  fired: boolean;
  detail: string;
}

export interface PolicyResult {
  decision: Verdict["decision"];
  riskScore: number;
  compatibility: Compatibility;
  rules: PolicyRule[];
}

const WEIGHTS: Record<Severity, number> = {
  critical: 60,
  high: 35,
  medium: 15,
  low: 5,
  info: 0,
};

export function checkCompatibility(
  elfs: ElfInfo[],
  target: Target
): Compatibility {
  if (elfs.length === 0) {
    return { status: "compatible", reasons: [] };
  }

  const reasons: string[] = [];
  let unknown = false;

  for (const elf of elfs) {
    if (!elf.ok) {
      unknown = true;
      reasons.push(`${elf.rel}: inspection failed (${elf.error ?? "unknown"})`);
      continue;
    }

    if (elf.arch !== "unknown" && elf.arch !== target.arch) {
      reasons.push(`${elf.rel}: arch ${elf.arch} != target ${target.arch}`);
    }

    if (elf.libc !== "unknown" && elf.libc !== target.libc) {
      reasons.push(`${elf.rel}: libc ${elf.libc} != target ${target.libc}`);
    }

    if (
      elf.glibc &&
      target.libc === "glibc" &&
      compareVersions(elf.glibc, target.libcVersion) > 0
    ) {
      reasons.push(
        `${elf.rel}: requires GLIBC_${elf.glibc} > target ${target.libcVersion}`
      );
    }

    if (elf.abi && !elf.napi && elf.abi !== target.abi) {
      reasons.push(`${elf.rel}: Node ABI ${elf.abi} != target ${target.abi}`);
    }
  }

  if (unknown) return { status: "unknown", reasons };
  if (reasons.length > 0) return { status: "incompatible", reasons };
  return { status: "compatible", reasons: [] };
}

export function evaluate(input: {
  elfs: ElfInfo[];
  target: Target;
  ledger: Ledger;
  coverage: Coverage;
  vulns: Vulnerability[];
}): PolicyResult {
  const { elfs, target, ledger, coverage, vulns } = input;

  const compatibility = checkCompatibility(elfs, target);

  let score = 0;
  for (const evidence of ledger.all()) {
    score += WEIGHTS[evidence.severity];
  }
  score = Math.min(100, score);

  const criticalVuln = vulns.some((v) => v.severity === "critical");
  const highVuln = vulns.some((v) => v.severity === "high");
  const incompatible = compatibility.status === "incompatible";
  const nativeUnknown =
    coverage.nativeExpected && !coverage.nativeInspected;
  const incompleteCoverage =
    !coverage.sandboxed || !coverage.transitiveChecked;

  const rules: PolicyRule[] = [
    {
      rule: "compatibility.incompatible",
      fired: incompatible,
      detail: incompatible
        ? compatibility.reasons.join("; ")
        : `compatible with ${target.os}/${target.arch} ${target.libc} ${target.libcVersion}`,
    },
    {
      rule: "security.critical_vulnerability",
      fired: criticalVuln,
      detail: criticalVuln
        ? `${vulns.filter((v) => v.severity === "critical").length} critical advisory(s)`
        : "no critical advisories",
    },
    {
      rule: "security.high_vulnerability",
      fired: highVuln,
      detail: highVuln
        ? `${vulns.filter((v) => v.severity === "high").length} high advisory(s)`
        : "no high advisories",
    },
    {
      rule: "coverage.vulnerability_feed",
      fired: !coverage.vulnChecked,
      detail: coverage.vulnChecked
        ? "OSV query succeeded"
        : "OSV query failed; cannot rule out known vulnerabilities",
    },
    {
      rule: "coverage.native_inspection",
      fired: nativeUnknown,
      detail: coverage.nativeExpected
        ? coverage.nativeInspected
          ? "native artifacts inspected"
          : "native artifacts present but not inspected"
        : "no native artifacts",
    },
    {
      rule: "coverage.sandbox",
      fired: !coverage.sandboxed,
      detail: coverage.sandboxed
        ? "install + import completed in sandbox"
        : "sandbox install/import did not complete",
    },
    {
      rule: "coverage.transitive",
      fired: !coverage.transitiveChecked,
      detail: coverage.transitiveChecked
        ? "transitive dependency tree scanned"
        : "transitive dependency tree not scanned",
    },
    {
      rule: "score.threshold",
      fired: score >= 50,
      detail: `risk score ${score}/100`,
    },
  ];

  if (incompatible || criticalVuln) score = 100;

  let decision: Verdict["decision"];
  if (incompatible || criticalVuln) {
    decision = "block";
  } else if (!coverage.vulnChecked || nativeUnknown || incompleteCoverage) {
    decision = "review";
  } else if (score >= 75) {
    decision = "block";
  } else if (score >= 50) {
    decision = "review";
  } else if (score >= 25) {
    decision = "allow_with_warnings";
  } else {
    decision = "allow";
  }

  return { decision, riskScore: score, compatibility, rules };
}
