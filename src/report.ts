import type { PolicyRule } from "./policy.js";
import type { Trace } from "./trace.js";
import type { Verdict } from "./types.js";

export function printReport(
  verdict: Verdict,
  trace: Trace,
  rules: PolicyRule[],
  explanationSource: string
): void {
  const { target } = verdict;

  console.log(
    `\nPACKAGE  ${verdict.package}@${verdict.version}\n` +
      `TARGET   ${target.os}/${target.arch} ${target.libc} ${target.libcVersion} ` +
      `node ${target.node} (ABI ${target.abi})\n` +
      `STATUS   ${verdict.status}\n` +
      `DECISION ${verdict.decision.toUpperCase()}  risk=${verdict.riskScore}/100\n` +
      `COMPAT   ${verdict.compatibility.status}${
        verdict.compatibility.reasons.length
          ? ` — ${verdict.compatibility.reasons.join("; ")}`
          : ""
      }\n` +
      `RECOMMEND ${verdict.recommendedVersion ?? "none"}\n`
  );

  console.log("TRACE");
  for (const step of trace.steps) {
    const status = step.ok ? "ok  " : "FAIL";
    console.log(
      `  [${String(step.step).padStart(2)}] ${step.tool.padEnd(20)} ${status} ` +
        `${String(step.ms).padStart(5)}ms  ${step.summary}`
    );
    if (step.error) console.log(`       error: ${step.error}`);
  }

  console.log(`\nEVIDENCE (${verdict.evidence.length})`);
  for (const e of verdict.evidence) {
    const location = e.file ? ` (${e.file}${e.line ? `:${e.line}` : ""})` : "";
    console.log(
      `  ${e.id.padEnd(6)} ${e.source.padEnd(8)} ${e.severity.padEnd(8)} ` +
        `${e.confidence.toFixed(2)}  ${e.message}${location}`
    );
  }

  console.log("\nPOLICY");
  for (const rule of rules) {
    console.log(`  [${rule.fired ? "x" : " "}] ${rule.rule.padEnd(34)} ${rule.detail}`);
  }

  console.log(
    `\nSUMMARY (${explanationSource})\n  ${verdict.summary}\n`
  );
}
