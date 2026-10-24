import type { Verdict } from "./types.js";

export interface Explanation {
  text: string;
  source: "gemma" | "deterministic";
  model: string;
}

function deterministicSummary(verdict: Verdict): string {
  const critical = verdict.evidence.filter(
    (e) => e.severity === "critical"
  ).length;
  const high = verdict.evidence.filter((e) => e.severity === "high").length;

  const parts = [
    `${verdict.decision.toUpperCase()}: ${verdict.package}@${verdict.version}.`,
    `Compatibility: ${verdict.compatibility.status}.`,
    `Risk score: ${verdict.riskScore}/100.`,
  ];

  if (critical > 0) parts.push(`${critical} critical finding(s).`);
  if (high > 0) parts.push(`${high} high-severity finding(s).`);
  if (verdict.recommendedVersion) {
    parts.push(`Recommended version: ${verdict.recommendedVersion}.`);
  }

  return parts.join(" ");
}

export async function explain(verdict: Verdict): Promise<Explanation> {
  const key = process.env.GEMINI_API_KEY;
  if (!key) {
    return {
      text: deterministicSummary(verdict),
      source: "deterministic",
      model: "none",
    };
  }

  const model = process.env.GEMMA_MODEL ?? "gemma-4-31b-it";

  const evidence = verdict.evidence.map((e) => ({
    id: e.id,
    source: e.source,
    claim: e.claim,
    severity: e.severity,
    message: e.message,
    file: e.file,
    line: e.line,
  }));

  const prompt = `You are a supply-chain security analyst.
Use only the evidence below. Do not invent CVEs, versions, symbols, or facts.
Explain the decision in 2-3 sentences for a developer.
Then list concrete next steps.
Return JSON with this shape:
{"summary":"...","evidence_ids":["ev_1"],"next_steps":["..."]}

Package: ${verdict.package}@${verdict.version}
Target: ${JSON.stringify(verdict.target)}
Decision: ${verdict.decision}
Risk: ${verdict.riskScore}
Compatibility: ${JSON.stringify(verdict.compatibility)}
Recommended version: ${verdict.recommendedVersion ?? "none"}
Evidence:
${JSON.stringify(evidence, null, 2)}`;

  try {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          contents: [{ role: "user", parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0,
            responseMimeType: "application/json",
          },
        }),
        signal: AbortSignal.timeout(30_000),
      }
    );

    if (!res.ok) {
      return {
        text: deterministicSummary(verdict),
        source: "deterministic",
        model,
      };
    }

    const data = (await res.json()) as any;
    const raw = data.candidates?.[0]?.content?.parts?.[0]?.text;
    if (typeof raw !== "string") {
      return {
        text: deterministicSummary(verdict),
        source: "deterministic",
        model,
      };
    }

    const parsed = JSON.parse(raw.replace(/^```json\s*|\s*```$/g, ""));
    const validIds = new Set(verdict.evidence.map((e) => e.id));
    const cited = (parsed.evidence_ids ?? []).filter((id: string) =>
      validIds.has(id)
    );

    if (!parsed.summary || cited.length === 0) {
      return {
        text: deterministicSummary(verdict),
        source: "deterministic",
        model,
      };
    }

    const steps = Array.isArray(parsed.next_steps)
      ? ` Next: ${parsed.next_steps.join(" ")}`
      : "";

    return {
      text: `${parsed.summary}${steps}`,
      source: "gemma",
      model,
    };
  } catch {
    return {
      text: deterministicSummary(verdict),
      source: "deterministic",
      model,
    };
  }
}
