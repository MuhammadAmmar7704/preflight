import { promises as fs } from "node:fs";
import path from "node:path";
import { runGemmaAgent } from "./agent.js";
import { listCandidateVersions } from "./candidates.js";
import { inspectElf, recordElfEvidence, type ElfInfo } from "./elf.js";
import { extractTarball } from "./extract.js";
import { Ledger } from "./evidence.js";
import { explain } from "./gemma.js";
import { buildIndex } from "./indexer.js";
import {
  queryOsv,
  recommendVersion,
  recordVulns,
  type OsvResult,
} from "./osv.js";
import { evaluate, type PolicyRule } from "./policy.js";
import {
  downloadTarball,
  fetchPackument,
  type Packument,
} from "./registry.js";
import { printReport } from "./report.js";
import { installAndDetonate } from "./sandbox.js";
import { scanStatic } from "./static.js";
import { targetFromArgs } from "./targets.js";
import { Trace } from "./trace.js";
import { scanTransitive } from "./transitive.js";
import type { Coverage, Target, Verdict } from "./types.js";
import { analyzeProject, checkUsage, type UsageContract } from "./usage.js";
import { mkdtemp, parseSpec, rmrf } from "./util.js";

function printUsage(): never {
  console.error(
    `Usage:
  preflight scan <name>[@version|range] [options]

Options:
  --target <preset>    ubuntu22-node20 | ubuntu24-node22 | debian12-node20 | alpine-node20
  --glibc <version>    Override target glibc version, e.g. 2.35
  --node <version>     Override target Node major, e.g. 20
  --abi <number>       Override target Node ABI, e.g. 115
  --arch <arch>        x64 | arm64
  --libc <libc>        glibc | musl
  --project <dir>      Project directory used for import/API analysis (default: cwd)
  --tarball <path>     Scan a local .tgz instead of the npm registry
  --no-gemma           Skip the Gemma 4 tool-calling agent (deterministic pipeline)
  --status             Print only {"status":"SAFE"} or {"status":"VULNERABLE"}
  --json               Print machine-readable verdict + trace

Gemma 4 is used automatically when GEMINI_API_KEY is set.
`
  );
  process.exit(1);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv[0] !== "scan") printUsage();

  const spec = argv[1];
  if (!spec) printUsage();

  const rest = argv.slice(2);
  const flag = (name: string): string | undefined => {
    const idx = rest.indexOf(name);
    return idx >= 0 ? rest[idx + 1] : undefined;
  };
  const has = (name: string): boolean => rest.includes(name);

  const target: Target = targetFromArgs(flag("--target"), {
    ...(flag("--glibc") ? { libcVersion: flag("--glibc")! } : {}),
    ...(flag("--node") ? { node: flag("--node")! } : {}),
    ...(flag("--abi") ? { abi: Number(flag("--abi")) } : {}),
    ...(flag("--arch") ? { arch: flag("--arch")! } : {}),
    ...(flag("--libc") ? { libc: flag("--libc") as "glibc" | "musl" } : {}),
  });

  const parsed = parseSpec(spec);
  let name = parsed.name;
  const range = parsed.range;
  const ledger = new Ledger();
  const trace = new Trace();
  const work = await mkdtemp();
  let root = path.join(work, "package");
  const localTarball = flag("--tarball");
  const projectDir = flag("--project") ?? process.cwd();

  let usage: UsageContract;
  try {
    usage = await analyzeProject(projectDir, name);
  } catch {
    usage = {
      packageName: name,
      range,
      symbols: [],
      subpaths: [],
      defaultImport: false,
      namespaceImport: false,
      files: [],
    };
  }

  if (!has("--no-gemma") && process.env.GEMINI_API_KEY && !localTarball) {
    try {
      const result = await runGemmaAgent({ name, range, target, usage });

      if (has("--status")) {
        console.log(JSON.stringify({ status: result.verdict.status }));
      } else if (has("--json")) {
        console.log(
          JSON.stringify(
            {
              status: result.verdict.status,
              verdict: result.verdict,
              trace: result.trace.steps,
              policy: result.policy,
              explanation: result.explanation,
            },
            null,
            2
          )
        );
      } else {
        printReport(
          result.verdict,
          result.trace,
          result.policy,
          result.explanation.source
        );
      }

      await rmrf(work);
      return;
    } catch (err) {
      console.error(
        `[preflight] Gemma unavailable (${(err as Error).message}); falling back to deterministic pipeline.`
      );
    }
  }

  try {
    await fs.mkdir(root, { recursive: true });

    let packument: Packument | undefined;
    let version = "";
    let meta: any = {};
    let tarballPath = localTarball ?? "";

    if (localTarball) {
      await trace.step(
        "local.tarball",
        { path: localTarball },
        async () => {
          const value = await extractTarball(localTarball, root);
          return {
            value,
            summary: `${value.files} files, ${value.bytes} bytes extracted from local tarball`,
          };
        }
      );

      const localPkg = JSON.parse(
        await fs.readFile(path.join(root, "package.json"), "utf8")
      );
      name = localPkg.name ?? name;
      version = localPkg.version ?? "0.0.0";
      usage = { ...usage, packageName: name };

      ledger.add({
        source: "registry",
        claim: "package.local",
        severity: "info",
        confidence: 1,
        message: `Loaded local tarball ${localTarball} (${name}@${version})`,
      });
    } else {
      packument = await trace.step(
        "registry.packument",
        { name },
        async () => {
          const value = await fetchPackument(name);
          return {
            value,
            summary: `${name}: ${Object.keys(value.versions).length} versions`,
          };
        }
      );

      const effectiveRange = range === "latest" ? usage.range : range;
      const candidates = listCandidateVersions(
        packument,
        effectiveRange,
        target
      );

      if (candidates.length === 0) {
        throw new Error(
          `no version of ${name} matches "${effectiveRange}" and target ${target.os}/${target.arch}/${target.libc}`
        );
      }

      let chosenRoot: string | undefined;
      let chosenVersion = "";
      let chosenMeta: any;
      let chosenTarball = "";

      for (const candidate of candidates) {
        const candidateRoot = path.join(work, `candidate-${candidate}`);
        const candidateTarball = path.join(work, `candidate-${candidate}.tgz`);
        await fs.mkdir(candidateRoot, { recursive: true });

        const candidateMeta = packument.versions[candidate];

        await trace.step(
          "registry.tarball",
          { name, version: candidate },
          async () => {
            const value = await downloadTarball(
              candidateMeta.dist.tarball,
              candidateMeta.dist.integrity,
              candidateTarball
            );
            return {
              value,
              summary: `${candidate}: ${value.bytes} bytes, integrity ${
                value.verified ? "verified" : "not provided"
              }`,
            };
          }
        );

        await trace.step(
          "archive.extract",
          { version: candidate },
          async () => {
            const value = await extractTarball(candidateTarball, candidateRoot);
            return {
              value,
              summary: `${candidate}: ${value.files} files, ${value.bytes} bytes, ${value.skipped} skipped`,
            };
          }
        );

        const candidatePkg = JSON.parse(
          await fs.readFile(path.join(candidateRoot, "package.json"), "utf8")
        );

        const usageCheck = await trace.step(
          "usage.check",
          {
            version: candidate,
            symbols: usage.symbols.length,
            subpaths: usage.subpaths.length,
          },
          async () => {
            const value = await checkUsage(candidateRoot, candidatePkg, usage);
            return {
              value,
              summary: value.ok
                ? `${candidate}: exports satisfy ${usage.symbols.length} symbol(s), ${usage.subpaths.length} subpath(s)`
                : `${candidate}: missing symbols=[${value.missingSymbols.join(
                    ","
                  )}] subpaths=[${value.missingSubpaths.join(",")}]`,
            };
          }
        );

        if (usageCheck.ok) {
          chosenRoot = candidateRoot;
          chosenVersion = candidate;
          chosenMeta = candidateMeta;
          chosenTarball = candidateTarball;
          break;
        }
      }

      if (!chosenRoot) {
        throw new Error(
          `no version of ${name} satisfies the project's usage (${usage.symbols.join(
            ", "
          ) || "no named symbols"})`
        );
      }

      root = chosenRoot;
      version = chosenVersion;
      meta = chosenMeta;
      tarballPath = chosenTarball;

      ledger.add({
        source: "registry",
        claim: "package.resolved",
        severity: "info",
        confidence: 1,
        message: `Resolved ${name}@${version} (requested "${range}", project usage ${usage.symbols.length} symbol(s))`,
        data: { version, integrity: meta.dist?.integrity ?? null },
      });
    }

    const pkg = JSON.parse(
      await fs.readFile(path.join(root, "package.json"), "utf8")
    );
    name = pkg.name ?? name;

    const index = await trace.step("index.build", {}, async () => {
      const value = await buildIndex(root, pkg);
      return {
        value,
        summary: `${value.length} files, ${
          value.filter((f) => f.kind === "elf").length
        } ELF, ${value.filter((f) => f.isEntry).length} entry points`,
      };
    });

    await trace.step("static.scan", {}, async () => {
      const value = await scanStatic(root, pkg, meta, index, ledger);
      return {
        value,
        summary: `${value.findings} findings, install scripts=${
          value.hasInstallScripts ? "yes" : "no"
        }, binding.gyp=${value.hasBindingGyp ? "yes" : "no"}`,
      };
    });

    const nativeFiles = index.filter(
      (f) => f.kind === "elf" || /\.(node|so|dylib|dll)$/i.test(f.rel)
    );
    const elfs: ElfInfo[] = [];

    for (const file of nativeFiles) {
      const info = await trace.step(
        "elf.inspect",
        { path: file.rel },
        async () => {
          const value = await inspectElf(root, file);
          recordElfEvidence(ledger, value);
          return {
            value,
            summary: `${value.arch} ${value.libc} glibc=${
              value.glibc ?? "?"
            } abi=${value.abi ?? "?"}${value.napi ? " napi" : ""}`,
          };
        }
      );
      elfs.push(info);
    }

    const sandboxImage =
      process.env.PREFLIGHT_SANDBOX_IMAGE ?? "preflight-sandbox:dev";
    const sandboxWork = path.join(work, "sandbox");
    await fs.mkdir(sandboxWork, { recursive: true });

    const sandbox = await trace.step(
      "sandbox.install_run",
      { image: sandboxImage, network: "install=bridge,run=none" },
      async () => {
        const value = await installAndDetonate({
          image: sandboxImage,
          work: sandboxWork,
          tarball: tarballPath,
          packageName: name,
          symbols: usage.symbols,
        });
        return {
          value,
          summary: value.ok
            ? `installed, import ok, network attempts=${value.networkAttempts}, canary hits=${value.canaryHits}`
            : `sandbox failed: ${
                value.logs.filter(Boolean).at(-1) ?? "unknown"
              }`,
        };
      }
    );

    if (!sandbox.installed) {
      ledger.add({
        source: "sandbox",
        claim: "sandbox.install_failed",
        severity: "high",
        confidence: 0.9,
        message: "Package could not be installed inside the sandbox",
      });
    }

    if (!sandbox.importOk) {
      ledger.add({
        source: "sandbox",
        claim: "sandbox.import_failed",
        severity: "critical",
        confidence: 0.9,
        message: "Package failed to load in the sandbox",
      });
    }

    for (const symbol of sandbox.missingSymbols) {
      ledger.add({
        source: "sandbox",
        claim: "sandbox.missing_symbol",
        severity: "critical",
        confidence: 1,
        message: `Project uses "${symbol}" but the installed package does not export it`,
      });
    }

    if (sandbox.networkAttempts > 0) {
      ledger.add({
        source: "sandbox",
        claim: "sandbox.network_attempt",
        severity: "high",
        confidence: 0.85,
        message: `Sandboxed code attempted network access ${sandbox.networkAttempts} time(s) with egress denied`,
      });
    }

    if (sandbox.canaryHits > 0) {
      ledger.add({
        source: "sandbox",
        claim: "sandbox.canary_hit",
        severity: "critical",
        confidence: 0.95,
        message: `Canary credential was read or written ${sandbox.canaryHits} time(s)`,
      });
    }

    if (!sandbox.rebuildOk) {
      ledger.add({
        source: "sandbox",
        claim: "sandbox.scripts_failed",
        severity: "medium",
        confidence: 0.7,
        message: "Lifecycle scripts failed under no-network rebuild",
      });
    }

    const transitive = await trace.step(
      "transitive.scan",
      { root: "node_modules" },
      async () => {
        const value = await scanTransitive(
          path.join(sandboxWork, "node_modules"),
          ledger,
          name
        );
        return {
          value,
          summary: `${value.packages} packages, ${value.suspicious} suspicious, ${value.scanned} deep-scanned`,
        };
      }
    );

    const osv: OsvResult = await trace.step(
      "osv.query",
      { package: name, version },
      async () => {
        const value = await queryOsv(name, version);
        return {
          value,
          summary: value.ok
            ? `${value.vulns.length} advisories`
            : `failed: ${value.error}`,
        };
      }
    );
    recordVulns(ledger, osv.vulns);

    const coverage: Coverage = {
      vulnChecked: osv.ok,
      nativeExpected: nativeFiles.length > 0,
      nativeInspected:
        nativeFiles.length === 0 ||
        (elfs.length === nativeFiles.length && elfs.every((e) => e.ok)),
      sandboxed: sandbox.ok,
      transitiveChecked: sandbox.installed,
    };

    const policy = evaluate({
      elfs,
      target,
      ledger,
      coverage,
      vulns: osv.vulns,
    });

    let recommended: string | undefined;
    if (policy.decision === "block" && osv.vulns.length > 0 && packument) {
      recommended = await trace.step(
        "osv.recommend",
        { name, current: version },
        async () => {
          const value = await recommendVersion(
            name,
            version,
            osv.vulns,
            packument
          );
          return {
            value,
            summary: value
              ? `${value} has no critical/high advisories`
              : "no clean version found",
          };
        }
      );
    }

    const status: Verdict["status"] =
      policy.decision === "allow" || policy.decision === "allow_with_warnings"
        ? "SAFE"
        : "VULNERABLE";

    const verdict: Verdict = {
      package: name,
      version,
      target,
      status,
      decision: policy.decision,
      riskScore: policy.riskScore,
      compatibility: policy.compatibility,
      recommendedVersion: recommended,
      evidence: ledger.all(),
      coverage,
      summary: "",
    };

    const explanation = await explain(verdict);
    verdict.summary = explanation.text;

    if (has("--status")) {
      console.log(JSON.stringify({ status }));
    } else if (has("--json")) {
      const payload: {
        status: Verdict["status"];
        verdict: Verdict;
        trace: typeof trace.steps;
        policy: PolicyRule[];
        explanation: { source: string; model: string };
      } = {
        status,
        verdict,
        trace: trace.steps,
        policy: policy.rules,
        explanation: {
          source: explanation.source,
          model: explanation.model,
        },
      };
      console.log(JSON.stringify(payload, null, 2));
    } else {
      printReport(verdict, trace, policy.rules, explanation.source);
    }
  } finally {
    await rmrf(work);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.stack ?? err.message : String(err));
  process.exit(1);
});
