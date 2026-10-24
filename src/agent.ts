import { promises as fs } from "node:fs";
import path from "node:path";
import { listCandidateVersions } from "./candidates.js";
import { inspectElf, recordElfEvidence, type ElfInfo } from "./elf.js";
import { extractTarball } from "./extract.js";
import { Ledger } from "./evidence.js";
import {
  GemmaClient,
  GemmaUnavailableError,
  type GemmaFunctionCall,
  type GemmaTool,
} from "./gemma-client.js";
import { buildIndex, type FileEntry } from "./indexer.js";
import { queryOsv, recordVulns } from "./osv.js";
import { checkCompatibility, evaluate, type PolicyRule } from "./policy.js";
import {
  downloadTarball,
  fetchPackument,
  type Packument,
} from "./registry.js";
import { installAndDetonate, type SandboxResult } from "./sandbox.js";
import { scanStatic } from "./static.js";
import { scanTransitive, type TransitiveResult } from "./transitive.js";
import { Trace } from "./trace.js";
import type { Coverage, Target, Verdict, Vulnerability } from "./types.js";
import { checkUsage, type UsageContract } from "./usage.js";
import { mkdtemp, rmrf } from "./util.js";

interface Prepared {
  version: string;
  root: string;
  tarball: string;
  meta: any;
  pkg: any;
  index: FileEntry[];
  nativeFiles: FileEntry[];
  elfs: ElfInfo[];
  usageOk: boolean;
  missingSymbols: string[];
  missingSubpaths: string[];
}

export interface AgentInput {
  name: string;
  range: string;
  target: Target;
  usage: UsageContract;
}

export interface AgentResult {
  verdict: Verdict;
  trace: Trace;
  policy: PolicyRule[];
  explanation: { text: string; source: "gemma"; model: string };
}

class ScanSession {
  readonly ledger = new Ledger();
  readonly trace = new Trace();
  readonly prepared = new Map<string, Prepared>();
  readonly vulns = new Map<string, Vulnerability[]>();
  readonly vulnChecked = new Map<string, boolean>();
  readonly sandboxes = new Map<string, SandboxResult>();
  readonly transitive = new Map<string, TransitiveResult>();

  private packument?: Packument;
  private work!: string;
  currentVersion?: string;
  final?: { status: "SAFE" | "VULNERABLE"; reason: string; version?: string };

  private constructor(
    readonly name: string,
    readonly range: string,
    readonly target: Target,
    readonly usage: UsageContract
  ) {}

  static async create(input: AgentInput): Promise<ScanSession> {
    const session = new ScanSession(
      input.name,
      input.range,
      input.target,
      input.usage
    );
    session.work = await mkdtemp();
    return session;
  }

  async close(): Promise<void> {
    await rmrf(this.work);
  }

  private async getPackument(): Promise<Packument> {
    if (!this.packument) {
      this.packument = await fetchPackument(this.name);
    }
    return this.packument;
  }

  async resolveVersions(range = this.range): Promise<string[]> {
    const packument = await this.getPackument();
    const effective = range === "latest" ? this.usage.range : range;
    return listCandidateVersions(packument, effective, this.target, 6);
  }

  async prepare(version: string): Promise<Record<string, unknown>> {
    const cached = this.prepared.get(version);
    if (cached) {
      this.currentVersion = version;
      return this.preparedSummary(cached);
    }

    const packument = await this.getPackument();
    const meta = packument.versions[version];
    if (!meta) throw new Error(`version ${version} does not exist`);

    const root = path.join(this.work, `v-${version}`);
    const tarball = path.join(this.work, `v-${version}.tgz`);
    await fs.mkdir(root, { recursive: true });

    await downloadTarball(meta.dist.tarball, meta.dist.integrity, tarball);
    await extractTarball(tarball, root);

    const pkg = JSON.parse(
      await fs.readFile(path.join(root, "package.json"), "utf8")
    );
    const index = await buildIndex(root, pkg);
    await scanStatic(root, pkg, meta, index, this.ledger);

    const nativeFiles = index.filter(
      (file) => file.kind === "elf" || /\.(node|so|dylib|dll)$/i.test(file.rel)
    );
    const elfs: ElfInfo[] = [];
    for (const file of nativeFiles) {
      const info = await inspectElf(root, file);
      recordElfEvidence(this.ledger, info);
      elfs.push(info);
    }

    const usageCheck = await checkUsage(root, pkg, this.usage);

    const prepared: Prepared = {
      version,
      root,
      tarball,
      meta,
      pkg,
      index,
      nativeFiles,
      elfs,
      usageOk: usageCheck.ok,
      missingSymbols: usageCheck.missingSymbols,
      missingSubpaths: usageCheck.missingSubpaths,
    };

    this.prepared.set(version, prepared);
    this.currentVersion = version;
    return this.preparedSummary(prepared);
  }

  private preparedSummary(prepared: Prepared): Record<string, unknown> {
    const findings = this.ledger
      .all()
      .filter((e) => e.file?.startsWith(`${prepared.version}/`) || e.source === "static");
    return {
      version: prepared.version,
      usageOk: prepared.usageOk,
      missingSymbols: prepared.missingSymbols,
      files: prepared.index.length,
      nativeArtifacts: prepared.nativeFiles.length,
      entry: prepared.pkg.main ?? prepared.pkg.module ?? "index.js",
      evidence: findings.slice(-12).map((e) => e.id),
    };
  }

  async checkVulnerabilities(
    version: string
  ): Promise<Record<string, unknown>> {
    this.currentVersion = version;
    const result = await queryOsv(this.name, version);
    recordVulns(this.ledger, result.vulns);
    this.vulns.set(version, result.vulns);
    this.vulnChecked.set(version, result.ok);
    this.currentVersion = version;

    return {
      version,
      ok: result.ok,
      total: result.vulns.length,
      critical: result.vulns.filter((v) => v.severity === "critical").length,
      high: result.vulns.filter((v) => v.severity === "high").length,
      evidence: this.ledger
        .all()
        .filter((e) => e.source === "osv")
        .slice(-10)
        .map((e) => e.id),
    };
  }

  async detonate(version: string): Promise<Record<string, unknown>> {
    await this.prepare(version);
    const sandboxWork = path.join(this.work, `sandbox-${version}`);
    await fs.mkdir(sandboxWork, { recursive: true });

    const sandbox = await installAndDetonate({
      image: process.env.PREFLIGHT_SANDBOX_IMAGE ?? "preflight-sandbox:dev",
      work: sandboxWork,
      tarball: path.join(this.work, `v-${version}.tgz`),
      packageName: this.name,
      symbols: this.usage.symbols,
    });

    this.sandboxes.set(version, sandbox);
    this.currentVersion = version;

    if (!sandbox.installed) {
      this.ledger.add({
        source: "sandbox",
        claim: "sandbox.install_failed",
        severity: "high",
        confidence: 0.9,
        message: `Package ${version} could not be installed in the sandbox`,
      });
    }
    if (!sandbox.importOk) {
      this.ledger.add({
        source: "sandbox",
        claim: "sandbox.import_failed",
        severity: "critical",
        confidence: 0.9,
        hard: true,
        message: `Package ${version} failed to load in the sandbox`,
      });
    }
    for (const symbol of sandbox.missingSymbols) {
      this.ledger.add({
        source: "sandbox",
        claim: "sandbox.missing_symbol",
        severity: "critical",
        confidence: 1,
        hard: true,
        message: `Project uses "${symbol}" but the installed ${version} does not export it`,
      });
    }
    if (sandbox.networkAttempts > 0) {
      this.ledger.add({
        source: "sandbox",
        claim: "sandbox.network_attempt",
        severity: "high",
        confidence: 0.85,
        hard: true,
        message: `Sandboxed ${version} attempted network access with egress denied`,
      });
    }
    if (sandbox.canaryHits > 0) {
      this.ledger.add({
        source: "sandbox",
        claim: "sandbox.canary_hit",
        severity: "critical",
        confidence: 0.95,
        hard: true,
        message: `Canary credential was read or written by ${version}`,
      });
    }

    return {
      version,
      installed: sandbox.installed,
      importOk: sandbox.importOk,
      missingSymbols: sandbox.missingSymbols,
      networkAttempts: sandbox.networkAttempts,
      canaryHits: sandbox.canaryHits,
      permissionMode: sandbox.permissionMode,
    };
  }

  async scanTransitive(version: string): Promise<Record<string, unknown>> {
    const sandbox = this.sandboxes.get(version);
    if (!sandbox) throw new Error(`detonate ${version} before scanning transitive deps`);

    const nodeModules = path.join(this.work, `sandbox-${version}`, "node_modules");
    const result = await scanTransitive(nodeModules, this.ledger, this.name);
    this.transitive.set(version, result);
    this.currentVersion = version;

    return {
      version,
      packages: result.packages,
      suspicious: result.suspicious,
      deepScanned: result.scanned,
    };
  }

  finalize(status: "SAFE" | "VULNERABLE", reason: string, version?: string): void {
    this.final = { status, reason, version };
    if (version) this.currentVersion = version;
  }

  evaluate(version: string): { verdict: Verdict; policy: ReturnType<typeof evaluate> } {
    const prepared = this.prepared.get(version);
    if (!prepared) throw new Error(`version ${version} was never verified`);

    if (!prepared.usageOk) {
      for (const symbol of prepared.missingSymbols) {
        this.ledger.add({
          source: "static",
          claim: "api.missing_symbol",
          severity: "high",
          confidence: 1,
          hard: false,
          message: `Project uses "${symbol}" but ${version} does not export it`,
          data: { version, symbol },
        });
      }
      for (const subpath of prepared.missingSubpaths) {
        this.ledger.add({
          source: "static",
          claim: "api.missing_subpath",
          severity: "high",
          confidence: 1,
          hard: false,
          message: `Project imports "${subpath}" but ${version} does not provide it`,
          data: { version, subpath },
        });
      }
    }

    const vulns = this.vulns.get(version) ?? [];
    const sandbox = this.sandboxes.get(version);
    const transitive = this.transitive.get(version);

    const compatibility = checkCompatibility(prepared.elfs, this.target);
    const coverage: Coverage = {
      vulnChecked: this.vulnChecked.get(version) ?? false,
      nativeExpected: prepared.nativeFiles.length > 0,
      nativeInspected:
        prepared.nativeFiles.length === 0 ||
        (prepared.elfs.length === prepared.nativeFiles.length &&
          prepared.elfs.every((elf) => elf.ok)),
      sandboxed: sandbox?.ok ?? false,
      transitiveChecked: transitive !== undefined,
    };

    const policy = evaluate({
      elfs: prepared.elfs,
      target: this.target,
      ledger: this.ledger,
      coverage,
      vulns,
    });

    const status: Verdict["status"] =
      policy.decision === "allow" || policy.decision === "allow_with_warnings"
        ? "SAFE"
        : "VULNERABLE";

    const verdict: Verdict = {
      package: this.name,
      version,
      target: this.target,
      status,
      decision: policy.decision,
      riskScore: policy.riskScore,
      compatibility: policy.compatibility,
      evidence: this.ledger.all(),
      coverage,
      summary: this.final?.reason ?? "Policy verdict applied after Gemma tool run.",
    };

    return { verdict, policy };
  }
}

function normalizeToolName(name: string): string {
  const idx = name.lastIndexOf(":");
  return idx >= 0 ? name.slice(idx + 1) : name;
}

function summarize(tool: string, value: Record<string, unknown>): string {
  switch (tool) {
    case "get_target":
      return `${String(value.os)}/${String(value.arch)} ${String(
        value.libc
      )} ${String(value.libcVersion)} node ${String(value.node)} ABI ${String(
        value.abi
      )}`;
    case "get_project_usage":
      return `${(value.symbols as string[] | undefined)?.length ?? 0} symbols, range ${String(
        value.range
      )}`;
    case "resolve_versions":
      return `${(value.versions as string[] | undefined)?.length ?? 0} candidates`;
    case "verify_version":
      return `usageOk=${String(value.usageOk)}, native=${String(
        value.nativeArtifacts
      )}, files=${String(value.files)}`;
    case "check_vulnerabilities":
      return `${String(value.total)} advisories (${String(
        value.critical
      )} critical, ${String(value.high)} high)`;
    case "detonate_version":
      return `installed=${String(value.installed)}, importOk=${String(
        value.importOk
      )}, canary=${String(value.canaryHits)}`;
    case "scan_transitive":
      return `${String(value.packages)} packages, ${String(
        value.suspicious
      )} suspicious`;
    case "finalize":
      return `status=${String(value.status)}`;
    default:
      return value.error ? `error: ${String(value.error)}` : "ok";
  }
}

async function dispatch(
  call: GemmaFunctionCall,
  session: ScanSession
): Promise<Record<string, unknown>> {
  const tool = normalizeToolName(call.name);
  switch (tool) {
    case "get_target":
      return { ...session.target };
    case "get_project_usage":
      return {
        range: session.usage.range,
        symbols: session.usage.symbols,
        subpaths: session.usage.subpaths,
        files: session.usage.files.length,
      };
    case "resolve_versions":
      return {
        versions: await session.resolveVersions(
          typeof call.args.range === "string" ? call.args.range : session.range
        ),
      };
    case "verify_version":
      return await session.prepare(String(call.args.version));
    case "check_vulnerabilities":
      return await session.checkVulnerabilities(String(call.args.version));
    case "detonate_version":
      return await session.detonate(String(call.args.version));
    case "scan_transitive":
      return await session.scanTransitive(String(call.args.version));
    case "finalize": {
      const status = call.args.status === "SAFE" ? "SAFE" : "VULNERABLE";
      session.finalize(
        status,
        String(call.args.reason ?? ""),
        typeof call.args.version === "string" ? call.args.version : undefined
      );
      return { accepted: true, status };
    }
    default:
      return { error: `unknown tool: ${call.name}` };
  }
}

const TOOLS: GemmaTool[] = [
  {
    name: "get_target",
    description: "Return the target OS, arch, libc, glibc version, Node version, and ABI.",
    parameters: { type: "OBJECT", properties: {} },
  },
  {
    name: "get_project_usage",
    description:
      "Return the symbols, subpaths, and requested range that the local project actually uses from this package.",
    parameters: { type: "OBJECT", properties: {} },
  },
  {
    name: "resolve_versions",
    description:
      "List candidate versions matching a semver range and target constraints, newest first.",
    parameters: {
      type: "OBJECT",
      properties: {
        range: { type: "STRING", description: "Optional semver range" },
      },
    },
  },
  {
    name: "verify_version",
    description:
      "Download and statically inspect one version: usage/API check, lifecycle scripts, code sinks, native ELF/ABI/glibc. Returns usageOk and evidence.",
    parameters: {
      type: "OBJECT",
      properties: {
        version: { type: "STRING" },
      },
      required: ["version"],
    },
  },
  {
    name: "check_vulnerabilities",
    description:
      "Query OSV for known advisories for one version and return counts by severity.",
    parameters: {
      type: "OBJECT",
      properties: {
        version: { type: "STRING" },
      },
      required: ["version"],
    },
  },
  {
    name: "detonate_version",
    description:
      "Install the version in Docker with scripts disabled, import it with no network, fake HOME, canary credentials, and run lifecycle scripts with egress denied.",
    parameters: {
      type: "OBJECT",
      properties: {
        version: { type: "STRING" },
      },
      required: ["version"],
    },
  },
  {
    name: "scan_transitive",
    description:
      "Scan the installed transitive dependency tree for install scripts, native binaries, and suspicious code. Requires detonate_version first.",
    parameters: {
      type: "OBJECT",
      properties: {
        version: { type: "STRING" },
      },
      required: ["version"],
    },
  },
  {
    name: "finalize",
    description:
      "Finish the investigation. SAFE only if usageOk, no critical advisories, import ok, no canary/network findings, and transitive scan is clean. Otherwise VULNERABLE.",
    parameters: {
      type: "OBJECT",
      properties: {
        status: { type: "STRING", enum: ["SAFE", "VULNERABLE"] },
        reason: { type: "STRING" },
        version: { type: "STRING" },
      },
      required: ["status", "reason"],
    },
  },
];

const SYSTEM = `You are Preflight, an npm supply-chain verification agent.
Use the tools; never invent facts.
Workflow:
1. Call get_target and get_project_usage.
2. Call resolve_versions.
3. Call verify_version from newest to oldest until usageOk=true.
4. For the chosen version, call check_vulnerabilities, detonate_version, and scan_transitive.
5. Call finalize.

Choose SAFE only when usageOk=true, there are no critical advisories,
the sandbox import succeeded, no canary or network findings were reported,
and the transitive scan found nothing suspicious.
Choose VULNERABLE when any hard check fails or evidence is incomplete.
If a version is missing a used API, try the next older version.
Keep tool arguments exact. Do not call finalize before verify_version and check_vulnerabilities.`;

export async function runGemmaAgent(input: AgentInput): Promise<AgentResult> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new GemmaUnavailableError("GEMINI_API_KEY is not set");

  const session = await ScanSession.create(input);
  const client = new GemmaClient(apiKey);

  const contents: any[] = [
    {
      role: "user",
      parts: [
        {
          text: `Verify ${input.name} for range "${input.range}" on target ${JSON.stringify(
            input.target
          )}. The project uses ${JSON.stringify(
            input.usage.symbols
          )} from it. Investigate and finalize.`,
        },
      ],
    },
  ];

  try {
    for (let step = 0; step < 10; step++) {
      const response = await client.generate(contents, TOOLS, SYSTEM);

      if (response.functionCalls.length > 0) {
        contents.push({
          role: "model",
          parts: response.functionCalls.map((call) => ({ functionCall: call })),
        });

        const responses: any[] = [];
        for (const call of response.functionCalls) {
          const toolName = normalizeToolName(call.name);
          const result = await session.trace.step(
            toolName,
            call.args,
            async () => {
              const value = await dispatch({ ...call, name: toolName }, session);
              return { value, summary: summarize(toolName, value) };
            }
          );
          responses.push({
            functionResponse: { name: call.name, response: result },
          });
        }

        contents.push({ role: "user", parts: responses });
        if (session.final) break;
        continue;
      }

      if (response.text) {
        contents.push({
          role: "model",
          parts: [{ text: response.text }],
        });

        const match = /\b(SAFE|VULNERABLE)\b/.exec(response.text);
        if (match && !session.final) {
          session.finalize(
            match[1] as "SAFE" | "VULNERABLE",
            response.text.slice(0, 600),
            session.currentVersion
          );
        }
        break;
      }

      break;
    }

    const versions = await session.resolveVersions();
    const version =
      session.final?.version ??
      session.currentVersion ??
      versions[0];

    if (!version) {
      throw new Error("no candidate version available");
    }

    if (!session.prepared.has(version)) {
      await session.prepare(version);
    }

    const { verdict, policy } = session.evaluate(version);

    if (session.final?.status === "VULNERABLE" && verdict.status === "SAFE") {
      verdict.status = "VULNERABLE";
      verdict.decision = "review";
    }

    if (session.final?.reason) {
      verdict.summary = session.final.reason;
    }

    return {
      verdict,
      trace: session.trace,
      policy: policy.rules,
      explanation: {
        text: verdict.summary,
        source: "gemma",
        model: process.env.GEMMA_MODEL ?? "gemma-4-26b-a4b-it",
      },
    };
  } finally {
    await session.close();
  }
}
