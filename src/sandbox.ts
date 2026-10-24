import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";

export interface SandboxOptions {
  image: string;
  work: string;
  tarball: string;
  packageName: string;
  symbols: string[];
  timeoutMs?: number;
}

export interface SandboxResult {
  ok: boolean;
  installed: boolean;
  importOk: boolean;
  missingSymbols: string[];
  rebuildOk: boolean;
  networkAttempts: number;
  canaryHits: number;
  permissionMode: "node-permission" | "none";
  logs: string[];
}

interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

function runDocker(args: string[], timeoutMs: number): Promise<RunResult> {
  return new Promise((resolve) => {
    const child = spawn("docker", args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut });
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({
        code: null,
        stdout,
        stderr: `${stderr}\n${err.message}`,
        timedOut,
      });
    });
  });
}

function uidArgs(): string[] {
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  const gid = typeof process.getgid === "function" ? process.getgid() : undefined;
  return uid !== undefined && gid !== undefined
    ? ["--user", `${uid}:${gid}`]
    : [];
}

const NETWORK_ERROR = /EAI_AGAIN|ENOTFOUND|ENETUNREACH|ECONNREFUSED|getaddrinfo/i;

export async function installAndDetonate(
  options: SandboxOptions
): Promise<SandboxResult> {
  const { image, work, tarball, packageName, symbols } = options;
  const timeoutMs = options.timeoutMs ?? 120_000;

  const logs: string[] = [];

  const tarballInWork = path.join(work, "package.tgz");
  await fs.copyFile(tarball, tarballInWork);

  const harnessPkg = path.join(work, "package.json");
  await fs.writeFile(
    harnessPkg,
    JSON.stringify(
      { name: "preflight-harness", version: "0.0.0", private: true },
      null,
      2
    )
  );

  // Phase 1: install without lifecycle scripts. Network is allowed here only
  // for the registry and dependency tarballs.
  const install = await runDocker(
    [
      "run",
      "--rm",
      "--network",
      "bridge",
      "-v",
      `${work}:/work`,
      "-w",
      "/work",
      "-e",
      "HOME=/tmp",
      ...uidArgs(),
      image,
      "npm",
      "install",
      "./package.tgz",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
    ],
    timeoutMs
  );
  logs.push(`install: exit=${install.code} timedOut=${install.timedOut}`);
  logs.push(install.stdout.trim());
  logs.push(install.stderr.trim());

  const installed = install.code === 0;
  if (!installed) {
    return {
      ok: false,
      installed: false,
      importOk: false,
      missingSymbols: [],
      rebuildOk: false,
      networkAttempts: NETWORK_ERROR.test(install.stderr) ? 1 : 0,
      canaryHits: 0,
      permissionMode: "none",
      logs,
    };
  }

  // Phase 2: import the package with no network and a fake home.
  const fakeHome = path.join(work, "fake-home");
  await fs.mkdir(fakeHome, { recursive: true });
  await fs.writeFile(
    path.join(fakeHome, ".npmrc"),
    "//registry.npmjs.org/:_authToken=PREFLIGHT_CANARY_TOKEN\n"
  );
  await fs.mkdir(path.join(fakeHome, ".ssh"), { recursive: true });
  await fs.writeFile(
    path.join(fakeHome, ".ssh", "id_rsa"),
    "PREFLIGHT_CANARY_SSH\n"
  );

  const harness = path.join(work, "harness.cjs");
  await fs.writeFile(
    harness,
    `const name = process.env.PKG_NAME;
const required = JSON.parse(process.env.PKG_SYMBOLS || "[]");
(async () => {
  let mod;
  try {
    mod = require(name);
  } catch (err) {
    try {
      mod = await import(name);
    } catch (err2) {
      console.error("REQUIRE_FAIL", err && err.message, err2 && err2.message);
      process.exit(3);
    }
  }
  const missing = required.filter((s) => !(s in mod));
  if (missing.length) {
    console.log("MISSING:" + missing.join(","));
    process.exit(2);
  }
  console.log("IMPORT_OK");
})();
`
  );

  const canary = `PREFLIGHT_CANARY_${randomBytes(8).toString("hex")}`;
  const baseRun = [
    "run",
    "--rm",
    "--network",
    "none",
    "-v",
    `${work}:/work`,
    "-w",
    "/work",
    "-e",
    "HOME=/work/fake-home",
    "-e",
    `PKG_NAME=${packageName}`,
    "-e",
    `PKG_SYMBOLS=${JSON.stringify(symbols)}`,
    "-e",
    `PREFLIGHT_CANARY=${canary}`,
    ...uidArgs(),
    image,
  ];

  let detonation = await runDocker(
    [
      ...baseRun,
      "node",
      "--permission",
      "--allow-fs-read=/work",
      "harness.cjs",
    ],
    timeoutMs
  );

  let permissionMode: "node-permission" | "none" = "node-permission";
  if (/ERR_ACCESS_DENIED|SecurityError|permission/i.test(detonation.stderr)) {
    permissionMode = "none";
    detonation = await runDocker([...baseRun, "node", "harness.cjs"], timeoutMs);
  }

  const detonationText = `${detonation.stdout}\n${detonation.stderr}`;
  const missingMatch = /MISSING:(.+)/.exec(detonation.stdout);
  const missingSymbols = missingMatch
    ? missingMatch[1].split(",").filter(Boolean)
    : [];
  const importOk = /IMPORT_OK/.test(detonation.stdout) && detonation.code === 0;

  logs.push(`detonate: exit=${detonation.code} timedOut=${detonation.timedOut}`);
  logs.push(detonationText.trim());

  // Phase 3: run lifecycle scripts with no network.
  const rebuild = await runDocker(
    [
      ...baseRun,
      "npm",
      "rebuild",
      "--foreground-scripts",
    ],
    timeoutMs
  );
  logs.push(`rebuild: exit=${rebuild.code} timedOut=${rebuild.timedOut}`);
  logs.push(`${rebuild.stdout}\n${rebuild.stderr}`.trim());

  const allText = [install.stderr, detonationText, rebuild.stdout, rebuild.stderr].join("\n");
  const networkAttempts = (allText.match(NETWORK_ERROR) ?? []).length;

  // Canary check: look for the fake token in files written outside node_modules.
  let canaryHits = 0;
  async function scanCanary(dir: string): Promise<void> {
    const dirents = await fs.readdir(dir, { withFileTypes: true });
    for (const dirent of dirents) {
      if (dirent.name === "node_modules") continue;
      if (dirent.name === "fake-home") continue;
      const full = path.join(dir, dirent.name);
      if (dirent.isDirectory()) {
        await scanCanary(full);
        continue;
      }
      if (!dirent.isFile()) continue;
      const stat = await fs.stat(full);
      if (stat.size > 2_000_000) continue;
      const text = await fs.readFile(full, "utf8").catch(() => "");
      if (text.includes(canary) || text.includes("PREFLIGHT_CANARY_TOKEN")) {
        canaryHits++;
      }
    }
  }

  try {
    await scanCanary(work);
  } catch {
    /* ignore */
  }

  return {
    ok: installed && importOk,
    installed,
    importOk,
    missingSymbols,
    rebuildOk: rebuild.code === 0,
    networkAttempts,
    canaryHits,
    permissionMode,
    logs,
  };
}
