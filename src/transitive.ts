import { promises as fs } from "node:fs";
import path from "node:path";
import { Ledger } from "./evidence.js";
import { buildIndex } from "./indexer.js";
import { scanStatic } from "./static.js";

export interface TransitiveResult {
  packages: number;
  suspicious: number;
  scanned: number;
}

const MAX_PACKAGES = 300;
const MAX_DEEP_SCAN = 25;

function hasLifecycleScripts(pkg: any): string[] {
  const found: string[] = [];
  for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
    if (typeof pkg.scripts?.[hook] === "string") found.push(hook);
  }
  return found;
}

async function findNative(dir: string, depth = 0): Promise<string[]> {
  if (depth > 3) return [];
  const out: string[] = [];
  const dirents = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
  for (const dirent of dirents) {
    if (out.length >= 5) break;
    if (dirent.name === "node_modules" || dirent.name === ".git") continue;
    const full = path.join(dir, dirent.name);
    if (dirent.isDirectory()) {
      out.push(...(await findNative(full, depth + 1)));
    } else if (
      /\.(node|so|dylib|dll)$/i.test(dirent.name) ||
      dirent.name === "binding.gyp"
    ) {
      out.push(full);
    }
  }
  return out;
}

function isRiskyScript(script: string): boolean {
  return /(curl|wget|https?:\/\/|base64|child_process|node\s+-e)/i.test(script);
}

export async function scanTransitive(
  nodeModules: string,
  ledger: Ledger,
  topPackage: string
): Promise<TransitiveResult> {
  let packages = 0;
  let suspicious = 0;
  let scanned = 0;

  async function walk(dir: string): Promise<void> {
    if (packages >= MAX_PACKAGES) return;

    const dirents = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const dirent of dirents) {
      if (packages >= MAX_PACKAGES) return;
      if (!dirent.isDirectory()) continue;
      if (dirent.name.startsWith(".")) continue;

      const full = path.join(dir, dirent.name);

      if (dirent.name.startsWith("@")) {
        await walk(full);
        continue;
      }

      const pkgJsonPath = path.join(full, "package.json");
      let pkg: any;
      try {
        pkg = JSON.parse(await fs.readFile(pkgJsonPath, "utf8"));
      } catch {
        // Not a package directory; keep walking for nested node_modules.
        await walk(full);
        continue;
      }

      packages++;
      const hooks = hasLifecycleScripts(pkg);
      const natives = await findNative(full);
      const topLevel = pkg.name === topPackage && dir.endsWith("node_modules");

      if (!topLevel && (hooks.length > 0 || natives.length > 0)) {
        suspicious++;

        for (const hook of hooks) {
          const script = String(pkg.scripts[hook]);
          ledger.add({
            source: "static",
            claim: "transitive.install_script",
            severity: isRiskyScript(script)
              ? "critical"
              : hook === "prepare"
                ? "low"
                : "high",
            confidence: 0.85,
            message: `${pkg.name}@${pkg.version} runs ${hook}: ${script}`,
            hard: isRiskyScript(script),
            data: { package: pkg.name, version: pkg.version, hook },
          });
        }

        if (natives.length > 0) {
          ledger.add({
            source: "static",
            claim: "transitive.native_binary",
            severity: "medium",
            confidence: 0.9,
            message: `${pkg.name}@${pkg.version} ships native artifacts: ${natives
              .slice(0, 3)
              .map((n) => path.relative(full, n))
              .join(", ")}`,
            data: { package: pkg.name, version: pkg.version },
          });
        }
      }

      if (!topLevel && scanned < MAX_DEEP_SCAN && (hooks.length > 0 || natives.length > 0)) {
        try {
          const index = await buildIndex(full, pkg);
          await scanStatic(
            full,
            pkg,
            { dist: { attestations: true } },
            index,
            ledger
          );
          scanned++;
        } catch {
          /* keep scanning the tree */
        }
      }

      const nested = path.join(full, "node_modules");
      try {
        await fs.access(nested);
        await walk(nested);
      } catch {
        /* no nested tree */
      }
    }
  }

  try {
    await walk(nodeModules);
  } catch {
    /* ignore */
  }

  return { packages, suspicious, scanned };
}
