import { promises as fs } from "node:fs";
import path from "node:path";

export interface UsageContract {
  packageName: string;
  range: string;
  symbols: string[];
  subpaths: string[];
  defaultImport: boolean;
  namespaceImport: boolean;
  files: string[];
}

export interface UsageCheck {
  ok: boolean;
  entry?: string;
  missingSymbols: string[];
  missingSubpaths: string[];
  error?: string;
}

const SOURCE_EXT = new Set([
  ".js",
  ".mjs",
  ".cjs",
  ".jsx",
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
]);

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  ".nuxt",
  "out",
  "vendor",
]);

const MAX_FILES = 2_000;
const MAX_FILE = 1_500_000;

function escapeRe(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function parseNamedList(list: string): string[] {
  return list
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => {
      const parts = item.split(/\s+as\s+/);
      return (parts[0] ?? item).replace(/^type\s+/, "").trim();
    })
    .filter((item) => item && item !== "default");
}

export async function analyzeProject(
  projectDir: string,
  packageName: string
): Promise<UsageContract> {
  const pkgJson = JSON.parse(
    await fs.readFile(path.join(projectDir, "package.json"), "utf8")
  );

  const range =
    pkgJson.dependencies?.[packageName] ??
    pkgJson.devDependencies?.[packageName] ??
    pkgJson.peerDependencies?.[packageName] ??
    "latest";

  const symbols = new Set<string>();
  const subpaths = new Set<string>();
  const files: string[] = [];
  let defaultImport = false;
  let namespaceImport = false;

  const addSpecifier = (spec: string): boolean => {
    if (spec === packageName) return true;
    if (spec.startsWith(`${packageName}/`)) {
      subpaths.add(`./${spec.slice(packageName.length + 1)}`);
      return true;
    }
    return false;
  };

  async function walk(dir: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    const dirents = await fs.readdir(dir, { withFileTypes: true });

    for (const dirent of dirents) {
      if (files.length >= MAX_FILES) return;
      if (dirent.name.startsWith(".") && dirent.name !== ".") continue;
      if (SKIP_DIRS.has(dirent.name)) continue;

      const full = path.join(dir, dirent.name);
      if (dirent.isDirectory()) {
        await walk(full);
        continue;
      }
      if (!dirent.isFile()) continue;
      if (!SOURCE_EXT.has(path.extname(dirent.name))) continue;

      const stat = await fs.stat(full);
      if (stat.size > MAX_FILE) continue;

      const text = await fs.readFile(full, "utf8");
      files.push(path.relative(projectDir, full));

      // import ... from "pkg"
      for (const match of text.matchAll(
        /\bimport\s+([^;]*?)\s+from\s+["']([^"']+)["']/g
      )) {
        const clause = match[1]?.trim() ?? "";
        const spec = match[2];
        if (!addSpecifier(spec)) continue;

        if (/\*\s+as\s+/.test(clause)) namespaceImport = true;
        const named = clause.match(/\{([^}]*)\}/);
        if (named) {
          for (const name of parseNamedList(named[1])) symbols.add(name);
        } else if (clause && !clause.startsWith("{")) {
          defaultImport = true;
        }
      }

      // import "pkg"
      for (const match of text.matchAll(/\bimport\s+["']([^"']+)["']/g)) {
        addSpecifier(match[1]);
      }

      // require("pkg") and import("pkg")
      for (const match of text.matchAll(
        /\b(?:require|import)\s*\(\s*["']([^"']+)["']\s*\)/g
      )) {
        addSpecifier(match[1]);
      }

      // const { a, b } = require("pkg")
      for (const match of text.matchAll(
        /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*["']([^"']+)["']\s*\)/g
      )) {
        if (!addSpecifier(match[2])) continue;
        for (const name of parseNamedList(match[1])) symbols.add(name);
      }

      // const x = require("pkg") / import ... as x
      for (const match of text.matchAll(
        /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']([^"']+)["']\s*\)/g
      )) {
        if (!addSpecifier(match[2])) continue;
        const local = match[1];
        namespaceImport = true;
        for (const access of text.matchAll(
          new RegExp(`\\b${escapeRe(local)}\\.([A-Za-z_$][\\w$]*)`, "g")
        )) {
          symbols.add(access[1]);
        }
      }

      // require("pkg").foo
      for (const match of text.matchAll(
        /\brequire\s*\(\s*["']([^"']+)["']\s*\)\.([A-Za-z_$][\w$]*)/g
      )) {
        if (addSpecifier(match[1])) symbols.add(match[2]);
      }
    }
  }

  await walk(projectDir);

  return {
    packageName,
    range,
    symbols: [...symbols].sort(),
    subpaths: [...subpaths].sort(),
    defaultImport,
    namespaceImport,
    files: files.sort(),
  };
}

function resolveConditional(value: any, conditions: string[]): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    for (const item of value) {
      const resolved = resolveConditional(item, conditions);
      if (resolved) return resolved;
    }
    return undefined;
  }
  if (value && typeof value === "object") {
    for (const condition of conditions) {
      if (condition in value) {
        const resolved = resolveConditional(value[condition], conditions);
        if (resolved) return resolved;
      }
    }
  }
  return undefined;
}

function resolveExportTarget(
  exportsField: any,
  subpath: string
): string | undefined {
  const conditions = ["require", "import", "node", "default"];

  if (typeof exportsField === "string") {
    return subpath === "." ? exportsField : undefined;
  }
  if (!exportsField || typeof exportsField !== "object") return undefined;

  if (subpath in exportsField) {
    return resolveConditional(exportsField[subpath], conditions);
  }

  // Root conditional exports: { require: ..., import: ... }
  if (!Object.keys(exportsField).some((key) => key.startsWith("."))) {
    return subpath === "."
      ? resolveConditional(exportsField, conditions)
      : undefined;
  }

  return undefined;
}

async function fileExists(file: string): Promise<boolean> {
  try {
    await fs.access(file);
    return true;
  } catch {
    return false;
  }
}

async function findEntry(
  pkgDir: string,
  manifest: any
): Promise<string | undefined> {
  const candidates: string[] = [];

  if (manifest.exports) {
    const target = resolveExportTarget(manifest.exports, ".");
    if (target) candidates.push(target);
  }

  if (typeof manifest.module === "string") candidates.push(manifest.module);
  if (typeof manifest.main === "string") candidates.push(manifest.main);
  candidates.push("index.js", "index.mjs", "index.cjs");

  for (const candidate of candidates) {
    const full = path.join(pkgDir, candidate);
    if (await fileExists(full)) return candidate;
  }

  return undefined;
}

async function resolveSubpath(
  pkgDir: string,
  manifest: any,
  subpath: string
): Promise<boolean> {
  if (manifest.exports) {
    const target = resolveExportTarget(manifest.exports, subpath);
    if (target) {
      return fileExists(path.join(pkgDir, target));
    }
    return false;
  }

  const relative = subpath.replace(/^\.\//, "");
  const candidates = [
    relative,
    `${relative}.js`,
    `${relative}.mjs`,
    `${relative}.cjs`,
    path.join(relative, "index.js"),
  ];

  for (const candidate of candidates) {
    if (await fileExists(path.join(pkgDir, candidate))) return true;
  }
  return false;
}

function hasSymbol(source: string, symbol: string): boolean {
  const s = escapeRe(symbol);
  const patterns = [
    new RegExp(`\\bexports\\.${s}\\s*=`),
    new RegExp(`\\bmodule\\.exports\\.${s}\\s*=`),
    new RegExp(`\\bexport\\s+(?:async\\s+)?function\\s+${s}\\b`),
    new RegExp(`\\bexport\\s+(?:const|let|var|class)\\s+${s}\\b`),
    new RegExp(`\\bexport\\s*\\{[^}]*\\b${s}\\b[^}]*\\}`),
    new RegExp(`\\bmodule\\.exports\\s*=\\s*\\{[^}]*\\b${s}\\b`, "s"),
  ];
  return patterns.some((re) => re.test(source));
}

export async function checkUsage(
  pkgDir: string,
  manifest: any,
  usage: UsageContract
): Promise<UsageCheck> {
  const missingSymbols: string[] = [];
  const missingSubpaths: string[] = [];

  for (const subpath of usage.subpaths) {
    if (!(await resolveSubpath(pkgDir, manifest, subpath))) {
      missingSubpaths.push(subpath);
    }
  }

  const entry = await findEntry(pkgDir, manifest);
  if (!entry) {
    return {
      ok: false,
      missingSymbols: [...usage.symbols],
      missingSubpaths,
      error: "no resolvable entry point",
    };
  }

  let source = "";
  try {
    source = await fs.readFile(path.join(pkgDir, entry), "utf8");
  } catch (err) {
    return {
      ok: false,
      entry,
      missingSymbols: [...usage.symbols],
      missingSubpaths,
      error: (err as Error).message,
    };
  }

  for (const symbol of usage.symbols) {
    if (!hasSymbol(source, symbol)) missingSymbols.push(symbol);
  }

  if (usage.defaultImport && !/export\s+default|module\.exports\s*=/.test(source)) {
    missingSymbols.push("default");
  }

  return {
    ok: missingSymbols.length === 0 && missingSubpaths.length === 0,
    entry,
    missingSymbols,
    missingSubpaths,
  };
}
