import { promises as fs } from "node:fs";
import path from "node:path";
import { normalizeRel, readMagic, sha256Hex } from "./util.js";

export type FileKind =
  | "js"
  | "ts"
  | "json"
  | "shell"
  | "text"
  | "elf"
  | "wasm"
  | "image"
  | "other";

export interface FileEntry {
  rel: string;
  size: number;
  kind: FileKind;
  sha256?: string;
  isEntry: boolean;
  isNative: boolean;
}

const MAX_FILES = 8_000;
const MAX_FILE = 50 * 1024 * 1024;
const MAX_HASH_FILE = 5 * 1024 * 1024;

function collectEntryPaths(pkg: any): Set<string> {
  const out = new Set<string>();

  const add = (value: unknown): void => {
    if (typeof value === "string") {
      out.add(normalizeRel(value));
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) add(item);
      return;
    }
    if (value && typeof value === "object") {
      for (const item of Object.values(value)) add(item);
    }
  };

  add(pkg.main);
  add(pkg.module);
  add(pkg.browser);
  add(pkg.exports);
  add(pkg.bin);
  return out;
}

function kindOf(rel: string, magic: Buffer): FileKind {
  if (
    magic.length >= 4 &&
    magic[0] === 0x7f &&
    magic[1] === 0x45 &&
    magic[2] === 0x4c &&
    magic[3] === 0x46
  ) {
    return "elf";
  }
  if (magic.length >= 4 && magic.toString("ascii", 0, 4) === "\0asm") {
    return "wasm";
  }

  const ext = path.extname(rel).toLowerCase();
  if (ext === ".json") return "json";
  if ([".js", ".mjs", ".cjs", ".jsx"].includes(ext)) return "js";
  if ([".ts", ".tsx", ".mts", ".cts"].includes(ext)) return "ts";
  if ([".sh", ".bash", ".zsh"].includes(ext)) return "shell";
  if ([".md", ".txt", ".yml", ".yaml", ".toml", ".ini"].includes(ext)) {
    return "text";
  }
  if ([".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico"].includes(ext)) {
    return "image";
  }
  return "other";
}

function nativeByPath(rel: string, kind: FileKind): boolean {
  if (kind === "elf") return true;
  if (/\.(node|so|dylib|dll)$/i.test(rel)) return true;
  if (rel.includes("prebuilds/")) return true;
  if (rel.endsWith("binding.gyp")) return true;
  return false;
}

export async function buildIndex(root: string, pkg: any): Promise<FileEntry[]> {
  const entries: FileEntry[] = [];
  const entryPaths = collectEntryPaths(pkg);

  async function walk(dir: string, relBase = ""): Promise<void> {
    if (entries.length >= MAX_FILES) return;

    const dirents = await fs.readdir(dir, { withFileTypes: true });
    for (const dirent of dirents) {
      if (entries.length >= MAX_FILES) return;
      if (dirent.name === ".git") continue;

      const full = path.join(dir, dirent.name);
      const rel = relBase ? `${relBase}/${dirent.name}` : dirent.name;

      if (dirent.isDirectory()) {
        await walk(full, rel);
        continue;
      }
      if (!dirent.isFile()) continue;

      const stat = await fs.stat(full);
      if (stat.size > MAX_FILE) continue;

      const magic = await readMagic(full, 4);
      const kind = kindOf(rel, magic);
      const sha256 =
        stat.size <= MAX_HASH_FILE
          ? sha256Hex(await fs.readFile(full))
          : undefined;

      entries.push({
        rel,
        size: stat.size,
        kind,
        sha256,
        isEntry: entryPaths.has(normalizeRel(rel)),
        isNative: nativeByPath(rel, kind),
      });
    }
  }

  await walk(root);
  return entries;
}
