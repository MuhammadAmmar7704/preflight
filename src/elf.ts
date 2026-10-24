import path from "node:path";
import { Ledger } from "./evidence.js";
import type { FileEntry } from "./indexer.js";
import { maxVersion, run } from "./util.js";

export interface ElfInfo {
  ok: boolean;
  rel: string;
  error?: string;
  fileType: string;
  arch: "x64" | "arm64" | "unknown";
  libc: "glibc" | "musl" | "unknown";
  glibc?: string;
  glibcxx?: string;
  cxxabi?: string;
  abi?: number;
  napi: boolean;
  needed: string[];
  interpreter?: string;
  isa?: string;
}

function archOf(fileType: string): ElfInfo["arch"] {
  if (fileType.includes("aarch64")) return "arm64";
  if (fileType.includes("x86-64")) return "x64";
  return "unknown";
}

function collectVersions(text: string, prefix: string): string[] {
  return [...text.matchAll(new RegExp(`${prefix}_([0-9.]+)`, "g"))].map(
    (m) => m[1]
  );
}

export async function inspectElf(
  root: string,
  entry: FileEntry
): Promise<ElfInfo> {
  const full = path.join(root, entry.rel);

  const file = await run("file", ["-b", full]);
  if (!file.ok) {
    return {
      ok: false,
      rel: entry.rel,
      error: `file failed: ${file.stderr}`,
      fileType: "",
      arch: "unknown",
      libc: "unknown",
      napi: false,
      needed: [],
    };
  }

  const fileType = file.stdout.trim();

  const objdump = await run("objdump", ["-T", full]);
  const dynamic = objdump.stdout;

  const dynamicInfo = await run("readelf", ["-d", full]);
  const needed = [...dynamicInfo.stdout.matchAll(/NEEDED\s+\[(.*?)\]/g)].map(
    (m) => m[1]
  );

  const program = await run("readelf", ["-l", full]);
  const interpreter = /interpreter:\s*(\S+)/.exec(program.stdout)?.[1];

  const notes = await run("readelf", ["-n", full]);
  const isa = /x86 ISA needed:\s*([^\n]+)/.exec(notes.stdout)?.[1]?.trim();

  const symbols = await run("readelf", ["-sW", full]);
  const napi = /\bnapi_[a-z_]+/.test(symbols.stdout);

  const glibc = maxVersion(collectVersions(dynamic, "GLIBC"));
  const glibcxx = maxVersion(collectVersions(dynamic, "GLIBCXX"));
  const cxxabi = maxVersion(collectVersions(dynamic, "CXXABI"));

  const abiMatch = /(?:abi|node-v)(\d+)/.exec(entry.rel);
  const abi = abiMatch ? Number.parseInt(abiMatch[1], 10) : undefined;

  const libc: ElfInfo["libc"] =
    interpreter?.includes("musl") || fileType.includes("musl")
      ? "musl"
      : fileType.includes("ELF")
        ? "glibc"
        : "unknown";

  return {
    ok: objdump.ok,
    rel: entry.rel,
    error: objdump.ok ? undefined : objdump.stderr,
    fileType,
    arch: archOf(fileType),
    libc,
    glibc,
    glibcxx,
    cxxabi,
    abi,
    napi,
    needed,
    interpreter,
    isa,
  };
}

export function recordElfEvidence(ledger: Ledger, info: ElfInfo): void {
  if (!info.ok) {
    ledger.add({
      source: "elf",
      claim: "elf.inspection_failed",
      severity: "medium",
      confidence: 0.9,
      message: `Could not inspect ${info.rel}: ${info.error ?? "unknown error"}`,
      file: info.rel,
    });
    return;
  }

  if (info.glibc) {
    ledger.add({
      source: "elf",
      claim: "elf.required_glibc",
      severity: "info",
      confidence: 1,
      message: `${info.rel} requires GLIBC_${info.glibc}`,
      file: info.rel,
      data: { glibc: info.glibc },
    });
  }

  if (info.glibcxx) {
    ledger.add({
      source: "elf",
      claim: "elf.required_glibcxx",
      severity: "info",
      confidence: 1,
      message: `${info.rel} requires GLIBCXX_${info.glibcxx}`,
      file: info.rel,
      data: { glibcxx: info.glibcxx, cxxabi: info.cxxabi },
    });
  }

  if (info.abi) {
    ledger.add({
      source: "elf",
      claim: "elf.abi",
      severity: "info",
      confidence: 1,
      message: `${info.rel} targets Node ABI ${info.abi}${info.napi ? " (Node-API)" : ""}`,
      file: info.rel,
      data: { abi: info.abi, napi: info.napi },
    });
  }
}
