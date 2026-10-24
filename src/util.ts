import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

export async function run(
  file: string,
  args: string[],
  timeoutMs = 15_000
): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileP(file, args, {
      timeout: timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
    });
    return { ok: true, stdout, stderr };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; message?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? e.message ?? "" };
  }
}

export function sha512Base64(buf: Buffer): string {
  return createHash("sha512").update(buf).digest("base64");
}

export function sha256Hex(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

export function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map((n) => Number.parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => Number.parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export function maxVersion(versions: string[]): string | undefined {
  return [...versions].sort(compareVersions).at(-1);
}

export function parseSpec(spec: string): { name: string; range: string } {
  if (spec.startsWith("@")) {
    const idx = spec.indexOf("@", 1);
    if (idx === -1) return { name: spec, range: "latest" };
    return { name: spec.slice(0, idx), range: spec.slice(idx + 1) };
  }
  const idx = spec.indexOf("@");
  if (idx === -1) return { name: spec, range: "latest" };
  return { name: spec.slice(0, idx), range: spec.slice(idx + 1) };
}

export async function mkdtemp(prefix = "preflight-"): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

export async function rmrf(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

export function normalizeRel(p: string): string {
  return p.replace(/^\.\//, "").replace(/\\/g, "/");
}

export async function readMagic(file: string, bytes = 4): Promise<Buffer> {
  const fh = await fs.open(file, "r");
  try {
    const buf = Buffer.alloc(bytes);
    const { bytesRead } = await fh.read(buf, 0, bytes, 0);
    return buf.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}
