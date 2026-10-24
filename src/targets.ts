import type { Target } from "./types.js";

export const PRESETS: Record<string, Target> = {
  "ubuntu22-node20": {
    os: "linux",
    arch: "x64",
    libc: "glibc",
    libcVersion: "2.35",
    node: "20",
    abi: 115,
  },
  "ubuntu24-node22": {
    os: "linux",
    arch: "x64",
    libc: "glibc",
    libcVersion: "2.39",
    node: "22",
    abi: 127,
  },
  "debian12-node20": {
    os: "linux",
    arch: "x64",
    libc: "glibc",
    libcVersion: "2.36",
    node: "20",
    abi: 115,
  },
  "alpine-node20": {
    os: "linux",
    arch: "x64",
    libc: "musl",
    libcVersion: "1.2.5",
    node: "20",
    abi: 115,
  },
};

export function targetFromArgs(
  preset?: string,
  overrides: Partial<Target> = {}
): Target {
  const key = preset ?? "ubuntu22-node20";
  const base = PRESETS[key];
  if (!base) {
    throw new Error(
      `unknown target preset "${key}". Available: ${Object.keys(PRESETS).join(", ")}`
    );
  }
  return { ...base, ...overrides };
}
