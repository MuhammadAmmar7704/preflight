import * as tar from "tar";

export interface ExtractResult {
  files: number;
  bytes: number;
  skipped: number;
}

const MAX_FILE = 50 * 1024 * 1024;
const MAX_TOTAL = 300 * 1024 * 1024;
const MAX_FILES = 10_000;

export async function extractTarball(
  file: string,
  dest: string
): Promise<ExtractResult> {
  let files = 0;
  let bytes = 0;
  let skipped = 0;

  await tar.x({
    file,
    cwd: dest,
    strip: 1,
    preserveOwner: false,
    noChmod: true,
    filter: (relPath, entry) => {
      const parts = relPath.split("/");
      if (relPath.startsWith("/") || parts.includes("..")) {
        skipped++;
        return false;
      }
      const entryType = "type" in entry ? entry.type : "File";
      if (entryType === "SymbolicLink" || entryType === "Link") {
        skipped++;
        return false;
      }

      const size = entry.size ?? 0;
      if (size > MAX_FILE) {
        skipped++;
        return false;
      }

      bytes += size;
      files++;
      if (bytes > MAX_TOTAL || files > MAX_FILES) {
        skipped++;
        return false;
      }
      return true;
    },
  });

  return { files, bytes, skipped };
}
