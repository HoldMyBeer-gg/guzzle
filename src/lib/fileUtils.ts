export const SOURCE_EXTENSIONS = new Set(["c", "cpp", "cc", "cxx", "h", "hpp"]);
export const BINARY_EXTENSIONS = ["so", "dylib", "a", "dll", "lib"];

/**
 * Returns true if the file should be opened in binary mode.
 *
 * Files with no extension (e.g. Mach-O and ELF executables) and files whose
 * extension is not a recognised C/C++ source type are treated as binaries.
 * The check is case-insensitive.
 */
export function isBinaryFile(path: string): boolean {
  const filename = path.split(/[\\/]/).pop() ?? "";
  const lastDot = filename.lastIndexOf(".");
  // No extension → binary (covers Mach-O / ELF executables, e.g. "Activity Monitor")
  if (lastDot === -1) return true;
  const ext = filename.slice(lastDot + 1).toLowerCase();
  return !SOURCE_EXTENSIONS.has(ext);
}
