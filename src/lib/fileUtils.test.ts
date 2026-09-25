import { describe, it, expect } from "vitest";
import { isBinaryFile } from "./fileUtils";

describe("isBinaryFile", () => {
  // ── No extension → binary ───────────────────────────────────────────────
  it("treats extensionless Mach-O / ELF executables as binary", () => {
    expect(isBinaryFile("Activity Monitor")).toBe(true);
    expect(isBinaryFile("/Applications/Utilities/Activity Monitor.app/Contents/MacOS/Activity Monitor")).toBe(true);
    expect(isBinaryFile("/usr/bin/clang")).toBe(true);
    expect(isBinaryFile("/usr/bin/nm")).toBe(true);
  });

  // ── C/C++ source extensions → NOT binary ────────────────────────────────
  it.each(["c", "cpp", "cc", "cxx", "h", "hpp"])(
    "treats .%s as source",
    (ext) => expect(isBinaryFile(`foo.${ext}`)).toBe(false)
  );

  it("is case-insensitive for source extensions", () => {
    expect(isBinaryFile("foo.C")).toBe(false);
    expect(isBinaryFile("foo.CPP")).toBe(false);
    expect(isBinaryFile("foo.H")).toBe(false);
    expect(isBinaryFile("MAIN.CXX")).toBe(false);
  });

  // ── Explicit binary extensions → binary ─────────────────────────────────
  it.each(["so", "dylib", "a", "dll", "lib"])(
    "treats .%s as binary",
    (ext) => expect(isBinaryFile(`libfoo.${ext}`)).toBe(true)
  );

  // ── Versioned shared libraries ───────────────────────────────────────────
  it("treats versioned .so as binary (last component is a number)", () => {
    expect(isBinaryFile("libz.so.1")).toBe(true);
    expect(isBinaryFile("libz.so.1.2.11")).toBe(true);
    expect(isBinaryFile("/usr/lib/x86_64-linux-gnu/libz.so.1.2.11")).toBe(true);
  });

  // ── Multiple dots — only the last extension counts ───────────────────────
  it("routes by the last extension for multi-dot filenames", () => {
    expect(isBinaryFile("file.test.c")).toBe(false);   // last ext "c" → source
    expect(isBinaryFile("archive.tar.gz")).toBe(true); // last ext "gz" → binary
    expect(isBinaryFile("foo.backup.cpp")).toBe(false); // last ext "cpp" → source
  });

  // ── Platform paths ───────────────────────────────────────────────────────
  it("handles Linux paths", () => {
    expect(isBinaryFile("/usr/lib/libssl.so")).toBe(true);
    expect(isBinaryFile("/home/user/project/main.c")).toBe(false);
  });

  it("handles macOS paths", () => {
    expect(isBinaryFile("/usr/lib/libz.dylib")).toBe(true);
    expect(isBinaryFile("/Users/user/project/parser.cpp")).toBe(false);
  });

  it("handles Windows paths with backslash separators", () => {
    expect(isBinaryFile("C:\\Windows\\System32\\kernel32.dll")).toBe(true);
    expect(isBinaryFile("C:\\Users\\user\\project\\main.cpp")).toBe(false);
  });

  // ── Edge cases ───────────────────────────────────────────────────────────
  it("treats hidden dotfiles as binary (not a source extension)", () => {
    // .bashrc → ext is "bashrc" which is not a C/C++ source extension
    expect(isBinaryFile(".bashrc")).toBe(true);
  });

  it("treats a directory with a dot in its name and extensionless file as binary", () => {
    expect(isBinaryFile("/home/user.name/my_binary")).toBe(true);
  });

  it("treats a lone dot as binary", () => {
    expect(isBinaryFile(".")).toBe(true); // ext would be "" → not a source ext
  });
});
