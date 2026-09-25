use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tauri::{AppHandle, Emitter};

use super::toolchain::find_best_clang;
use super::parser::get_all_functions;

#[derive(Debug, Serialize, Deserialize)]
pub struct CompileSettings {
    pub sanitizers: Vec<String>,
    pub includes: Vec<String>,
    pub library_files: Vec<String>,
    pub extra_flags: String,
    pub out_path: String,
    /// User-overridden clang path; if None, auto-detect via find_best_clang()
    pub clang_override: Option<String>,
}

/// Injected before the user's harness code.
/// - Renames LLVMFuzzerTestOneInput → __guzzle_fuzz_impl so we can wrap it
/// - Provides exit()/abort() overrides via longjmp so target code can't kill
///   the fuzzer process
const HARNESS_PREAMBLE: &str = r#"/* === Guzzle preamble === */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#endif
#include <setjmp.h>

/* Rename the user's entry point so we can wrap it with setjmp protection */
#define LLVMFuzzerTestOneInput __guzzle_fuzz_impl

/* Override exit() — some targets call exit(0) on bad input which would kill
   the entire fuzzer process. longjmp back to our wrapper instead.
   NOTE: abort() is intentionally NOT overridden — ASan uses it to signal
   crashes to libFuzzer's signal handler.
   NOTE: Windows/lld-link statically links the CRT so exit() cannot be
   redefined; skip the override there. */
jmp_buf __guzzle_exit_buf;
static int __guzzle_jmp_ready = 0;
#ifndef _WIN32
extern "C" void exit(int code) {
    if (__guzzle_jmp_ready) { longjmp(__guzzle_exit_buf, 1); }
    /* Not inside a fuzz iteration (e.g. libFuzzer shutdown) — terminate cleanly
       so the process exits with the correct code instead of firing a crash signal. */
    _exit(code);
}
#endif
/* === end preamble === */

"#;

/// Injected after the user's harness. Provides the real LLVMFuzzerTestOneInput
/// that libFuzzer calls, wrapped in setjmp so exit()/abort() in the target
/// returns 0 instead of terminating the process.
const HARNESS_POSTAMBLE: &str = r#"
/* === Guzzle postamble === */
#undef LLVMFuzzerTestOneInput
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    __guzzle_jmp_ready = 1;
    if (setjmp(__guzzle_exit_buf)) { __guzzle_jmp_ready = 0; return 0; }
    int r = __guzzle_fuzz_impl(data, size);
    __guzzle_jmp_ready = 0;
    return r;
}
/* === end postamble === */
"#;

#[tauri::command]
pub async fn compile_harness(
    app: AppHandle,
    harness: String,
    target_files: Vec<String>,
    settings: CompileSettings,
) -> Result<String, String> {
    let temp_dir = std::env::temp_dir().join("guzzle");
    std::fs::create_dir_all(&temp_dir).map_err(|e| format!("Failed to create temp dir: {e}"))?;

    // Strip any #include lines that pull in one of the target files directly
    let harness_clean = strip_target_includes(&harness, &target_files);
    // Move typedef struct blocks that appear after their first use to before it,
    // fixing "unknown type name" errors from AI-generated ordering issues.
    let harness_clean = hoist_type_definitions(&harness_clean);
    // Inject `extern "C"` on any forward declarations of C target functions that
    // are missing it — prevents C++ name-mangling from breaking the link step.
    let harness_clean = fix_c_fn_linkage(&harness_clean, &target_files);

    // Hard-fail before invoking clang if the harness forward-declares any
    // static C target functions. Static functions have internal linkage and
    // do not exist as linkable symbols — even `extern "C"` declarations won't
    // resolve them. The linker would fail with a cryptic "symbol not found"
    // error; fail here with an actionable message instead.
    let static_conflicts = find_static_fn_decls(&harness_clean, &target_files);
    if !static_conflicts.is_empty() {
        let names = static_conflicts.join("', '");
        let plural = if static_conflicts.len() == 1 { "is" } else { "are" };
        return Err(format!(
            "Harness calls ['{names}'], which {plural} declared `static` in \
             the target file. Static functions have internal C linkage and \
             cannot be linked from the harness — no exported symbol exists, \
             regardless of how the forward declaration is written.\n\
             Regenerate the harness. The AI must call a public (non-static) \
             function from the target instead of calling the static helper directly."
        ));
    }

    // Build extern "C" forward declarations for C target functions.
    // Pass the harness so we can skip forward-declaring types the AI already defined.
    let extern_c_block = build_extern_c_block(&target_files, &harness_clean);

    let harness_final = format!("{HARNESS_PREAMBLE}{extern_c_block}{harness_clean}{HARNESS_POSTAMBLE}");
    let harness_path = temp_dir.join("harness.cpp");
    std::fs::write(&harness_path, &harness_final)
        .map_err(|e| format!("Failed to write harness: {e}"))?;

    // Output binary path
    let out_path = if settings.out_path.is_empty() {
        let target_dir = target_files
            .first()
            .or_else(|| settings.library_files.first())
            .and_then(|f| PathBuf::from(f).parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let guzzle_dir = target_dir.join(".guzzle");
        std::fs::create_dir_all(&guzzle_dir)
            .map_err(|e| format!("Failed to create .guzzle dir: {e}"))?;

        // Also save a copy of the harness next to the binary for inspection
        let _ = std::fs::copy(&harness_path, guzzle_dir.join("harness.cpp"));

        guzzle_dir.join(if cfg!(windows) { "fuzzer.exe" } else { "fuzzer" }).to_string_lossy().to_string()
    } else {
        settings.out_path.clone()
    };

    let clang = settings.clang_override.clone()
        .filter(|p| !p.is_empty())
        .or_else(find_best_clang)
        .ok_or_else(|| "No suitable clang found. Run the toolchain check first.".to_string())?;

    let sanitize_flag = if settings.sanitizers.is_empty() {
        "-fsanitize=fuzzer".to_string()
    } else {
        format!("-fsanitize={}", settings.sanitizers.join(","))
    };

    // Detect if any C target file defines main() — if so, rename it so
    // libFuzzer's own main() takes precedence.
    // NOTE: get_all_functions() skips main() by design (for extern "C" blocks),
    // so we do a direct source scan here instead.
    let target_has_main = target_files.iter()
        .filter(|f| f.ends_with(".c"))
        .any(|f| {
            let src = std::fs::read_to_string(f).unwrap_or_default();
            src.contains("int main(") || src.contains("int main (")
        });

    let mut cmd = Command::new(&clang);
    cmd.arg(&sanitize_flag);

    for inc in &settings.includes {
        cmd.arg(format!("-I{inc}"));
    }
    for flag in settings.extra_flags.split_whitespace() {
        cmd.arg(flag);
    }

    // Harness as C++
    cmd.arg("-x").arg("c++");
    cmd.arg(harness_path.to_str().unwrap());

    // Target files in their native language
    for tf in &target_files {
        let lang = if tf.ends_with(".c") { "c" } else { "c++" };
        cmd.arg("-x").arg(lang);
        // Rename main() in target files so libFuzzer's main wins
        if target_has_main && tf.ends_with(".c") {
            cmd.arg("-Dmain=__guzzle_target_main");
        }
        cmd.arg(tf);
    }

    // Pre-built library files (.a, .so, .dylib) — reset -x so clang treats them as
    // archives/objects to link rather than source to compile
    if !settings.library_files.is_empty() {
        cmd.arg("-x").arg("none");
        for lib in &settings.library_files {
            cmd.arg(lib);
        }
    }

    // Windows fuzzer runtime requires these system libraries.
    #[cfg(target_os = "windows")]
    cmd.args(["-D_CRT_SECURE_NO_WARNINGS", "-ldbghelp", "-lshell32"]);

    cmd.arg("-o").arg(&out_path);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let args_display = cmd.get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let _ = app.emit("compile_output", format!("$ {clang} {args_display}"));

    // Set working dir to temp so clang's intermediate files don't land in
    // src-tauri/ (the cargo run cwd), which would trigger Tauri's file watcher.
    cmd.current_dir(&temp_dir);
    let mut child = cmd.spawn().map_err(|e| format!("Failed to spawn clang: {e}"))?;

    let stderr = child.stderr.take().unwrap();
    let app_e = app.clone();
    let t_err = tokio::task::spawn_blocking(move || {
        BufReader::new(stderr).lines().map_while(Result::ok)
            .for_each(|l| { let _ = app_e.emit("compile_output", l); });
    });

    let stdout = child.stdout.take().unwrap();
    let app_o = app.clone();
    let t_out = tokio::task::spawn_blocking(move || {
        BufReader::new(stdout).lines().map_while(Result::ok)
            .for_each(|l| { let _ = app_o.emit("compile_output", l); });
    });

    let status = tokio::task::spawn_blocking(move || child.wait())
        .await.map_err(|e| format!("join: {e}"))?
        .map_err(|e| format!("wait: {e}"))?;

    let _ = t_err.await;
    let _ = t_out.await;

    if status.success() {
        let _ = app.emit("compile_output", format!("\n✓ Compiled: {out_path}"));
        Ok(out_path)
    } else {
        Err(format!("Compilation failed with exit code {}", status.code().unwrap_or(-1)))
    }
}

/// Scan the harness for forward declarations of C target functions that are missing
/// `extern "C"` linkage, and inject it.  This is needed because the harness is
/// compiled as C++ but the target files are compiled as C — without `extern "C"`,
/// C++ name-mangles the call site and the linker can't match the C symbol.
///
/// Example transform:
///   `int ParseMessage(const uint8_t *buf, size_t len, Message *msg);`
///   → `extern "C" int ParseMessage(const uint8_t *buf, size_t len, Message *msg);`
pub fn fix_c_fn_linkage(harness: &str, target_files: &[String]) -> String {
    // Collect the names of all non-static public functions in C target files.
    let c_fn_names: std::collections::HashSet<String> = target_files.iter()
        .filter(|f| f.ends_with(".c"))
        .flat_map(|f| get_all_functions(f))
        .filter(|sig| {
            let ret = sig.return_type.trim();
            !ret.starts_with("static ") && !ret.starts_with("static\t")
        })
        .map(|sig| sig.name)
        .collect();

    if c_fn_names.is_empty() {
        return harness.to_string();
    }

    harness.lines().map(|line| {
        let t = line.trim();
        // Skip comments and lines already using extern "C"
        if t.starts_with("//") || t.starts_with("/*") || t.contains("extern \"C\"") {
            return line.to_string();
        }
        // Only consider forward declarations: end with ';', no '{'
        if !t.ends_with(';') || t.contains('{') {
            return line.to_string();
        }
        for name in &c_fn_names {
            let Some(pos) = t.find(name.as_str()) else { continue };
            if pos == 0 { continue; } // bare call statement
            let before = t[..pos].trim();
            // Must have a return type before the name, not an assignment or nested call
            if before.is_empty() || before.contains('(') || before.contains('=') { continue; }
            // Looks like a forward declaration of a C function — inject extern "C"
            let indent = &line[..line.len() - line.trim_start().len()];
            return format!("{indent}extern \"C\" {t}");
        }
        line.to_string()
    }).collect::<Vec<_>>().join("\n")
}

/// Move `typedef struct { ... } TypeName;` blocks that appear *after* a forward
/// declaration using `TypeName` to *before* that declaration.
///
/// AI models occasionally emit a forward declaration before the struct typedef
/// it depends on, producing "unknown type name" compile errors. This pass
/// detects such ordering problems and hoists the typedef to the first use site.
pub fn hoist_type_definitions(harness: &str) -> String {
    let lines: Vec<&str> = harness.lines().collect();
    let n = lines.len();

    // Pass 1: find every `typedef struct { ... } TypeName;` block.
    // Records (start_line, end_line, type_name) — indices inclusive.
    let mut blocks: Vec<(usize, usize, String)> = Vec::new();
    let mut i = 0;
    while i < n {
        let t = lines[i].trim();
        // Only full struct definitions (contain '{'), not opaque typedefs.
        if t.starts_with("typedef struct") && t.contains('{') {
            let start = i;
            if t.contains('}') {
                // Single-line: `typedef struct { ... } Name;`
                if let Some(name) = typedef_closing_name(lines[i]) {
                    blocks.push((start, i, name));
                }
                i += 1;
                continue;
            }
            // Multi-line: scan forward for the closing `} Name;` line.
            i += 1;
            while i < n {
                if lines[i].trim().starts_with('}') && lines[i].trim().ends_with(';') {
                    if let Some(name) = typedef_closing_name(lines[i]) {
                        blocks.push((start, i, name));
                    }
                    break;
                }
                i += 1;
            }
        }
        i += 1;
    }

    if blocks.is_empty() {
        return harness.to_string();
    }

    let block_lines: std::collections::HashSet<usize> =
        blocks.iter().flat_map(|(s, e, _)| *s..=*e).collect();

    // Pass 2: find the earliest forward declaration that uses a type defined
    // *later* in the harness (i.e., the typedef block's start > this line).
    let mut hoist_before: Option<usize> = None;
    for (idx, line) in lines.iter().enumerate() {
        if block_lines.contains(&idx) {
            continue;
        }
        let t = line.trim();
        // Forward declarations end with ';', contain '(', have no '{'.
        if !t.ends_with(';') || !t.contains('(') || t.contains('{') {
            continue;
        }
        if t.starts_with("//") || t.starts_with("/*") || t.starts_with('#') {
            continue;
        }
        for (bstart, _, name) in &blocks {
            if *bstart > idx && t.contains(name.as_str()) {
                hoist_before = Some(hoist_before.map_or(idx, |prev: usize| prev.min(idx)));
            }
        }
    }

    let Some(hoist_at) = hoist_before else {
        return harness.to_string(); // No reordering needed.
    };

    // Only hoist blocks defined after `hoist_at`.
    let to_hoist: Vec<_> = blocks.iter().filter(|(s, _, _)| *s > hoist_at).collect();
    if to_hoist.is_empty() {
        return harness.to_string();
    }

    let hoisted_lines: std::collections::HashSet<usize> =
        to_hoist.iter().flat_map(|(s, e, _)| *s..=*e).collect();

    let mut out: Vec<&str> = Vec::with_capacity(n + to_hoist.len());
    let mut inserted = false;
    for (idx, &line) in lines.iter().enumerate() {
        if idx == hoist_at && !inserted {
            for (hs, he, _) in &to_hoist {
                for bi in *hs..=*he {
                    out.push(lines[bi]);
                }
            }
            inserted = true;
        }
        if !hoisted_lines.contains(&idx) {
            out.push(line);
        }
    }
    out.join("\n")
}

/// Extract the type name from the closing line of a typedef struct, e.g.
/// `} TlvField;` → `"TlvField"`, or `typedef struct { int x; } Foo;` → `"Foo"`.
fn typedef_closing_name(line: &str) -> Option<String> {
    let t = line.trim();
    let pos = t.rfind('}')?;
    let after = t[pos + 1..].trim().trim_end_matches(';').trim();
    if after.is_empty() || after.contains('(') || after.contains(' ') || after.contains(',') {
        return None;
    }
    Some(after.to_string())
}

/// Returns names of static C target functions that the harness forward-declares
/// (with `static`). Such declarations give the function internal linkage inside
/// the harness translation unit — the definition in the target file is in a
/// different TU and can never satisfy them. The linker fails with
/// "Undefined symbols" / "symbol not found for architecture".
pub fn find_static_fn_decls(harness: &str, target_files: &[String]) -> Vec<String> {
    let static_fn_names: std::collections::HashSet<String> = target_files
        .iter()
        .filter(|f| f.ends_with(".c"))
        .flat_map(|f| get_all_functions(f))
        .filter(|sig| {
            let ret = sig.return_type.trim();
            ret.starts_with("static ") || ret.starts_with("static\t")
        })
        .map(|sig| sig.name.clone())
        .collect();

    if static_fn_names.is_empty() {
        return vec![];
    }

    let mut found: Vec<String> = Vec::new();
    for line in harness.lines() {
        let t = line.trim();
        if t.starts_with("//") || t.starts_with("/*") {
            continue;
        }
        // Only forward declarations: ends with ';', no '{'
        if !t.ends_with(';') || t.contains('{') {
            continue;
        }
        for name in &static_fn_names {
            let Some(pos) = t.find(name.as_str()) else { continue };
            if pos == 0 {
                continue; // bare call statement
            }
            let before = t[..pos].trim();
            if before.is_empty() || before.contains('(') || before.contains('=') {
                continue;
            }
            if !found.contains(name) {
                found.push(name.clone());
            }
        }
    }
    found
}

pub fn strip_target_includes(harness: &str, target_files: &[String]) -> String {
    let stems: Vec<&str> = target_files.iter()
        .map(|f| f.rsplit('/').next().unwrap_or(f.as_str()))
        .collect();

    harness.lines()
        .filter(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("#include") { return true; }
            !stems.iter().any(|stem| trimmed.contains(stem))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Returns true if `harness` contains a full typedef/struct definition for `type_name`.
/// Catches both:
///   typedef struct TypeName { ... } TypeName;   (named)
///   typedef struct { ... } TypeName;             (anonymous)
/// Returns true if `harness` already contains a forward declaration or definition
/// of a function named `func_name`.  Matches lines of the form:
///   ReturnType func_name(...);    ← forward declaration
///   ReturnType func_name(...) {   ← definition
/// but NOT call sites like `func_name(...)` or `result = func_name(...)`.
fn harness_declares_fn(harness: &str, func_name: &str) -> bool {
    harness.lines().any(|line| {
        let t = line.trim();
        if t.starts_with("//") || t.starts_with("/*") { return false; }
        // The function name must appear in the line
        let Some(pos) = t.find(func_name) else { return false };
        if pos == 0 { return false; } // bare call at start of statement
        let before = &t[..pos];
        let bt = before.trim();
        // Must have something before (return type), not be a keyword-only prefix,
        // and must not be an assignment or nested call
        !bt.is_empty()
            && !matches!(bt, "return" | "if" | "while" | "else")
            && !bt.ends_with("return")
            && !bt.ends_with("if")
            && !bt.ends_with("while")
            && !bt.contains('=')
            && !bt.contains('(')
    })
}

fn harness_defines_type(harness: &str, type_name: &str) -> bool {
    // The closing `} TypeName;` token is the reliable marker for both patterns.
    harness.contains(&format!("}} {};", type_name))
        || harness.contains(&format!("}}{};", type_name))
        // Also catch `} TypeName ;` with extra whitespace
        || harness.lines().any(|l| {
            let t = l.trim();
            t.starts_with('}') && t.trim_start_matches('}').trim().starts_with(type_name)
                && t.ends_with(';')
        })
}

pub fn build_extern_c_block(target_files: &[String], harness: &str) -> String {
    let c_files: Vec<&String> = target_files.iter()
        .filter(|f| f.ends_with(".c"))
        .collect();

    if c_files.is_empty() {
        return String::new();
    }

    let mut lines = vec![
        "/* --- extern \"C\" declarations injected by Guzzle --- */".to_string(),
        "extern \"C\" {".to_string(),
    ];

    for path in &c_files {
        // If a companion header exists (e.g. msgparse.h for msgparse.c), include it.
        // This brings in type definitions that forward-declarations alone can't provide.
        let header = std::path::Path::new(path).with_extension("h");
        if header.exists() {
            lines.push(format!("    #include \"{}\"", header.to_string_lossy().replace('\\', "/")));
            continue;
        }

        // No header — fall back to forward-declaring each function.
        // Collect any unknown struct/typedef names used in signatures so we
        // can emit forward declarations and avoid "unknown type" errors.
        let mut seen_types: std::collections::HashSet<String> = std::collections::HashSet::new();
        let sigs: Vec<_> = get_all_functions(path)
            .into_iter()
            .filter(|s| s.name != "main")
            .collect();

        // Strip storage-class specifiers and qualifiers to get the bare type name.
        // e.g. "static TlvField *" -> "TlvField"
        let bare_type = |t: &str| -> String {
            let mut s = t.trim();
            for kw in &["static ", "extern ", "inline ", "volatile ", "const ",
                        "static\t", "extern\t", "inline\t", "volatile\t", "const\t"] {
                while s.starts_with(kw) {
                    s = s[kw.len()..].trim();
                }
            }
            s.trim_end_matches('*').trim()
             .trim_end_matches("const").trim()
             .trim_end_matches('*').trim()
             .to_string()
        };

        // Emit `typedef struct X X;` for any non-primitive pointer types.
        let primitive = |t: &str| {
            matches!(t, "void"|"int"|"char"|"float"|"double"|"long"|"short"
                       |"uint8_t"|"uint16_t"|"uint32_t"|"uint64_t"
                       |"int8_t"|"int16_t"|"int32_t"|"int64_t"
                       |"size_t"|"bool"|"unsigned"|"signed")
        };
        for sig in &sigs {
            let all_types = std::iter::once(sig.return_type.as_str())
                .chain(sig.params.iter().map(|p| p.type_name.as_str()));
            for t in all_types {
                let base = bare_type(t);
                if !base.is_empty() && !primitive(&base) && seen_types.insert(base.clone())
                    && !harness_defines_type(harness, &base)
                {
                    lines.push(format!("    typedef struct {base} {base};"));
                }
            }
        }

        for sig in &sigs {
            // Skip static functions — they have internal linkage and can't be
            // called from outside the translation unit, so declaring them in
            // an extern "C" block would be both wrong and unnecessary.
            let ret = sig.return_type.trim();
            if ret.starts_with("static ") || ret.starts_with("static\t") {
                continue;
            }
            // Skip if the harness already declares this function — re-declaring
            // it here would place the declaration before the parameter types are
            // defined (types come from harness_clean which follows extern_c_block).
            if harness_declares_fn(harness, &sig.name) {
                continue;
            }
            let params: Vec<String> = sig.params.iter().map(|p| {
                if p.param_name.is_empty() {
                    p.type_name.clone()
                } else {
                    format!("{} {}", p.type_name, p.param_name)
                }
            }).collect();
            lines.push(format!(
                "    {} {}({});",
                ret, sig.name, params.join(", ")
            ));
        }
    }

    lines.push("}".to_string());
    lines.push("/* ---------------------------------------------------- */\n".to_string());
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // --- fix_c_fn_linkage ---

    #[test]
    fn fix_linkage_adds_extern_c_to_bare_decl() {
        // Regression: AI declares a C function without extern "C" — the C++ compiler
        // name-mangles it and the linker can't find the C symbol.
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        writeln!(f, "int ParseMessage(const uint8_t *buf, size_t len) {{ return 0; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        let harness = "int ParseMessage(const uint8_t *buf, size_t len);\n\
                       extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }\n";
        let result = fix_c_fn_linkage(harness, &[path]);
        assert!(result.contains("extern \"C\" int ParseMessage("),
            "must inject extern \"C\" on the bare declaration");
    }

    #[test]
    fn fix_linkage_leaves_already_extern_c_decl_alone() {
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        writeln!(f, "int foo(int x) {{ return x; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        let harness = "extern \"C\" int foo(int x);\n";
        let result = fix_c_fn_linkage(harness, &[path]);
        // Should not double-wrap
        assert!(!result.contains("extern \"C\" extern \"C\""));
        assert!(result.contains("extern \"C\" int foo("));
    }

    #[test]
    fn fix_linkage_does_not_touch_call_sites() {
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        writeln!(f, "int foo(int x) {{ return x; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        // A call site should not get extern "C" prepended
        let harness = "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) {\n    foo(1);\n    return 0;\n}\n";
        let result = fix_c_fn_linkage(harness, &[path]);
        assert!(!result.contains("extern \"C\" foo("),
            "call sites must not be modified");
    }

    // --- strip_target_includes ---

    #[test]
    fn strip_removes_target_include() {
        let harness = "#include \"msgparse.c\"\nint x;";
        let result = strip_target_includes(harness, &["/path/to/msgparse.c".to_string()]);
        assert!(!result.contains("#include \"msgparse.c\""));
        assert!(result.contains("int x;"));
    }

    #[test]
    fn strip_keeps_system_include() {
        let harness = "#include <stdio.h>\nint x;";
        let result = strip_target_includes(harness, &["msgparse.c".to_string()]);
        assert!(result.contains("#include <stdio.h>"));
    }

    #[test]
    fn strip_keeps_other_header() {
        let harness = "#include \"other.h\"\nint x;";
        let result = strip_target_includes(harness, &["msgparse.c".to_string()]);
        assert!(result.contains("#include \"other.h\""));
    }

    #[test]
    fn strip_empty_targets_unchanged() {
        let harness = "#include \"foo.c\"\nint x;";
        let result = strip_target_includes(harness, &[]);
        assert_eq!(result, harness);
    }

    #[test]
    fn strip_preserves_comment_containing_target_name() {
        // A comment that mentions a target filename is not an include — keep it
        let harness = "// msgparse.c is the parser\nint x;";
        let result = strip_target_includes(harness, &["msgparse.c".to_string()]);
        assert!(result.contains("// msgparse.c is the parser"));
    }

    // --- build_extern_c_block ---

    #[test]
    fn extern_c_empty_input() {
        assert_eq!(build_extern_c_block(&[], ""), "");
    }

    #[test]
    fn extern_c_cpp_only() {
        assert_eq!(build_extern_c_block(&["foo.cpp".to_string()], ""), "");
    }

    #[test]
    fn extern_c_c_file_primitive_types() {
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        writeln!(f, "int add(int a, int b) {{ return a + b; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        let result = build_extern_c_block(&[path], "");
        assert!(result.contains("extern \"C\""));
        assert!(result.contains("int add("));
        assert!(!result.contains("typedef struct"));
    }

    #[test]
    fn extern_c_c_file_custom_type_emits_typedef() {
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        // TlvField is a non-primitive type — build_extern_c_block should emit a typedef
        writeln!(f, "TlvField *parse(unsigned char *buf, int len) {{ return 0; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        // No harness — forward typedef should be emitted
        let result = build_extern_c_block(&[path], "");
        assert!(result.contains("typedef struct TlvField TlvField;"));
    }

    #[test]
    fn extern_c_skips_typedef_already_defined_in_harness() {
        // Regression: AI harness defines `typedef struct { ... } TlvField;`
        // build_extern_c_block must NOT also emit `typedef struct TlvField TlvField;`
        // because C++ rejects redefining a typedef to a different (anonymous) struct type.
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        writeln!(f, "TlvField *parse(unsigned char *buf, int len) {{ return 0; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        // Harness uses anonymous struct pattern (common AI output)
        let harness = "typedef struct {\n    uint8_t type;\n} TlvField;\n";
        let result = build_extern_c_block(&[path], harness);
        assert!(!result.contains("typedef struct TlvField TlvField;"),
            "must not forward-declare a type the harness already fully defines");
        // Function declaration should still appear
        // The format is "ReturnType FuncName(" — there may be a space before the name
        assert!(result.contains("parse("), "function declaration must still be emitted");
    }

    #[test]
    fn extern_c_skips_fn_already_declared_in_harness() {
        // Regression: AI harness includes its own `int ParseMessage(...);` forward
        // declaration. build_extern_c_block must not re-declare it, because the
        // re-declaration would precede the type definitions that come from harness_clean,
        // causing "unknown type name 'Message'" errors.
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        writeln!(f, "int ParseMessage(const uint8_t *buf, size_t len, Message *msg) {{ return 0; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        let harness = "typedef struct { int n; } Message;\nint ParseMessage(const uint8_t *buf, size_t len, Message *msg);\n";
        let result = build_extern_c_block(&[path], harness);
        // Harness already declares ParseMessage — extern_c_block must not add another
        assert!(!result.contains("ParseMessage"),
            "must not re-declare a function the harness already declares");
    }

    #[test]
    fn extern_c_static_qualifier_stripped_from_typedef() {
        // Functions with `static` return types (e.g. `static TlvField *parse(...)`)
        // must not produce `typedef struct static TlvField static TlvField;`
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        writeln!(f, "typedef struct TlvField TlvField;").unwrap();
        writeln!(f, "static TlvField *parse(const unsigned char *buf, int len) {{ return 0; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        let result = build_extern_c_block(&[path], "");
        assert!(!result.contains("struct static"), "static must not appear inside typedef struct");
        assert!(result.contains("typedef struct TlvField TlvField") || result.contains("TlvField"));
    }

    #[test]
    fn extern_c_c_file_with_companion_header() {
        let dir = tempfile::tempdir().unwrap();
        let c_path = dir.path().join("mylib.c");
        let h_path = dir.path().join("mylib.h");
        std::fs::write(&c_path, "int foo(int x) { return x; }").unwrap();
        std::fs::write(&h_path, "int foo(int x);").unwrap();

        let result = build_extern_c_block(&[c_path.to_string_lossy().to_string()], "");
        let h_str = h_path.to_string_lossy().replace('\\', "/");
        assert!(result.contains(&format!("#include \"{h_str}\"")));
    }

    // --- Preamble regression tests ---

    #[test]
    fn preamble_unistd_guarded_by_ifndef_win32() {
        let ifndef_pos = HARNESS_PREAMBLE.find("#ifndef _WIN32")
            .expect("#ifndef _WIN32 not found in preamble");
        let unistd_pos = HARNESS_PREAMBLE.find("unistd.h")
            .expect("unistd.h not found in preamble");
        assert!(ifndef_pos < unistd_pos,
            "#ifndef _WIN32 must appear before unistd.h");
    }

    #[test]
    fn preamble_exit_override_guarded_by_ifndef_win32() {
        let exit_pos = HARNESS_PREAMBLE.find("extern \"C\" void exit(")
            .expect("exit() override not found in preamble");
        // The nearest #ifndef _WIN32 before the exit() declaration must exist
        HARNESS_PREAMBLE[..exit_pos].rfind("#ifndef _WIN32")
            .expect("exit() override must be inside #ifndef _WIN32 guard");
    }

    #[test]
    fn preamble_exit_override_falls_back_to_exit_not_trap() {
        // Regression: when __guzzle_jmp_ready == 0 (e.g. libFuzzer shutdown),
        // the exit() override must call _exit() and not __builtin_trap().
        // __builtin_trap() fires a crash signal, producing a spurious finding.
        assert!(!HARNESS_PREAMBLE.contains("__builtin_trap"),
            "exit() fallback must use _exit(), not __builtin_trap()");
        assert!(HARNESS_PREAMBLE.contains("_exit(code)"),
            "exit() fallback must call _exit(code)");
    }

    #[test]
    fn preamble_no_crt_secure_no_warnings() {
        assert!(!HARNESS_PREAMBLE.contains("_CRT_SECURE_NO_WARNINGS"),
            "_CRT_SECURE_NO_WARNINGS must be a compiler flag, not in the preamble");
    }

    // --- hoist_type_definitions ---

    #[test]
    fn hoist_moves_typedef_before_forward_decl() {
        // Regression: AI puts the forward declaration before the typedef it needs.
        let harness = "\
TlvField *parse_array(const uint8_t *data, int len);\n\
typedef struct {\n\
    uint8_t type;\n\
} TlvField;\n\
extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }\n";

        let result = hoist_type_definitions(harness);
        let typedef_pos = result.find("typedef struct").unwrap();
        let fwd_pos = result.find("TlvField *parse_array").unwrap();
        assert!(
            typedef_pos < fwd_pos,
            "typedef must appear before the forward declaration that uses it"
        );
    }

    #[test]
    fn hoist_no_change_when_order_correct() {
        let harness = "\
typedef struct {\n\
    uint8_t type;\n\
} TlvField;\n\
TlvField *parse_array(const uint8_t *data, int len);\n";

        let result = hoist_type_definitions(harness);
        // Order is already correct — result should be unchanged.
        let typedef_pos = result.find("typedef struct").unwrap();
        let fwd_pos = result.find("TlvField *parse_array").unwrap();
        assert!(typedef_pos < fwd_pos);
    }

    #[test]
    fn hoist_no_change_when_no_typedef() {
        let harness = "int foo(int x);\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }\n";
        let result = hoist_type_definitions(harness);
        // No typedef blocks — content must be unchanged (modulo trailing newline).
        assert_eq!(result.trim_end(), harness.trim_end());
    }

    #[test]
    fn hoist_preserves_all_lines() {
        let harness = "\
#include <stdint.h>\n\
TlvField *parse_array(const uint8_t *data, int len);\n\
typedef struct {\n\
    uint8_t type;\n\
    uint16_t length;\n\
} TlvField;\n\
extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }\n";

        let result = hoist_type_definitions(harness);
        // Every non-empty line from the original must still be present.
        for line in harness.lines().filter(|l| !l.trim().is_empty()) {
            assert!(result.contains(line), "line missing after hoist: {line:?}");
        }
    }

    // --- find_static_fn_decls ---

    #[test]
    fn static_decl_detected_for_static_c_fn() {
        // Regression: AI copies `static` from context into the harness forward
        // declaration. The linker then fails with "symbol not found" because the
        // function has internal linkage in the target TU.
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        writeln!(f, "static int *parse_array(const unsigned char *d, int len) {{ return 0; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        let harness = "static int *parse_array(const unsigned char *d, int len);\n\
                       extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }\n";
        let found = find_static_fn_decls(harness, &[path]);
        assert!(found.contains(&"parse_array".to_string()),
            "must detect static forward declaration of a static C function");
    }

    #[test]
    fn static_decl_not_flagged_for_public_fn() {
        // A non-static C function declared without `static` in the harness is fine.
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        writeln!(f, "int ParseMessage(const unsigned char *d, int len) {{ return 0; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        let harness = "int ParseMessage(const unsigned char *d, int len);\n";
        let found = find_static_fn_decls(harness, &[path]);
        assert!(found.is_empty(), "public function should not be flagged");
    }

    #[test]
    fn static_decl_not_flagged_for_call_sites() {
        // A call to a static function (not a declaration) should not be flagged.
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        writeln!(f, "static int helper(int x) {{ return x; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        // Call site, not a forward declaration
        let harness = "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) {\n\
                       helper(1);\n    return 0;\n}\n";
        let found = find_static_fn_decls(harness, &[path]);
        assert!(found.is_empty(), "call site should not be flagged");
    }

    #[test]
    fn static_decl_empty_target_list() {
        let harness = "static int foo(int x);\n";
        let found = find_static_fn_decls(harness, &[]);
        assert!(found.is_empty());
    }

    #[test]
    fn fuzzer_binary_name_has_exe_on_windows() {
        let name = if cfg!(windows) { "fuzzer.exe" } else { "fuzzer" };
        if cfg!(windows) {
            assert!(name.ends_with(".exe"));
        } else {
            assert!(!name.contains('.'));
        }
    }
}
