use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tauri::{AppHandle, Emitter};

use super::ai::{call_ai, AiProvider};
use super::compile::{build_extern_c_block, fix_c_fn_linkage, strip_target_includes};
use super::parser::FunctionSignature;
use super::toolchain::find_best_clang;

/// C stub that reads the crash file and calls LLVMFuzzerTestOneInput.
const REPRODUCER_MAIN: &str = r#"#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: reproducer <crash_file>\n"); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    if (size <= 0) { fclose(f); return 1; }
    uint8_t *buf = (uint8_t *)malloc((size_t)size);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, (size_t)size, f);
    fclose(f);
    int ret = LLVMFuzzerTestOneInput(buf, (size_t)size);
    free(buf);
    return ret;
}
"#;

enum RopTool {
    ROPgadget,
    Ropper,
    Radare2,
}

fn probe(name: &str, arg: &str) -> bool {
    Command::new(name)
        .arg(arg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn find_rop_tool() -> Option<RopTool> {
    // macOS (Mach-O) and Windows (PE): prefer radare2 — it handles both
    // formats natively. ROPgadget/ropper work but radare2 is the better pick.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    if probe("r2", "-h") { return Some(RopTool::Radare2); }

    if probe("ROPgadget", "--help") { return Some(RopTool::ROPgadget); }
    if probe("ropper", "--help")    { return Some(RopTool::Ropper);    }

    // Linux fallback to radare2 if the others aren't available.
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    if probe("r2", "-h") { return Some(RopTool::Radare2); }

    None
}

fn rop_tool_name(tool: &RopTool) -> &'static str {
    match tool {
        RopTool::ROPgadget => "ROPgadget",
        RopTool::Ropper    => "ropper",
        RopTool::Radare2   => "radare2",
    }
}

fn run_rop_tool(tool: &RopTool, binary: &str, work_dir: &std::path::Path) -> Result<String, String> {
    let output = match tool {
        RopTool::ROPgadget => Command::new("ROPgadget")
            .args(["--binary", binary, "--rop", "--nosys"])
            .current_dir(work_dir)
            .output()
            .map_err(|e| format!("ROPgadget error: {e}"))?,
        RopTool::Ropper => Command::new("ropper")
            .args(["-f", binary])
            .current_dir(work_dir)
            .output()
            .map_err(|e| format!("ropper error: {e}"))?,
        // r2 -q: quiet mode (no banner); -c "aaa;/R;q": analyse, list ROP gadgets, quit.
        RopTool::Radare2 => Command::new("r2")
            .args(["-q", "-c", "aaa;/R;q", binary])
            .current_dir(work_dir)
            .output()
            .map_err(|e| format!("radare2 error: {e}"))?,
    };

    let text = String::from_utf8_lossy(&output.stdout).to_string();
    // Truncate to first 200 gadget lines
    let lines: Vec<&str> = text.lines().take(200).collect();
    Ok(lines.join("\n"))
}

fn emit(app: &AppHandle, msg: impl Into<String>) {
    let _ = app.emit("poc_log", msg.into());
}

#[derive(Debug, PartialEq)]
enum BugClass {
    StackOverflow,
    HeapOverflow,
    UseAfterFree,
    Unknown,
}

fn detect_bug_class(asan_report: &str) -> BugClass {
    let r = asan_report.to_ascii_lowercase();
    if r.contains("stack-buffer-overflow") {
        BugClass::StackOverflow
    } else if r.contains("heap-buffer-overflow") {
        BugClass::HeapOverflow
    } else if r.contains("heap-use-after-free") || r.contains("use-after-free") {
        BugClass::UseAfterFree
    } else {
        BugClass::Unknown
    }
}

/// Outcome of running the sanitizer-free reproducer against the crash input.
/// This is the triage gate: only a genuine native crash is worth taking to the
/// ROP/pwntools exploit stage — a clean or non-crashing exit is not.
#[derive(Debug, PartialEq, Eq)]
enum ReproOutcome {
    /// Killed by a terminating signal (Unix) or an exception status (Windows) —
    /// a real native crash. Proceed to the exploit path.
    Crashed,
    /// Exited 0: the target ran to completion. Any bug here was only catchable
    /// by ASan, not a native fault — not (yet) exploitable, skip.
    CleanExit,
    /// Non-zero exit with no crash signal: the reproducer harness bailed (bad
    /// crash file, read error) rather than the target crashing. Not reproduced.
    NonCrashExit,
}

impl ReproOutcome {
    /// Whether this outcome represents a genuine crash worth exploiting.
    fn is_crash(&self) -> bool {
        matches!(self, ReproOutcome::Crashed)
    }
}

/// Classify a reproducer run from its terminating signal and exit code.
///
/// `signal` is the terminating signal number on Unix (`None` on Windows or when
/// the process exited normally); `code` is the normal exit code when present.
#[cfg(unix)]
fn classify_repro(signal: Option<i32>, code: Option<i32>) -> ReproOutcome {
    if signal.is_some() {
        ReproOutcome::Crashed
    } else if code == Some(0) {
        ReproOutcome::CleanExit
    } else {
        ReproOutcome::NonCrashExit
    }
}

/// Windows has no signals; a crash surfaces as an NTSTATUS exception code in the
/// exit code (high bit set, e.g. `0xC0000005` access violation, `0xC000001D`
/// illegal instruction).
#[cfg(windows)]
fn classify_repro(_signal: Option<i32>, code: Option<i32>) -> ReproOutcome {
    match code {
        Some(0) => ReproOutcome::CleanExit,
        Some(c) if (c as u32) >= 0xC000_0000 => ReproOutcome::Crashed,
        _ => ReproOutcome::NonCrashExit,
    }
}

/// Result of a PoC attempt. A crash that doesn't reproduce on the
/// sanitizer-free binary is a legitimate *verdict*, not an error — the UI
/// should present it as "not exploitable" rather than a red failure.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PocResult {
    /// A reproducing crash; `script` is the generated pwntools exploit.
    Script { script: String },
    /// The crash did not reproduce natively; `reason` explains the verdict.
    NotExploitable { reason: String },
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn generate_poc(
    app: AppHandle,
    crash_path: String,
    harness_source: String,
    target_files: Vec<String>,
    includes: Vec<String>,
    library_files: Vec<String>,
    clang_override: Option<String>,
    provider: AiProvider,
    function_signature: FunctionSignature,
) -> Result<PocResult, String> {
    // ── Step 1: Check for ROP tool ──────────────────────────────────────────
    emit(&app, "[ 1/5 ] Checking for ROP gadget tool…");
    let rop_tool = find_rop_tool().ok_or_else(|| {
        #[cfg(target_os = "macos")]
        return "No ROP gadget tool found.\n  \
                macOS: brew install radare2".to_string();
        #[cfg(target_os = "windows")]
        return "No ROP gadget tool found.\n  \
                Windows: scoop install radare2\n  \
                (via UniGetUI, Scoop, or winget install radare2.radare2)".to_string();
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        return "No ROP gadget tool found. Install one:\n  \
                pip3 install ROPgadget\n  pip3 install ropper\n  apt/brew install radare2"
            .to_string();
    })?;
    let tool_name = rop_tool_name(&rop_tool);
    emit(&app, format!("      Found: {tool_name}"));

    // Derive .guzzle dir early — needed by both the ASan step and the compile step.
    let guzzle_dir = PathBuf::from(&crash_path)
        .parent()           // crashes/
        .and_then(|p| p.parent()) // .guzzle/
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::temp_dir().join("guzzle_poc"));

    // ── Step 2: Capture ASan crash report ────────────────────────────────────
    emit(&app, "[ 2/6 ] Capturing ASan crash report…");
    let fuzzer_path = guzzle_dir.join(if cfg!(windows) { "fuzzer.exe" } else { "fuzzer" });
    let asan_report = if fuzzer_path.exists() {
        emit(&app, format!("      Running: {} {}", fuzzer_path.display(), crash_path));
        match Command::new(&fuzzer_path)
            .arg(&crash_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stderr).to_string();
                let lines: Vec<&str> = text.lines().take(150).collect();
                let report = lines.join("\n");
                emit(&app, format!("      Captured {} lines of ASan output", lines.len()));
                report
            }
            Err(e) => {
                emit(&app, format!("      WARNING: could not run fuzzer binary: {e}"));
                "(ASan report unavailable)".to_string()
            }
        }
    } else {
        emit(&app, format!("      WARNING: fuzzer binary not found at {} — skipping ASan report", fuzzer_path.display()));
        "(ASan report unavailable — fuzzer binary not found)".to_string()
    };

    // ── Step 3: Write temp files ─────────────────────────────────────────────
    emit(&app, "[ 3/6 ] Preparing reproducer source…");
    let temp_dir = std::env::temp_dir().join("guzzle_poc");
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("Failed to create temp dir: {e}"))?;

    // Write reproducer_main.c
    let main_path = temp_dir.join("reproducer_main.c");
    std::fs::write(&main_path, REPRODUCER_MAIN)
        .map_err(|e| format!("Failed to write reproducer_main.c: {e}"))?;

    // Prepare harness: strip direct target includes, prepend extern "C" block.
    // The extern "C" block uses uint8_t / size_t etc., so inject the standard
    // headers before it — the harness's own includes come after via harness_clean.
    let preamble = "#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>\n#include <stdio.h>\n";
    let harness_clean = strip_target_includes(&harness_source, &target_files);
    let harness_clean = fix_c_fn_linkage(&harness_clean, &target_files);
    let extern_c_block = build_extern_c_block(&target_files, &harness_clean);
    let harness_final = format!("{preamble}{extern_c_block}{harness_clean}");
    let harness_path = temp_dir.join("poc_harness.cpp");
    std::fs::write(&harness_path, &harness_final)
        .map_err(|e| format!("Failed to write poc_harness.cpp: {e}"))?;

    // ── Step 4: Compile reproducer binary ────────────────────────────────────
    emit(&app, "[ 4/6 ] Compiling reproducer binary (no sanitizers)…");

    let clang = clang_override
        .filter(|p| !p.is_empty())
        .or_else(find_best_clang)
        .ok_or_else(|| "No suitable clang found.".to_string())?;

    let reproducer_path = guzzle_dir.join(if cfg!(windows) { "reproducer.exe" } else { "reproducer" });

    // Detect if any C target file defines main() — rename it to avoid conflict
    let target_has_main = target_files.iter()
        .filter(|f| f.ends_with(".c"))
        .any(|f| {
            let src = std::fs::read_to_string(f).unwrap_or_default();
            src.contains("int main(") || src.contains("int main (")
        });

    // -Dmain=__guzzle_target_main is a global preprocessor flag — if passed in a
    // single clang invocation it renames main in reproducer_main.c too, causing a
    // duplicate symbol. Fix: pre-compile any target C file that defines main() into
    // an object file (with the rename), then link the object instead of the source.
    let mut precompiled_objs: Vec<PathBuf> = Vec::new();
    for tf in &target_files {
        if !target_has_main || !tf.ends_with(".c") { continue; }
        let src = std::fs::read_to_string(tf).unwrap_or_default();
        if !src.contains("int main(") && !src.contains("int main (") { continue; }

        let stem = PathBuf::from(tf)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "target".to_string());
        let obj_path = temp_dir.join(format!("{stem}.o"));

        let mut obj_cmd = Command::new(&clang);
        obj_cmd.args(["-O0", "-g", "-c", "-Dmain=__guzzle_target_main"]);
        #[cfg(target_os = "windows")]
        obj_cmd.arg("-D_CRT_SECURE_NO_WARNINGS");
        for inc in &includes { obj_cmd.arg(format!("-I{inc}")); }
        obj_cmd.arg("-x").arg("c").arg(tf);
        obj_cmd.arg("-o").arg(&obj_path);
        obj_cmd.stdout(Stdio::piped());
        obj_cmd.stderr(Stdio::piped());

        let args_display = obj_cmd.get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        emit(&app, format!("      [pre-compile] $ {clang} {args_display}"));

        obj_cmd.current_dir(&temp_dir);
        let mut obj_child = obj_cmd.spawn()
            .map_err(|e| format!("Failed to spawn clang for pre-compile: {e}"))?;
        let obj_stderr = obj_child.stderr.take().unwrap();
        let obj_stdout = obj_child.stdout.take().unwrap();
        let app_pre = app.clone();
        let t1 = tokio::task::spawn_blocking(move || {
            BufReader::new(obj_stderr).lines().map_while(Result::ok)
                .for_each(|l| emit(&app_pre, format!("      {l}")));
        });
        let app_pre2 = app.clone();
        let t2 = tokio::task::spawn_blocking(move || {
            BufReader::new(obj_stdout).lines().map_while(Result::ok)
                .for_each(|l| emit(&app_pre2, format!("      {l}")));
        });
        let obj_status = tokio::task::spawn_blocking(move || obj_child.wait())
            .await.map_err(|e| format!("join: {e}"))?
            .map_err(|e| format!("wait: {e}"))?;
        let _ = t1.await;
        let _ = t2.await;
        if !obj_status.success() {
            return Err(format!("Pre-compile of {tf} failed (exit {}). Check poc_log.", obj_status.code().unwrap_or(-1)));
        }
        precompiled_objs.push(obj_path);
    }

    let mut cmd = Command::new(&clang);
    // No sanitizers — we want real crashes, not ASan-caught ones.
    // -no-pie is Linux-only; macOS ARM64 always produces PIE binaries.
    #[cfg(target_os = "linux")]
    cmd.args(["-O0", "-no-pie", "-fno-stack-protector", "-g"]);
    #[cfg(not(target_os = "linux"))]
    cmd.args(["-O0", "-fno-stack-protector", "-g"]);
    #[cfg(target_os = "windows")]
    cmd.arg("-D_CRT_SECURE_NO_WARNINGS");

    for inc in &includes {
        cmd.arg(format!("-I{inc}"));
    }

    // Harness as C++
    cmd.arg("-x").arg("c++");
    cmd.arg(harness_path.to_str().unwrap());

    // Target files — skip ones we pre-compiled to objects
    let precompiled_sources: std::collections::HashSet<&str> =
        if precompiled_objs.is_empty() { Default::default() }
        else { target_files.iter().filter(|f| f.ends_with(".c") && {
            let src = std::fs::read_to_string(f).unwrap_or_default();
            src.contains("int main(") || src.contains("int main (")
        }).map(|s| s.as_str()).collect() };

    for tf in &target_files {
        if precompiled_sources.contains(tf.as_str()) { continue; }
        let lang = if tf.ends_with(".c") { "c" } else { "c++" };
        cmd.arg("-x").arg(lang).arg(tf);
    }

    // reproducer_main.c as C — no -D rename, so its main() stays as main()
    cmd.arg("-x").arg("c");
    cmd.arg(main_path.to_str().unwrap());

    // Pre-compiled object files (no -x)
    if !precompiled_objs.is_empty() {
        cmd.arg("-x").arg("none");
        for obj in &precompiled_objs {
            cmd.arg(obj);
        }
    }

    // Pre-built libraries
    if !library_files.is_empty() {
        cmd.arg("-x").arg("none");
        for lib in &library_files {
            cmd.arg(lib);
        }
    }

    cmd.arg("-o").arg(reproducer_path.to_str().unwrap());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let args_display = cmd.get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    emit(&app, format!("      $ {clang} {args_display}"));

    cmd.current_dir(&temp_dir);
    let mut child = cmd.spawn()
        .map_err(|e| format!("Failed to spawn clang: {e}"))?;

    let stderr = child.stderr.take().unwrap();
    let app_e = app.clone();
    let t_err = tokio::task::spawn_blocking(move || {
        BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
            .for_each(|l| emit(&app_e, format!("      {l}")));
    });

    let stdout = child.stdout.take().unwrap();
    let app_o = app.clone();
    let t_out = tokio::task::spawn_blocking(move || {
        BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
            .for_each(|l| emit(&app_o, format!("      {l}")));
    });

    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .map_err(|e| format!("join: {e}"))?
        .map_err(|e| format!("wait: {e}"))?;

    let _ = t_err.await;
    let _ = t_out.await;

    if !status.success() {
        return Err(format!(
            "Reproducer compilation failed (exit {}). Check poc_log for details.",
            status.code().unwrap_or(-1)
        ));
    }
    emit(&app, format!("      Compiled: {}", reproducer_path.display()));
    emit(&app, format!("      Run it as: {} <crash_file>", reproducer_path.display()));

    // ── Step 5: Verify crash reproduces ──────────────────────────────────────
    // Triage gate: the reproducer is built WITHOUT sanitizers, so only a genuine
    // native fault (a terminating signal on Unix / exception status on Windows)
    // counts as reproduced. An exit 0 means the bug was ASan-only; a non-zero
    // non-crash exit means the harness bailed. Neither is worth the exploit path,
    // so we stop here rather than hand the AI a crash that doesn't exist.
    emit(&app, "[ 5/6 ] Verifying crash reproduces…");
    let verify = Command::new(reproducer_path.to_str().unwrap())
        .arg(&crash_path)
        .current_dir(&temp_dir)
        .output();

    let out = verify.map_err(|e| {
        format!("Could not run reproducer to verify the crash: {e}. Aborting — cannot confirm the crash is real.")
    })?;

    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        out.status.signal()
    };
    #[cfg(not(unix))]
    let signal: Option<i32> = None;

    let code = out.status.code();
    let outcome = classify_repro(signal, code);
    if outcome.is_crash() {
        let how = signal
            .map(|s| format!("signal {s}"))
            .or_else(|| code.map(|c| format!("exit 0x{:08X}", c as u32)))
            .unwrap_or_else(|| "abnormal termination".into());
        emit(&app, format!("      Crash reproduced on sanitizer-free binary ({how}) ✓"));
    } else {
        let reason = match outcome {
            ReproOutcome::CleanExit =>
                "The sanitizer-free reproducer exited cleanly (0). This crash was an \
                 ASan-only catch, not a native fault — not exploitable as-is."
                    .to_string(),
            _ => {
                let code = code.unwrap_or(-1);
                format!(
                    "The reproducer exited {code} with no crash signal (likely a harness or \
                     crash-file problem, not a native fault) — the crash did not reproduce."
                )
            }
        };
        emit(&app, format!("      Verdict: not exploitable — {reason}"));
        return Ok(PocResult::NotExploitable { reason });
    }

    // ── Step 6: Extract ROP gadgets ──────────────────────────────────────────
    let bug_class = detect_bug_class(&asan_report);
    emit(&app, format!("[ 6/6 ] Extracting ROP gadgets with {tool_name}…"));
    let gadgets = match run_rop_tool(&rop_tool, reproducer_path.to_str().unwrap(), &temp_dir) {
        Ok(g) => {
            let count = g.lines().count();
            emit(&app, format!("      Found {count} gadget lines (truncated at 200)"));
            g
        }
        Err(e) => {
            emit(&app, format!("      WARNING: gadget extraction failed: {e}"));
            String::from("(gadget extraction failed)")
        }
    };

    // ── Step 6: Call AI ──────────────────────────────────────────────────────
    emit(&app, "[ AI  ] Sending to AI for PoC script generation…");

    let crash_bytes = std::fs::read(&crash_path).unwrap_or_default();
    let crash_size = crash_bytes.len();
    // Send up to 512 bytes — enough to capture full chunk structures in format-based
    // parsers (e.g. length-prefixed inputs) so the AI can identify the bug class
    // from the actual input layout rather than guessing.
    let preview_cap = 512.min(crash_size);
    let truncated = crash_size > preview_cap;
    let hex_preview: String = crash_bytes
        .iter()
        .take(preview_cap)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let hex_preview = if truncated {
        format!("{hex_preview}  … ({} bytes total, first {preview_cap} shown)", crash_size)
    } else {
        hex_preview
    };

    // Extract the target function's source so the AI can see the actual bug
    // (e.g. integer overflow in size calculation before malloc) rather than
    // guessing the vulnerability class from the signature alone.
    let target_func_source: String = target_files.iter()
        .find_map(|tf| {
            let src = std::fs::read_to_string(tf).ok()?;
            let lines: Vec<&str> = src.lines().collect();
            let start = (function_signature.start_line as usize).saturating_sub(1);
            let end = (function_signature.end_line as usize).min(lines.len());
            let snippet = lines.get(start..end)?.join("\n");
            if snippet.contains(&function_signature.name) { Some(snippet) } else { None }
        })
        .unwrap_or_else(|| "(source not available)".to_string());

    let param_str = function_signature
        .params
        .iter()
        .map(|p| format!("{} {}", p.type_name, p.param_name))
        .collect::<Vec<_>>()
        .join(", ");
    let func_sig = format!(
        "{} {}({})",
        function_signature.return_type, function_signature.name, param_str
    );

    let system = "You are an expert binary exploitation researcher. \
        Generate complete, runnable pwntools Python3 exploit scripts. \
        Output only raw Python code with no markdown fences and no explanation."
        .to_string();

    // Platform-specific notes injected into the prompt.
    #[cfg(target_os = "macos")]
    let platform_ctx = format!(
        "Platform: macOS {} (Mach-O binary, PIE always enabled — ASLR cannot be \
         disabled per-process on macOS without disabling SIP)\n\
         Binary format: Mach-O — pwntools ELF() does NOT support Mach-O; use \
         hardcoded gadget addresses from the radare2 output below.\n\
         Architecture: {arch}\n\
         To disable ASLR in lldb for manual testing:\n\
           lldb -- {rp} <crash_file>\n\
           (lldb) settings set target.disable-aslr true\n\
           (lldb) run",
        std::env::consts::OS,
        arch = std::env::consts::ARCH,
        rp = reproducer_path.display(),
    );
    #[cfg(target_os = "linux")]
    let platform_ctx = format!(
        "Platform: Linux {} (ELF binary, compiled -no-pie so base is fixed)\n\
         Architecture: {arch}\n\
         Disable ASLR: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space",
        std::env::consts::OS,
        arch = std::env::consts::ARCH,
    );
    #[cfg(target_os = "windows")]
    let platform_ctx = format!(
        "Platform: Windows {} (PE binary, ASLR enabled by default)\n\
         Architecture: {arch}\n\
         pwntools has limited Windows support — the exploit script may need \
         to be run under WSL or adapted for Windows process handling.",
        std::env::consts::OS,
        arch = std::env::consts::ARCH,
    );
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let platform_ctx = format!(
        "Platform: {} {}", std::env::consts::OS, std::env::consts::ARCH
    );

    // Frame gadgets based on bug class. For heap bugs at stage 1, a full gadget
    // dump is noise — the AI needs a write primitive before gadgets are useful.
    let gadgets_section = match bug_class {
        BugClass::StackOverflow => gadgets,
        BugClass::HeapOverflow | BugClass::UseAfterFree => format!(
            "(Gadgets extracted and available for stage 2 exploitation once a write primitive \
             is established — see the full list below. Do NOT attempt to use them yet: the \
             adjacent heap object and corruption target must be identified first.)\n\n{gadgets}"
        ),
        BugClass::Unknown => gadgets,
    };

    // Truncate harness source to avoid blowing the context window.
    let harness_preview: String = harness_final
        .lines()
        .take(100)
        .collect::<Vec<_>>()
        .join("\n");

    let user = format!(
        r#"You are an expert binary exploitation researcher.

Target function: {func_sig}
Crash input hex: {hex_preview}
Crash input size: {crash_size} bytes
{platform_ctx}

ASan crash report (from running the fuzzer binary on the crash input):
{asan_report}
Reproducer binary: {reproducer_path}
Reproducer invocation: {reproducer_path} <crash_file_path>
IMPORTANT: the reproducer reads the payload from a FILE passed as argv[1], NOT from stdin.
To deliver a payload: write the bytes to a temp file, then run the reproducer with that path.
Do NOT use p.send() or p.sendline() — the process exits with code 1 if no file argument is given.
When calling process(), pass the binary path as a string:
  process(['/path/to/reproducer', temp_path])   # correct
  process([context.binary, temp_path])           # wrong — ELF object, not a string
IMPORTANT: for heap overflows, the reproducer may exit 0 without ASan — the corrupted
allocation returns normally. Do NOT call p.corefile on exit code 0. Check the exit code:
non-zero or a signal (SIGSEGV/SIGABRT) confirms native reproduction. Exit code 0 means
the overflow is real but only reliably detected with ASan (use the fuzzer binary to confirm).

Target function source:
```c
{target_func_source}
```

Fuzzer harness source (shows how the crash input maps to function arguments):
```c
{harness_preview}
```

ROP gadgets:
{gadgets_section}

The ASan report above identifies the vulnerability class. Generate a complete pwntools
Python3 exploit script appropriate for that class:

If STACK overflow:
  - Use cyclic() to find the exact offset to the saved return address
  - On x86_64: overwrite RIP; on ARM64: overwrite the saved x30 (link register) on the stack
  - Demonstrate control of the instruction pointer
  - Use the ROP gadgets above to build a ret2libc / ret2system chain

If HEAP overflow:
  - Do NOT use cyclic() — there is no stack offset to find
  - Craft an input that triggers the overflow and demonstrates the out-of-bounds write
  - Stage 1 goal: identify what object sits adjacent to the overflow buffer in memory
    and which of its fields can be corrupted (length, pointer, function pointer)
  - Stage 2 (once a write primitive is established): use the ROP gadgets to redirect
    execution — but do NOT attempt to build a ROP chain in this script yet, because
    the adjacent object and corruption target are not yet known
  - On Linux/glibc: note tcache/fastbin/unsorted-bin grooming techniques
  - On macOS/libmalloc: note magazine allocator metadata corruption

If USE-AFTER-FREE or OOB READ:
  - Craft an input that triggers the condition
  - Show how to achieve an information leak or controlled write

Always:
- Comment at the top: vulnerability class identified and why
- Comment each step of the script
- Note ASLR situation (from the platform context above) and how it affects exploitation

Return ONLY the Python3 source code, no markdown fences."#,
        reproducer_path = reproducer_path.display(),
    );

    let script = call_ai(&provider, system, user).await?;
    emit(&app, "      PoC script generated ✓");

    Ok(PocResult::Script { script })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reproducer_binary_name_has_exe_on_windows() {
        let name = if cfg!(windows) { "reproducer.exe" } else { "reproducer" };
        if cfg!(windows) {
            assert!(name.ends_with(".exe"));
        } else {
            assert!(!name.contains('.'));
        }
    }

    #[test]
    fn reproducer_main_contains_llvm_entry_point() {
        assert!(REPRODUCER_MAIN.contains("LLVMFuzzerTestOneInput"));
        assert!(REPRODUCER_MAIN.contains("int main("));
    }

    #[test]
    fn reproducer_main_no_main_rename_define() {
        // REPRODUCER_MAIN must never contain the rename macro — that would
        // defeat the purpose of the two-pass pre-compile workaround.
        assert!(!REPRODUCER_MAIN.contains("__guzzle_target_main"));
    }

    #[test]
    fn rop_tool_name_covers_all_variants() {
        assert_eq!(rop_tool_name(&RopTool::ROPgadget), "ROPgadget");
        assert_eq!(rop_tool_name(&RopTool::Ropper),    "ropper");
        assert_eq!(rop_tool_name(&RopTool::Radare2),   "radare2");
    }

    #[test]
    fn macos_no_pie_flag_absent_from_non_linux_build() {
        // On macOS ARM64 the linker rejects -no-pie; verify it is gated.
        let src = include_str!("poc.rs");
        let no_pie_pos  = src.find("\"-no-pie\"").expect("\"-no-pie\" not found in poc.rs");
        let cfg_pos     = src[..no_pie_pos].rfind("#[cfg(target_os = \"linux\")]")
            .expect("-no-pie must be inside a #[cfg(target_os = \"linux\")] block");
        assert!(cfg_pos < no_pie_pos);
    }

    #[test]
    fn detect_bug_class_stack() {
        let report = "AddressSanitizer: stack-buffer-overflow on address 0x...";
        assert_eq!(detect_bug_class(report), BugClass::StackOverflow);
    }

    #[test]
    fn detect_bug_class_heap() {
        let report = "AddressSanitizer: heap-buffer-overflow on address 0x...";
        assert_eq!(detect_bug_class(report), BugClass::HeapOverflow);
    }

    #[test]
    fn detect_bug_class_uaf() {
        let report = "AddressSanitizer: heap-use-after-free on address 0x...";
        assert_eq!(detect_bug_class(report), BugClass::UseAfterFree);
    }

    #[test]
    fn detect_bug_class_unknown() {
        assert_eq!(detect_bug_class("(ASan report unavailable)"), BugClass::Unknown);
        assert_eq!(detect_bug_class("SEGV on unknown address 0x0"), BugClass::Unknown);
    }

    #[test]
    fn detect_bug_class_case_insensitive() {
        assert_eq!(detect_bug_class("HEAP-BUFFER-OVERFLOW"), BugClass::HeapOverflow);
        assert_eq!(detect_bug_class("Stack-Buffer-Overflow"), BugClass::StackOverflow);
    }

    #[test]
    fn reproducer_verify_uses_temp_dir_not_src_tauri() {
        // This is a static analysis guard: the verification Command must call
        // current_dir so the harness can't write temp files to the cargo cwd
        // (src-tauri/), which would trigger Tauri's file watcher and restart
        // the app. We verify the source contains the expected call.
        let src = include_str!("poc.rs");
        // Find the verify block and confirm current_dir appears before .output()
        let verify_pos = src.find("let verify = Command::new").expect("verify block not found");
        let output_pos = src[verify_pos..].find(".output()").expect(".output() not found") + verify_pos;
        let current_dir_pos = src[verify_pos..].find(".current_dir(&temp_dir)").map(|p| p + verify_pos);
        assert!(
            current_dir_pos.map_or(false, |p| p < output_pos),
            "reproducer verify Command must set current_dir before .output()"
        );
    }

    #[cfg(unix)]
    #[test]
    fn classify_repro_unix_signal_is_crash() {
        // Killed by SIGSEGV / SIGABRT / SIGBUS → genuine native crash.
        assert_eq!(classify_repro(Some(11), None), ReproOutcome::Crashed);
        assert_eq!(classify_repro(Some(6), None), ReproOutcome::Crashed);
        assert_eq!(classify_repro(Some(10), None), ReproOutcome::Crashed);
    }

    #[cfg(unix)]
    #[test]
    fn classify_repro_unix_exit_zero_is_clean() {
        // Ran to completion with 0 → only ASan would have caught it. Not a crash.
        assert_eq!(classify_repro(None, Some(0)), ReproOutcome::CleanExit);
    }

    #[cfg(unix)]
    #[test]
    fn classify_repro_unix_nonzero_exit_is_not_crash() {
        // Non-zero exit with no signal = harness/file problem, not a reproduced crash.
        assert_eq!(classify_repro(None, Some(1)), ReproOutcome::NonCrashExit);
        assert_eq!(classify_repro(None, None), ReproOutcome::NonCrashExit);
    }

    #[cfg(windows)]
    #[test]
    fn classify_repro_windows_exception_code_is_crash() {
        // No signals on Windows; a crash surfaces as an NTSTATUS exception code
        // with the high bit set, e.g. 0xC0000005 (access violation).
        assert_eq!(classify_repro(None, Some(0xC0000005u32 as i32)), ReproOutcome::Crashed);
        assert_eq!(classify_repro(None, Some(0xC000001Du32 as i32)), ReproOutcome::Crashed);
    }

    #[cfg(windows)]
    #[test]
    fn classify_repro_windows_clean_and_benign() {
        assert_eq!(classify_repro(None, Some(0)), ReproOutcome::CleanExit);
        assert_eq!(classify_repro(None, Some(1)), ReproOutcome::NonCrashExit);
    }

    #[test]
    fn only_crashed_outcome_proceeds_to_exploit() {
        assert!(ReproOutcome::Crashed.is_crash());
        assert!(!ReproOutcome::CleanExit.is_crash());
        assert!(!ReproOutcome::NonCrashExit.is_crash());
    }
}
