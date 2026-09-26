use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use serde::Serialize;
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

/// Platform-specific one-liner for running the reproducer under a debugger,
/// used in the next-steps guidance so the user can inspect where the crash
/// actually lands (intermediate-pointer deref vs. reaching the return). Both
/// the reproducer and the crash file are real paths so the line is runnable.
fn debugger_hint(reproducer: &str, crash: &str) -> String {
    #[cfg(target_os = "macos")]
    { format!("lldb -o 'run {crash}' -o 'bt' -o 'register read pc' -- {reproducer}") }
    #[cfg(target_os = "linux")]
    { format!("gdb --args {reproducer} {crash}   # then: run; bt; info registers pc") }
    #[cfg(target_os = "windows")]
    { format!("cdb -g -G {reproducer} {crash}   # or open in WinDbg; inspect the faulting instruction") }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    { format!("run {reproducer} {crash} under your platform debugger and inspect the faulting PC") }
}

/// Deterministic, staged next-steps guidance emitted by Guzzle itself, so the
/// user gets a concrete plan even when the AI half is unavailable or terse.
/// Tailored per bug class; steps are actionable, not vague.
fn next_steps_lines(bug_class: &BugClass, reproducer: &str, fuzzer: &str, crash: &str) -> Vec<String> {
    let dbg = debugger_hint(reproducer, crash);

    // ASLR note is the same shape everywhere but the mechanism differs.
    #[cfg(target_os = "linux")]
    let aslr = "The reproducer is built -no-pie, so the base is fixed. Disable ASLR while \
                developing: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space".to_string();
    #[cfg(target_os = "macos")]
    let aslr = "macOS forces PIE and randomizes the base per run — an absolute-address chain \
                needs an info leak first. For local testing, lldb's `settings set \
                target.disable-aslr true` pins the base so you can prove the technique.".to_string();
    #[cfg(target_os = "windows")]
    let aslr = "Windows enables ASLR by default — an absolute-address chain needs an info leak \
                first, or a module compiled without /DYNAMICBASE.".to_string();
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let aslr = "Account for ASLR: an absolute-address chain needs a fixed base or an info leak.".to_string();

    match bug_class {
        BugClass::StackOverflow => vec![
            "NEXT STEPS (stack-buffer-overflow):".to_string(),
            " 1. Confirm WHERE it crashes before assuming return-address control. A stack".to_string(),
            "    overflow usually smashes local pointer variables too, and those are often".to_string(),
            "    dereferenced BEFORE the function returns — so a naive smash faults on a bad".to_string(),
            "    pointer, not on the return. Check under a debugger:".to_string(),
            format!("      {dbg}"),
            "    If the crashing PC is INSIDE the target function → an intermediate pointer".to_string(),
            "    was smashed (see step 2). If the PC is an attacker-controlled address →".to_string(),
            "    the saved return address is reached (skip to step 3).".to_string(),
            " 2. Intermediate-pointer case: keep those locals valid in your input, or steer".to_string(),
            "    the control flow to a bail-out path that skips the deref, so execution".to_string(),
            "    survives to the function epilogue.".to_string(),
            " 3. Find the exact offset to the saved return address with a cyclic pattern;".to_string(),
            "    pad PAST the slot if the code writes a terminator after your copy.".to_string(),
            format!(" 4. {aslr}"),
            " 5. Point the return at your target (ret2win to a resident function, or a".to_string(),
            "    ret2libc/ret2system chain from the gadgets above).".to_string(),
        ],
        BugClass::HeapOverflow => vec![
            "NEXT STEPS (heap-buffer-overflow):".to_string(),
            " 1. There is no return-address offset — do NOT use cyclic(). The goal is a".to_string(),
            "    write primitive over an adjacent heap object.".to_string(),
            " 2. From the source, identify what allocation lands immediately AFTER the".to_string(),
            "    overflow buffer, and which of its fields you can corrupt (length, pointer,".to_string(),
            "    function pointer).".to_string(),
            format!(" 3. Inspect heap state at the crash: {dbg}"),
            " 4. Groom the heap from input bytes so the victim object is adjacent, then".to_string(),
            "    corrupt exactly the field you identified.".to_string(),
            format!(" 5. {aslr}"),
            " 6. Once you control a pointer/length, escalate to execution using the gadgets".to_string(),
            "    above.".to_string(),
        ],
        BugClass::UseAfterFree => vec![
            "NEXT STEPS (use-after-free):".to_string(),
            " 1. Identify the freed object and the code path that still uses it.".to_string(),
            " 2. Reclaim the freed chunk with an allocation you control the contents of".to_string(),
            "    (same size class), so the stale pointer now reads your data.".to_string(),
            " 3. Aim for a controlled function pointer or length field to convert the".to_string(),
            "    type confusion into a leak or a write.".to_string(),
            format!(" 4. Inspect allocator state at the crash: {dbg}"),
            format!(" 5. {aslr}"),
        ],
        BugClass::Unknown => vec![
            "NEXT STEPS (bug class not identified from the ASan report):".to_string(),
            " 1. Re-run the fuzzer binary on the crash input for a full ASan report and bug".to_string(),
            "    class:".to_string(),
            format!("      {fuzzer} {crash}"),
            " 2. Inspect the native crash:".to_string(),
            format!("      {dbg}"),
            " 3. A SEGV on address 0x0 is usually a null-deref (not directly exploitable);".to_string(),
            "    a SEGV on an input-derived address is worth pursuing.".to_string(),
        ],
    }
}

// ── Native control-flow assessment ───────────────────────────────────────────
//
// A stack overflow's ASan class ("stack-buffer-overflow") does NOT establish
// whether the saved return address is actually controllable. On the clean
// (non-sanitizer) reproducer the honest ground-truth signal is: at the fault,
// do $pc or the saved-return slot on the stack contain bytes drawn from the
// crash input?
//
// The taxonomy is deliberately more than binary — the middle cases are exactly
// where an auto-PoC tool overclaims ("RCE!") or underclaims (buries a real bug):
//   * ReturnControl                  — $pc holds input bytes, reached by `ret`
//                                      OR an indirect call/jmp through a
//                                      corrupted pointer. Both are control flow.
//   * PartialControl(n)              — only the low n (1..=2) bytes of $pc are
//                                      input; a partial RA overwrite is still
//                                      control, not "none".
//   * DerefBeforeControllableReturn  — $pc is valid code faulting on a data
//                                      dereference BEFORE the return, but the
//                                      saved return slot already holds input:
//                                      survive the deref and the return is yours.
//   * PointerWritePrimitive          — a fully attacker-controlled data pointer
//                                      is dereferenced: ~an arbitrary read/write,
//                                      no return control needed. High severity.
//   * DerefOnly                      — partial pointer control (low bytes input,
//                                      high bytes a live base). Real, but not a
//                                      full R/W and not confirmed RCE.
//   * Uncertain                      — crashed, but $pc/stack can't be tied to
//                                      the input (PIE/ASLR noise, or an abort).
//   * NoNativeCrash                  — clean exit; only ASan catches this bug.
//
// Ordering is load-bearing: the $pc-control path is gated on `!pc_symbolized`
// (a symbolized $pc is mapped code, so control was not redirected to input);
// run-length only matters once $pc fails to symbolize. ret2libc control lives
// in the saved-RA slot, detected by the stack inspection, not by $pc.

#[derive(Debug, PartialEq, Clone)]
enum ControlAssessment {
    ReturnControl,
    PartialControl(usize),
    DerefBeforeControllableReturn,
    /// The overflow yields a fully attacker-controlled data pointer that the
    /// code dereferences — a controlled-address primitive, even without
    /// return-address control. Neutral on direction: a controlled address on a
    /// load is an arbitrary READ (info leak), on a store an arbitrary WRITE.
    /// The access direction is carried separately (from the faulting
    /// instruction) so the headline never asserts more than the fault proves.
    ControlledDerefPrimitive,
    DerefOnly,
    Uncertain,
    NoNativeCrash,
}

/// Direction of the faulting memory access on the clean reproducer. A
/// controlled fault address means an arbitrary read (leak) on a load and an
/// arbitrary write on a store — different severities, so we never conflate them.
#[derive(Debug, PartialEq, Clone, Copy)]
enum Access {
    Read,
    Write,
}

#[derive(Debug, Default, Clone)]
struct CrashProbe {
    pc: Option<u64>,
    pc_symbolized: bool,      // $pc resolved to a known module`symbol / source line
    location: Option<String>, // e.g. "load_one at kvstore.c:63"
    fault_addr: Option<u64>,  // faulting data address (deref target), if reported
    access: Option<Access>,   // read vs write at the fault, from the faulting instruction
    stack_words: Vec<u64>,    // words dumped from $sp upward (index i = *(sp + 8i))
    /// The saved RETURN ADDRESS value, located precisely (arm64: the frame's
    /// `ldp x29, x30, [sp, #N]` epilogue → the word at sp+N+8; x86: *(rbp+8)).
    /// This is the actual return slot — NOT a window scan, which would match the
    /// overflow buffer sitting on the stack and always look "controlled".
    ra_slot: Option<u64>,
    clean_exit: bool,
}

/// Classify a disassembled faulting instruction as a read or a write.
/// arm64 is unambiguous (`ld*` load = read, `st*` store = write). For x86 in
/// AT&T syntax (gdb default) the destination is the last operand, so a memory
/// destination `(...)` is a write and a memory source is a read. Returns None
/// when the direction can't be established — the caller then stays neutral.
fn classify_access(instr: &str) -> Option<Access> {
    let t = instr.trim().to_ascii_lowercase();
    // Mnemonic = first whitespace-delimited token.
    let mnem = t.split_whitespace().next().unwrap_or("");
    // arm64: load/store prefixes are definitive.
    if mnem.starts_with("ld") { return Some(Access::Read); }
    if mnem.starts_with("st") { return Some(Access::Write); }
    // x86 AT&T: inspect operands (only meaningful if a memory operand exists).
    if let Some(ops) = t.split_once(char::is_whitespace).map(|(_, o)| o) {
        if ops.contains('(') {
            let last = ops.rsplit(',').next().unwrap_or("").trim();
            return Some(if last.contains('(') { Access::Write } else { Access::Read });
        }
    }
    None
}

/// Longest prefix of `val`'s little-endian bytes (b0, b0b1, …) that occurs as a
/// contiguous run anywhere in `input`. The overflow writes input bytes low→high
/// into a slot, so a controlled value's low bytes match a window of the input.
/// Returns 0..=8.
fn le_prefix_run_in_input(val: u64, input: &[u8]) -> usize {
    if input.is_empty() { return 0; }
    let bytes = val.to_le_bytes();
    for len in (1..=8).rev() {
        let needle = &bytes[..len];
        // Zero bytes are ubiquitous filler (uninitialized stack, padding, small
        // values), not attacker payload — a stack word that is mostly zeros will
        // otherwise "match" any input that contains a run of zeros (almost all of
        // them), falsely inflating the control verdict. Require at least one
        // non-zero byte so the match reflects real attacker-placed data. A
        // genuine all-0x41 return value still counts; an all-0x00 one does not.
        if needle.iter().all(|&b| b == 0) { continue; }
        if input.windows(len).any(|w| w == needle) {
            return len;
        }
    }
    0
}

/// Classify the control-flow situation from a parsed probe + the crash input.
///
/// Ordering matters (this is the crux): the ground truth for $pc is NOT its
/// run-length against the input, it is whether $pc resolves to a symbol. A
/// symbolized $pc points at mapped executable code, so control was NOT
/// redirected to an input-controlled address — even if the address happens to
/// share a few low bytes with an input run. So the $pc-control path is gated on
/// `!pc_symbolized`; run-length only matters once $pc fails to symbolize. This
/// also makes it PIE-robust: a legitimate PIE code address still symbolizes.
///
/// Control via ret2libc / ret2existing-code redirects $pc to a REAL function
/// (which symbolizes) — that control lives in the saved-RA slot on the stack,
/// which is exactly why the stack-RA inspection carries it.
///
/// Byte-width thresholds: a canonical x86-64 user address is 48 bits = 6
/// meaningful bytes (the top two are 0x0000), so 6 input bytes IS the full
/// controllable width of a valid address — hence `>= 6` for "full" control and
/// 3..=5 for "partial". The probe runs with ASLR disabled so addresses are
/// stable while we reason.
fn classify_control(p: &CrashProbe, input: &[u8]) -> ControlAssessment {
    if p.clean_exit { return ControlAssessment::NoNativeCrash; }
    let Some(pc) = p.pc else { return ControlAssessment::Uncertain; };

    // 1) $pc-based control — ONLY when $pc does not resolve to real code.
    //    A single coincidental input byte is ~guaranteed in any non-trivial
    //    input, so pc_run == 1 is noise and falls through.
    //    Ordering choice (deliberate): an observed $pc hijack — even partial —
    //    is a more concrete signal than a latent fully-controllable RA slot that
    //    still depends on surviving to the epilogue, so it headlines first. If a
    //    partial $pc coincides with a full RA slot, we lead with the observed
    //    hijack rather than the latent primitive. (First-match, not most-severe.)
    if !p.pc_symbolized {
        let pc_run = le_prefix_run_in_input(pc, input);
        if pc_run >= 6 { return ControlAssessment::ReturnControl; }
        if pc_run >= 2 { return ControlAssessment::PartialControl(pc_run); }
    }

    // 2) Otherwise control, if any, lives in the PRECISE saved-return slot
    //    (p.ra_slot, located via the epilogue). A window scan is NOT usable here:
    //    the overflow buffer sits on the stack and always contains the input, so
    //    scanning would report "controlled" for every overflow.
    let ra_run = p.ra_slot.map(|w| le_prefix_run_in_input(w, input)).unwrap_or(0);

    if ra_run >= 6 {
        // The REAL saved return address holds input bytes → the return is
        // controlled. A demonstrably-hijacked $pc is already handled above, so
        // reaching here means we crashed before/at the return: control is
        // reachable through the return slot (survive any deref first).
        return ControlAssessment::DerefBeforeControllableReturn;
    }
    if ra_run >= 3 {
        // Partial overwrite of the real saved-RA slot — latent partial control.
        return ControlAssessment::PartialControl(ra_run);
    }

    let deref_run = p.fault_addr
        .map(|fa| le_prefix_run_in_input(fa, input))
        .unwrap_or(0);

    // 3) No return control. Grade the corrupted data pointer.
    //    Full control of the fault address is a controlled-address primitive
    //    (read or write — direction from p.access); 4..=5 is partial pointer
    //    control (low bytes input, high bytes a live base).
    if deref_run >= 6 { return ControlAssessment::ControlledDerefPrimitive; }
    if deref_run >= 4 { return ControlAssessment::DerefOnly; }

    ControlAssessment::Uncertain
}

/// Human-readable verdict for the log and the AI prompt. Phrased to avoid
/// overclaiming: control is only asserted when $pc/RA are demonstrably input.
fn control_headline(a: &ControlAssessment, p: &CrashProbe) -> String {
    let loc = p.location.clone().unwrap_or_else(|| "the target function".to_string());
    match a {
        ControlAssessment::ReturnControl =>
            "CONTROL — $pc is attacker-controlled (the saved return address, or an indirect \
             branch target, resolves to crash-input bytes). Return-address control looks \
             achievable; proceed to a ret2win / ROP chain.".to_string(),
        ControlAssessment::PartialControl(n) =>
            format!("PARTIAL CONTROL — {n} input byte(s) reach the saved return address / $pc \
             (a partial overwrite). Real control, but narrower than full width; widen the \
             overwrite or work within the fixed high bytes."),
        ControlAssessment::DerefBeforeControllableReturn =>
            format!("REACHABLE CONTROL, blocked by a deref — the crash is a corrupted-pointer \
             dereference inside {loc}, BEFORE the return, but the saved return slot already \
             holds your input bytes. Keep that pointer valid (or take a bail-out path) to \
             survive to the epilogue; control follows."),
        ControlAssessment::ControlledDerefPrimitive => {
            // Never assert a write on a read. Direction comes from the faulting
            // instruction; stay neutral (and say so) when it is unknown.
            let (kind, note) = match p.access {
                Some(Access::Write) => ("arbitrary WRITE",
                    "target a GOT/PLT entry, a function pointer, or a saved return address."),
                Some(Access::Read) => ("arbitrary READ (info leak)",
                    "leak a base/canary to defeat ASLR, then escalate — this is a read, not yet a write."),
                None => ("controlled dereference (READ or WRITE — check the faulting instruction)",
                    "confirm the access direction before claiming a write primitive."),
            };
            format!("CONTROLLED-ADDRESS PRIMITIVE — the overflow hands you a fully \
             attacker-controlled pointer that {loc} dereferences: an {kind} of a chosen \
             address, no return-address control required. {note}")
        }
        ControlAssessment::DerefOnly =>
            format!("PARTIAL POINTER CONTROL — {loc} dereferences a pointer whose low bytes \
             are input but whose high bytes are a live base (partial control). Real, but not \
             yet a full arbitrary read/write; not confirmed RCE — widen the controlled bytes."),
        ControlAssessment::Uncertain =>
            "UNCERTAIN — crashed, but $pc/stack could not be tied to the crash input (likely \
             PIE/ASLR noise or an abort). Re-run with ASLR disabled and reason base-relative \
             before claiming control.".to_string(),
        ControlAssessment::NoNativeCrash =>
            "NO NATIVE CRASH — the clean reproducer exited normally; the overflow is real but \
             only reliably caught by ASan. Confirm with the fuzzer binary.".to_string(),
    }
}

/// Parse an lldb `--batch` transcript (with `-k` crash handlers that dump pc/sp
/// and stack memory) into a CrashProbe. Wired to the runner on macOS; on other
/// platforms it is exercised only by the unit tests.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_lldb_probe(text: &str) -> CrashProbe {
    let mut p = CrashProbe::default();
    if (text.contains("exited with status = 0") || text.contains("exited with status = 0 "))
        && !text.contains("stop reason =") {
        p.clean_exit = true;
        return p;
    }
    for line in text.lines() {
        let t = line.trim();
        // EXC_BAD_ACCESS (code=1, address=0x....)
        if let Some(idx) = t.find("address=0x") {
            if let Some(v) = parse_hex_u64(&t[idx + "address=".len()..]) { p.fault_addr = Some(v); }
        }
        // "      pc = 0x....  module`symbol + N at file:line"
        if let Some(rest) = t.strip_prefix("pc = ") {
            if let Some(v) = parse_hex_u64(rest) { p.pc = Some(v); }
            if rest.contains('`') || rest.contains(" at ") {
                p.pc_symbolized = true;
            }
        }
        // "frame #0: 0x.... module`symbol(...) at file:line"
        if t.starts_with("frame #0:") {
            if t.contains('`') || t.contains(" at ") { p.pc_symbolized = true; }
            p.location = extract_symbol_location(t).or(p.location.take());
        }
        // current-instruction marker from `disassemble`: "->  0x..: ldr w8, [x8]"
        if p.access.is_none() && t.contains("->") {
            if let Some(cidx) = t.rfind(':') {
                let instr = t[cidx + 1..].trim();
                if !instr.is_empty() { p.access = classify_access(instr); }
            }
        }
        // stack dump lines: "0xADDR: 0xWORD 0xWORD ..."
        if let Some(cidx) = t.find(':') {
            if t.starts_with("0x") && t[..cidx].chars().skip(2).all(|c| c.is_ascii_hexdigit()) {
                for tok in t[cidx + 1..].split_whitespace() {
                    if let Some(v) = parse_hex_u64(tok) { p.stack_words.push(v); }
                }
            }
        }
    }
    // Locate the REAL saved-return slot from the epilogue: x30 sits at sp+N+8,
    // and stack_words[i] = *(sp + 8i), so the slot is stack_words[(N+8)/8].
    if let Some(ra_off) = parse_ra_offset_arm64(text) {
        if ra_off % 8 == 0 {
            p.ra_slot = p.stack_words.get((ra_off / 8) as usize).copied();
        }
    }
    p
}

/// Parse a gdb `-batch` transcript. gdb keeps executing `-ex` commands after a
/// signal, so pc/sp come from a `printf`, the fault address from `$_siginfo`,
/// and the stack from `x/Nxg $sp`. Wired to the runner on Linux; on other
/// platforms it is exercised only by the unit tests.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_gdb_probe(text: &str) -> CrashProbe {
    let mut p = CrashProbe::default();
    if text.contains("exited normally") && !text.contains("received signal") {
        p.clean_exit = true;
        return p;
    }
    for line in text.lines() {
        let t = line.trim();
        // our injected: "PC=0x.... SP=0x...."
        if let Some(rest) = t.strip_prefix("PC=") {
            let mut it = rest.split_whitespace();
            if let Some(pc) = it.next() { p.pc = parse_hex_u64(pc); }
        }
        // our injected: "RA=0x...." — the precise saved return, *(rbp+8).
        if let Some(rest) = t.strip_prefix("RA=") {
            p.ra_slot = parse_hex_u64(rest.trim());
        }
        // si_addr from "$N = 0x...."
        if t.contains("= 0x") && p.fault_addr.is_none() && t.starts_with('$') {
            if let Some(idx) = t.find("0x") { p.fault_addr = parse_hex_u64(&t[idx..]); }
        }
        // "#0  0x.... in load_one (...) at kvstore.c:63"
        if t.starts_with("#0") {
            if t.contains(" in ?? ") || t.contains("?? ()") {
                p.pc_symbolized = false;
            } else if t.contains(" in ") {
                p.pc_symbolized = true;
                p.location = extract_symbol_location(t).or(p.location.take());
            }
        }
        // current-instruction from `x/i $pc`: "=> 0x..:\tmov (%rax),%rbx"
        if p.access.is_none() && t.contains("=>") {
            if let Some(cidx) = t.rfind(':') {
                let instr = t[cidx + 1..].trim();
                if !instr.is_empty() { p.access = classify_access(instr); }
            }
        }
        // stack: "0xADDR:\t0xWORD\t0xWORD ..."
        if let Some(cidx) = t.find(':') {
            if t.starts_with("0x") && t[..cidx].chars().skip(2).all(|c| c.is_ascii_hexdigit()) {
                for tok in t[cidx + 1..].split_whitespace() {
                    if let Some(v) = parse_hex_u64(tok) { p.stack_words.push(v); }
                }
            }
        }
    }
    p
}

/// From an arm64 function disassembly, find the frame-record epilogue
/// `ldp x29, x30, [sp, #N]` and return the offset of the saved RETURN address
/// (x30) from $sp, i.e. N + 8 (x29 sits at sp+N, x30 at sp+N+8). `[sp]` with no
/// displacement means N = 0. Returns None if no such epilogue is found.
fn parse_ra_offset_arm64(disasm: &str) -> Option<u64> {
    for line in disasm.lines() {
        let t = line.to_ascii_lowercase();
        if t.contains("ldp") && t.contains("x29") && t.contains("x30") && t.contains("[sp") {
            // "[sp, #0x70]" → 0x70 ; "[sp]" → 0
            let n = if let Some(i) = t.find("[sp, #") {
                parse_hex_u64(&t[i + "[sp, #".len()..]).unwrap_or(0)
            } else {
                0
            };
            return Some(n + 8);
        }
    }
    None
}

/// Parse a leading `0x…` hex token (stops at the first non-hex char).
fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    let hex: String = s.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if hex.is_empty() { return None; }
    // Values can exceed u64 width if the debugger tags bytes; take the low 16 nibbles.
    let hex = if hex.len() > 16 { &hex[hex.len() - 16..] } else { &hex };
    u64::from_str_radix(hex, 16).ok()
}

/// Pull a "symbol at file:line" style location out of a debugger frame line.
fn extract_symbol_location(line: &str) -> Option<String> {
    // Prefer the "at file:line" tail if present.
    if let Some(idx) = line.find(" at ") {
        let tail = line[idx + 4..].trim();
        let file_line: String = tail.split_whitespace().next().unwrap_or(tail).to_string();
        // Try to prefix with the symbol name (between ` and ( for lldb, or "in X" for gdb).
        let sym = line.rfind('`').map(|b| {
            let after = &line[b + 1..];
            after.split(['(', ' ']).next().unwrap_or("").to_string()
        }).filter(|s| !s.is_empty());
        return Some(match sym {
            Some(s) => format!("{s} at {file_line}"),
            None => format!("at {file_line}"),
        });
    }
    // lldb symbol only: module`symbol
    if let Some(b) = line.rfind('`') {
        let after = &line[b + 1..];
        let sym: String = after.split(['(', ' ', '+']).next().unwrap_or("").trim().to_string();
        if !sym.is_empty() { return Some(sym); }
    }
    None
}

/// Run the clean reproducer under the platform debugger and parse the crash into
/// a CrashProbe. Returns None when no debugger is available (graceful — the
/// caller falls back to the manual NEXT STEPS check). `stdin` is closed so a
/// reproducer that pops a shell on success can't block the probe.
#[cfg(target_os = "macos")]
fn run_crash_probe(reproducer: &str, crash: &str) -> Option<CrashProbe> {
    let out = Command::new("lldb")
        .args([
            "--batch",
            "-k", "register read pc sp",
            "-k", "disassemble --frame",
            "-k", "memory read -f x -s 8 -c 48 $sp",
            "-k", "quit",
            "-o", "settings set target.disable-aslr true",
            "-o", &format!("settings set target.run-args \"{crash}\""),
            "-o", "run",
            "--", reproducer,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Some(parse_lldb_probe(&text))
}

#[cfg(target_os = "linux")]
fn run_crash_probe(reproducer: &str, crash: &str) -> Option<CrashProbe> {
    let out = Command::new("gdb")
        .args([
            "-batch", "-nx",
            "-ex", "run",
            "-ex", "printf \"PC=%p SP=%p\\n\", $pc, $sp",
            "-ex", "p/x $_siginfo._sifields._sigfault.si_addr",
            "-ex", "x/i $pc",
            // Saved return address on x86-64 = *(rbp+8) (rbp-based frame at -O0).
            "-ex", "printf \"RA=%p\\n\", *(void**)($rbp+8)",
            "-ex", "x/64xg $sp",
            "-ex", "bt",
            "--args", reproducer, crash,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Some(parse_gdb_probe(&text))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn run_crash_probe(_reproducer: &str, _crash: &str) -> Option<CrashProbe> {
    // No supported debugger wired up (e.g. Windows/cdb) — fall back to the
    // manual NEXT STEPS check rather than guessing.
    None
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
) -> Result<String, String> {
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
    emit(&app, "[ 4/6 ] Compiling reproducer binary (no sanitizers, no fortify, no stack protector)…");

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
        // Strip hardening on the TARGET too — it holds the vulnerable code, and
        // fortify (`__memcpy_chk`) / the stack canary would trap the overflow
        // before it can reach the return, defeating the whole exploit path.
        obj_cmd.args(["-O0", "-g", "-c", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0", "-Dmain=__guzzle_target_main"]);
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
    // No sanitizers — we want real crashes, not ASan-caught ones. Also strip
    // the stack protector and fortify (`_FORTIFY_SOURCE=0`): fortify compiles
    // memcpy/strcpy into `__memcpy_chk`/`__strcpy_chk`, which trap a fixed-size
    // buffer overflow (even at -O0, since the size is compile-time known) before
    // it can corrupt the stack — so without this the reproducer aborts in
    // `__chk_fail_overflow` instead of reaching the return.
    // -no-pie is Linux-only; macOS ARM64 always produces PIE binaries.
    #[cfg(target_os = "linux")]
    cmd.args(["-O0", "-no-pie", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0", "-g"]);
    #[cfg(not(target_os = "linux"))]
    cmd.args(["-O0", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0", "-g"]);
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
    emit(&app, "[ 5/6 ] Verifying crash reproduces…");
    let verify = Command::new(reproducer_path.to_str().unwrap())
        .arg(&crash_path)
        .current_dir(&temp_dir)
        .output();

    match verify {
        Ok(out) => {
            let code = out.status.code().unwrap_or(-1);
            if out.status.success() {
                emit(&app, "      WARNING: reproducer exited 0 — crash may not reproduce on clean binary.");
                emit(&app, "      (This is expected if the overflow is only caught by ASan, not a native SIGSEGV.)");
            } else {
                emit(&app, format!("      Crash reproduced (exit code {code}) ✓"));
            }
        }
        Err(e) => {
            emit(&app, format!("      WARNING: Could not run reproducer: {e}"));
        }
    }

    // Read the crash input up front — used for both the control-flow assessment
    // and the AI prompt preview.
    let crash_bytes = std::fs::read(&crash_path).unwrap_or_default();
    let crash_size = crash_bytes.len();

    // ── Step 5b: Native control-flow assessment ──────────────────────────────
    // Run the clean reproducer under a debugger and decide, from ground truth
    // (do $pc / the saved-return slot hold crash-input bytes?), whether this is
    // real control, partial control, a deref-before-return, or just a crash.
    // This is what stops the tool from overclaiming "return-address control".
    emit(&app, "[ 5b  ] Assessing control-flow on the clean reproducer…");
    let control_ctx = match run_crash_probe(
        &reproducer_path.display().to_string(),
        &crash_path,
    ) {
        Some(probe) => {
            let assessment = classify_control(&probe, &crash_bytes);
            let headline = control_headline(&assessment, &probe);
            if let Some(loc) = &probe.location {
                emit(&app, format!("      fault at: {loc}"));
            }
            emit(&app, format!("      {headline}"));
            headline
        }
        None => {
            emit(&app, "      (no debugger available — skipping; use the manual check in NEXT STEPS)");
            "(control-flow assessment unavailable — no debugger found)".to_string()
        }
    };

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

Native control-flow assessment (from the clean reproducer under a debugger — ground
truth from whether $pc or the saved-return slot hold crash-input bytes). Honour this;
do NOT claim return-address control if it says otherwise:
{control_ctx}

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
  - IMPORTANT: a stack overflow usually smashes local pointer variables as well,
    and those are often dereferenced BEFORE the function returns. A naive
    return-address overwrite will then fault on a corrupted pointer INSIDE the
    function, never reaching the return. Detect this: if the crashing PC is
    inside the target function (not an attacker-controlled address), the payload
    must keep those locals valid, or steer control to a bail-out path that skips
    the deref, so execution survives to the epilogue. Say so explicitly in the
    script comments and handle it, rather than assuming direct return control.
  - Use cyclic() to find the exact offset to the saved return address; if the
    vulnerable copy writes a terminator byte just past its length, pad the
    payload PAST the return slot so that write does not corrupt your address.
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
- End the top comment with a "NEXT STEPS" section: a numbered, concrete,
  actionable plan for turning THIS crash into control — offset discovery,
  intermediate-pointer handling (for stack bugs), the specific object/field to
  corrupt (for heap bugs), the ASLR/leak requirement, and the gadget/chain to
  finish. No vague statements like "inspect manually" without saying what to
  look for and what to do with it.

Return ONLY the Python3 source code, no markdown fences."#,
        reproducer_path = reproducer_path.display(),
    );

    // Guzzle's own staged guidance — deterministic and independent of the AI.
    // Emitted BEFORE the AI call so the user always gets a concrete plan even if
    // the AI provider errors or is unavailable (e.g. a safeguard-flagged model),
    // which is the whole point of it being deterministic.
    emit(&app, "");
    for line in next_steps_lines(
        &bug_class,
        &reproducer_path.display().to_string(),
        &fuzzer_path.display().to_string(),
        &crash_path,
    ) {
        emit(&app, line);
    }

    let script = call_ai(&provider, system, user).await?;
    emit(&app, "      PoC script generated ✓");

    Ok(script)
}

// ── Batch crash triage ───────────────────────────────────────────────────────
//
// Runs the clean reproducer over every crash and classifies each with the same
// control-flow engine as generate_poc, so the UI can highlight the juicy crashes
// (real return control, R/W primitives) and dim the minimal overflows that only
// ASan/fortify caught — instead of the user lldb'ing each one by hand.

/// One crash's control-flow verdict, sent to the UI (streamed + returned).
#[derive(Debug, Serialize, Clone)]
pub struct CrashVerdict {
    pub crash_path: String,
    /// Stable machine kind for row colouring: control | primitive | reachable |
    /// partial | deref | uncertain | none | error.
    pub kind: String,
    /// 0 (dim) … 5 (juicy) — for sorting/highlighting.
    pub severity: u8,
    /// Short badge label.
    pub label: String,
    /// One-line explanation (tooltip / detail).
    pub headline: String,
}

/// Map an assessment to (machine kind, severity 0..=5, short badge label).
fn assessment_kind(a: &ControlAssessment) -> (&'static str, u8, &'static str) {
    match a {
        ControlAssessment::ReturnControl                 => ("control",   5, "return control"),
        ControlAssessment::ControlledDerefPrimitive      => ("primitive", 5, "R/W primitive"),
        ControlAssessment::DerefBeforeControllableReturn => ("reachable", 4, "control (deref first)"),
        ControlAssessment::PartialControl(_)             => ("partial",   3, "partial control"),
        ControlAssessment::DerefOnly                     => ("deref",     2, "partial ptr control"),
        ControlAssessment::Uncertain                     => ("uncertain", 1, "uncertain"),
        ControlAssessment::NoNativeCrash                 => ("none",      0, "no native crash"),
    }
}

/// Tier-1 fast check: run the reproducer directly (no debugger) with a timeout.
/// Exit 0 means the overflow didn't natively crash (minimal overflow); anything
/// else is a real crash worth the expensive debugger probe. `stdin` is closed so
/// a reproducer that pops a shell can't block.
enum RunOutcome { Exited0, Crashed, Skipped }

async fn run_reproducer(rep: &Path, crash: &str, timeout: Duration) -> RunOutcome {
    let mut child = match Command::new(rep)
        .arg(crash)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return RunOutcome::Skipped,
    };
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() { RunOutcome::Exited0 } else { RunOutcome::Crashed };
            }
            Ok(None) => {
                if tokio::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return RunOutcome::Crashed; // hung — treat as a crash worth probing
                }
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
            Err(_) => return RunOutcome::Skipped,
        }
    }
}

/// Triage every crash against an already-built reproducer, streaming a
/// `triage_progress` event per crash and returning the full list. Two-tier: a
/// fast direct run filters out the exit-0 (minimal) crashes; only real crashers
/// pay for the debugger probe.
#[tauri::command]
pub async fn triage_crashes(
    app: AppHandle,
    reproducer_path: String,
    crash_paths: Vec<String>,
) -> Result<Vec<CrashVerdict>, String> {
    let mut rep = PathBuf::from(&reproducer_path);
    if !rep.exists() {
        // Windows names it reproducer.exe — accept either.
        let exe = rep.with_extension("exe");
        if exe.exists() {
            rep = exe;
        } else {
            return Err(format!(
                "Reproducer not found at {reproducer_path}. Run Gen PoC on one crash first to build \
                 the reproducer, then triage."
            ));
        }
    }

    let total = crash_paths.len();
    let mut verdicts = Vec::with_capacity(total);

    for (i, crash) in crash_paths.iter().enumerate() {
        let outcome = run_reproducer(&rep, crash, Duration::from_secs(5)).await;

        let (assessment, probe) = match outcome {
            RunOutcome::Exited0 => (
                ControlAssessment::NoNativeCrash,
                CrashProbe { clean_exit: true, ..Default::default() },
            ),
            RunOutcome::Skipped => (ControlAssessment::Uncertain, CrashProbe::default()),
            RunOutcome::Crashed => {
                // Tier 2: only real crashers pay for the debugger probe.
                let input = std::fs::read(crash).unwrap_or_default();
                let rep_s = rep.display().to_string();
                let crash_s = crash.clone();
                let probe = tokio::task::spawn_blocking(move || run_crash_probe(&rep_s, &crash_s))
                    .await
                    .ok()
                    .flatten();
                match probe {
                    Some(p) => {
                        let a = classify_control(&p, &input);
                        (a, p)
                    }
                    None => (ControlAssessment::Uncertain, CrashProbe::default()),
                }
            }
        };

        let (kind, severity, label) = assessment_kind(&assessment);
        let verdict = CrashVerdict {
            crash_path: crash.clone(),
            kind: kind.to_string(),
            severity,
            label: label.to_string(),
            headline: control_headline(&assessment, &probe),
        };
        let _ = app.emit("triage_progress", (&verdict, i + 1, total));
        verdicts.push(verdict);
    }

    Ok(verdicts)
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
    fn reproducer_strips_fortify_and_stack_protector() {
        // Fortify (`__memcpy_chk`) and the stack canary trap a fixed-size buffer
        // overflow before it reaches the return, which would mask exploitability
        // and make every crash read as a libsystem trap. The reproducer builds
        // (both the target pre-compile and the final link) must strip them.
        let src = include_str!("poc.rs");
        // Count only the actual compiler-arg occurrences, not comments/tests.
        let arg_hits = src.matches("\"-D_FORTIFY_SOURCE=0\"").count();
        assert!(arg_hits >= 3, "expected >=3 `-D_FORTIFY_SOURCE=0` compiler args (obj + linux + non-linux), found {arg_hits}");
        assert!(src.contains("\"-fno-stack-protector\", \"-D_FORTIFY_SOURCE=0\", \"-Dmain=__guzzle_target_main\""),
            "target pre-compile must strip stack protector and fortify");
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
    fn debugger_hint_includes_reproducer_and_crash_paths() {
        let h = debugger_hint("/tmp/.guzzle/reproducer", "/tmp/crash-abc");
        assert!(!h.is_empty());
        assert!(h.contains("/tmp/.guzzle/reproducer"));
        // The crash path must be concrete, not a "<crash>" placeholder.
        assert!(h.contains("/tmp/crash-abc"));
        assert!(!h.contains("<crash>"));
    }

    #[test]
    fn next_steps_stack_flags_intermediate_pointer_and_offset() {
        let s = next_steps_lines(&BugClass::StackOverflow, "/tmp/reproducer", "/tmp/.guzzle/fuzzer", "/tmp/crash-abc").join("\n");
        // The core insight: crash may land before the return on a smashed pointer.
        assert!(s.to_lowercase().contains("before the function returns")
            || s.to_lowercase().contains("intermediate pointer"));
        // And the classic offset step must be present.
        assert!(s.contains("cyclic"));
        assert!(s.to_lowercase().contains("saved return address"));
    }

    #[test]
    fn next_steps_heap_does_not_use_cyclic() {
        let s = next_steps_lines(&BugClass::HeapOverflow, "/tmp/reproducer", "/tmp/.guzzle/fuzzer", "/tmp/crash-abc").join("\n");
        // Heap has no return-address offset — guidance must warn AGAINST cyclic,
        // not instruct it, and must point at the adjacent-object write primitive.
        let low = s.to_lowercase();
        assert!(low.contains("do not use cyclic") || low.contains("no return-address offset"));
        assert!(low.contains("adjacent"));
    }

    #[test]
    fn next_steps_uaf_mentions_reclaim() {
        let s = next_steps_lines(&BugClass::UseAfterFree, "/tmp/reproducer", "/tmp/.guzzle/fuzzer", "/tmp/crash-abc").join("\n");
        assert!(s.to_lowercase().contains("reclaim"));
    }

    #[test]
    fn next_steps_unknown_points_back_to_asan() {
        let s = next_steps_lines(&BugClass::Unknown, "/tmp/reproducer", "/tmp/.guzzle/fuzzer", "/tmp/crash-abc").join("\n");
        assert!(s.to_lowercase().contains("asan"));
        // "re-run the fuzzer binary" must name the actual paths, not be vague.
        assert!(s.contains("/tmp/.guzzle/fuzzer"));
        assert!(s.contains("/tmp/crash-abc"));
    }

    #[test]
    fn next_steps_every_class_is_nonempty_and_titled() {
        for bc in [BugClass::StackOverflow, BugClass::HeapOverflow,
                   BugClass::UseAfterFree, BugClass::Unknown] {
            let lines = next_steps_lines(&bc, "/tmp/reproducer", "/tmp/.guzzle/fuzzer", "/tmp/crash-abc");
            assert!(!lines.is_empty());
            assert!(lines[0].starts_with("NEXT STEPS"));
        }
    }

    // ── Control-flow assessment ──────────────────────────────────────────────

    // Input with three distinct, null-free regions used across the classifier
    // tests: "ABCDEFGH" (a controlled 8-byte value), "aaaa" (a 4-byte fault
    // pointer), and "ZZZZZZZZ" (a controlled stack/return word).
    const TEST_INPUT: &[u8] = b"ABCDEFGH++++aaaa++++ZZZZZZZZ";
    const PC_FULL: u64  = 0x4847464544434241; // LE bytes = "ABCDEFGH"
    const PC_PART: u64  = 0x0000000100004241; // low 2 bytes = "AB", rest an address
    const PC_CODE: u64  = 0x0000000100005678; // a code-looking address, not in input
    const FAULT_IN: u64 = 0x0000000061616161; // low 4 bytes = "aaaa"
    const STACK_IN: u64 = 0x5a5a5a5a5a5a5a5a; // = "ZZZZZZZZ"

    #[test]
    fn le_prefix_run_full_partial_none() {
        assert_eq!(le_prefix_run_in_input(PC_FULL, TEST_INPUT), 8);
        assert_eq!(le_prefix_run_in_input(PC_PART, TEST_INPUT), 2);
        assert_eq!(le_prefix_run_in_input(PC_CODE, TEST_INPUT), 0);
        assert_eq!(le_prefix_run_in_input(FAULT_IN, TEST_INPUT), 4);
        assert_eq!(le_prefix_run_in_input(0, b""), 0);
    }

    #[test]
    fn le_prefix_run_ignores_zero_runs() {
        // A zero-heavy input (common: length-prefixed formats, padding) must NOT
        // make zero-ish stack words look attacker-controlled — this was a real
        // false positive that over-badged benign small-overflow deref crashes.
        let zeroish = b"\x24\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(le_prefix_run_in_input(0x0400_0000_0000_0000, zeroish), 0);
        assert_eq!(le_prefix_run_in_input(0x5f5f_0000_0000_0000, zeroish), 0);
        assert_eq!(le_prefix_run_in_input(0, zeroish), 0);
        // A genuine all-0x41 control value in an all-'A' input still counts fully.
        assert_eq!(le_prefix_run_in_input(0x4141_4141_4141_4141, b"AAAAAAAAAAAA"), 8);
    }

    // Reproduces crash-cacd: tiny overflow, mostly-zero input, $pc in valid code
    // faulting on a deref, stack full of zero-heavy stale words. Must NOT read as
    // return control — the zero-run match was the false positive.
    #[test]
    fn classify_zero_heavy_deref_is_not_control() {
        let input = b"\x24\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                      \x00\x00\x00\x00\x00\x00\x02\xff\x00\x00";
        // The real saved-return slot holds a zero-heavy stale value (the small
        // overflow never reached it); zero-exclusion means it does not count.
        let p = CrashProbe {
            pc: Some(0x0000_0001_0000_0844),
            pc_symbolized: true,
            fault_addr: Some(0x8004),
            ra_slot: Some(0x5f5f_0000_0000_0000),
            ..Default::default()
        };
        let got = classify_control(&p, input);
        assert_ne!(got, ControlAssessment::ReturnControl);
        assert_ne!(got, ControlAssessment::DerefBeforeControllableReturn);
    }

    #[test]
    fn parse_hex_u64_basic_and_tagged() {
        assert_eq!(parse_hex_u64("0x1234"), Some(0x1234));
        assert_eq!(parse_hex_u64("0x6b6161616a6161ca)"), Some(0x6b6161616a6161ca));
        // >16 nibbles: keep the low 16 (defends against tagged/overlong tokens).
        assert_eq!(parse_hex_u64("0x1ffffffffffffffff"), Some(0xffffffffffffffff));
        assert_eq!(parse_hex_u64("nope"), None);
    }

    // Bucket 1: saved return / $pc holds input → true control.
    #[test]
    fn classify_return_control() {
        let p = CrashProbe { pc: Some(PC_FULL), ..Default::default() };
        assert_eq!(classify_control(&p, TEST_INPUT), ControlAssessment::ReturnControl);
    }

    // An indirect call/jmp through a corrupted pointer lands $pc on input bytes
    // too — must read as control, NOT be collapsed into "intermediate pointer".
    #[test]
    fn classify_indirect_branch_to_input_is_control() {
        let p = CrashProbe { pc: Some(PC_FULL), pc_symbolized: false, ..Default::default() };
        assert_eq!(classify_control(&p, TEST_INPUT), ControlAssessment::ReturnControl);
    }

    // Edge: partial (1–2 byte) return-address overwrite is still control.
    #[test]
    fn classify_partial_control() {
        let p = CrashProbe { pc: Some(PC_PART), ..Default::default() };
        assert_eq!(classify_control(&p, TEST_INPUT), ControlAssessment::PartialControl(2));
    }

    // Bucket 2: data deref through an overflow-loaded register, return NOT
    // controllable → not directly exploitable (must not read as control).
    #[test]
    fn classify_deref_only() {
        // Fault pointer is input-derived, but the real return slot is not.
        let p = CrashProbe {
            pc: Some(PC_CODE), pc_symbolized: true,
            fault_addr: Some(FAULT_IN), ra_slot: Some(0xdead_beef_0000_1111),
            ..Default::default()
        };
        assert_eq!(classify_control(&p, TEST_INPUT), ControlAssessment::DerefOnly);
    }

    // The high-value middle case: crashes on a smashed pointer before the return,
    // but the saved return slot already holds input → control is reachable.
    #[test]
    fn classify_deref_before_controllable_return() {
        // The REAL saved-return slot holds input → reachable control, even though
        // $pc is still in valid code faulting on a deref.
        let p = CrashProbe {
            pc: Some(PC_CODE), pc_symbolized: true,
            fault_addr: Some(FAULT_IN), ra_slot: Some(STACK_IN),
            ..Default::default()
        };
        assert_eq!(
            classify_control(&p, TEST_INPUT),
            ControlAssessment::DerefBeforeControllableReturn
        );
    }

    // PIE/noise: crashed but nothing ties to the input → Uncertain, not a claim.
    #[test]
    fn classify_uncertain_on_pie_noise() {
        let p = CrashProbe { pc: Some(0x0000_0001_0000_9999), ..Default::default() };
        assert_eq!(classify_control(&p, TEST_INPUT), ControlAssessment::Uncertain);
    }

    #[test]
    fn assessment_kind_severity_ordering() {
        // Juicy verdicts outrank the dim ones, and the ordering is monotonic
        // through the middle tiers so the UI can sort/highlight by severity.
        assert_eq!(assessment_kind(&ControlAssessment::NoNativeCrash).1, 0);
        assert_eq!(assessment_kind(&ControlAssessment::ReturnControl).0, "control");
        assert_eq!(assessment_kind(&ControlAssessment::ControlledDerefPrimitive).1, 5);
        let deref = assessment_kind(&ControlAssessment::DerefOnly).1;
        let partial = assessment_kind(&ControlAssessment::PartialControl(2)).1;
        let reachable = assessment_kind(&ControlAssessment::DerefBeforeControllableReturn).1;
        assert!(deref < partial && partial < reachable);
        assert!(reachable < assessment_kind(&ControlAssessment::ReturnControl).1);
    }

    #[test]
    fn classify_clean_exit_is_no_native_crash() {
        let p = CrashProbe { clean_exit: true, ..Default::default() };
        assert_eq!(classify_control(&p, TEST_INPUT), ControlAssessment::NoNativeCrash);
    }

    #[test]
    fn parse_lldb_probe_extracts_pc_fault_and_stack() {
        // Epilogue `ldp x29, x30, [sp, #0x8]` → x30 at sp+0x10 → stack index 2.
        let sample = "\
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x6b6161616a6161ca)\n\
    frame #0: 0x00000001000006b4 kvstore_win`load_one(p=0x71, end=\"\", rec=0x6d) at kvstore.c:63:23\n\
      pc = 0x00000001000006b4  kvstore_win`load_one + 236 at kvstore.c:63:23\n\
      sp = 0x000000016fdfb710\n\
->  0x00000001000006b4 <+236>: ldr    w8, [x8]\n\
    0x000000010000092c <+468>: ldp    x29, x30, [sp, #0x8]\n\
0x16fdfb710: 0x000000016fdfb730 0x00000001f9b841a0\n\
0x16fdfb720: 0x7761616176616161 0x7961616178616161\n";
        let p = parse_lldb_probe(sample);
        assert_eq!(p.pc, Some(0x1000006b4));
        assert!(p.pc_symbolized);
        assert_eq!(p.fault_addr, Some(0x6b6161616a6161ca));
        assert_eq!(p.access, Some(Access::Read)); // ldr = load = read
        assert!(p.location.as_deref().unwrap_or("").contains("load_one"));
        assert!(p.location.as_deref().unwrap_or("").contains("kvstore.c:63"));
        assert!(p.stack_words.contains(&0x7761616176616161));
        // The precise saved-return slot (sp+0x10 = index 2), not a window scan.
        assert_eq!(p.ra_slot, Some(0x7761616176616161));
        assert!(!p.clean_exit);
    }

    #[test]
    fn parse_ra_offset_arm64_reads_ldp_displacement() {
        assert_eq!(parse_ra_offset_arm64("  ldp    x29, x30, [sp, #0x70]"), Some(0x78));
        assert_eq!(parse_ra_offset_arm64("  ldp    x29, x30, [sp, #0x8]"), Some(0x10));
        assert_eq!(parse_ra_offset_arm64("  ldp    x29, x30, [sp]"), Some(8));
        assert_eq!(parse_ra_offset_arm64("  add x0, x1, x2\n  ret"), None);
    }

    #[test]
    fn parse_lldb_probe_detects_clean_exit() {
        let sample = "Process 123 exited with status = 0 (0x00000000)\n";
        let p = parse_lldb_probe(sample);
        assert!(p.clean_exit);
    }

    #[test]
    fn parse_gdb_probe_extracts_pc_fault_and_stack() {
        let sample = "\
Program received signal SIGSEGV, Segmentation fault.\n\
#0  0x0000555555555234 in load_one (p=0x0) at kvstore.c:63\n\
PC=0x555555555234 SP=0x7fffffffe000\n\
$1 = 0x616161616161\n\
=> 0x555555555234 <load_one+236>:\tmov    (%rax),%rbx\n\
RA=0x4141414141414141\n\
0x7fffffffe000:\t0x4141414141414141\t0x0000555555555111\n";
        let p = parse_gdb_probe(sample);
        assert_eq!(p.pc, Some(0x555555555234));
        assert!(p.pc_symbolized);
        assert_eq!(p.fault_addr, Some(0x616161616161));
        assert_eq!(p.access, Some(Access::Read)); // mov (%rax),%rbx = memory source = read
        assert!(p.stack_words.contains(&0x4141414141414141));
        assert_eq!(p.ra_slot, Some(0x4141414141414141)); // precise *(rbp+8)
    }

    #[test]
    fn parse_gdb_probe_wild_pc_not_symbolized() {
        let sample = "\
Program received signal SIGSEGV, Segmentation fault.\n\
#0  0x4141414141414141 in ?? ()\n\
PC=0x4141414141414141 SP=0x7fffffffe000\n";
        let p = parse_gdb_probe(sample);
        assert_eq!(p.pc, Some(0x4141414141414141));
        assert!(!p.pc_symbolized);
    }

    #[test]
    fn control_headline_never_claims_control_when_deref_only() {
        let p = CrashProbe { pc: Some(PC_CODE), pc_symbolized: true,
            fault_addr: Some(FAULT_IN), ..Default::default() };
        let h = control_headline(&ControlAssessment::DerefOnly, &p).to_lowercase();
        // Must NOT assert confirmed control; must hedge.
        assert!(h.contains("partial pointer control") || h.contains("not confirmed rce"));
        assert!(!h.contains("return-address control looks achievable"));
    }

    // The ordering fix: a symbolized $pc that coincidentally shares 3 low bytes
    // with an input run must NOT be mislabeled ReturnControl.
    #[test]
    fn classify_symbolized_pc_is_not_control_despite_byte_collision() {
        const PC_SYM_COLLIDE: u64 = 0x0000_0001_0043_4241; // low 3 bytes = "ABC"
        assert_eq!(le_prefix_run_in_input(PC_SYM_COLLIDE, TEST_INPUT), 3); // would trip old logic
        let p = CrashProbe { pc: Some(PC_SYM_COLLIDE), pc_symbolized: true, ..Default::default() };
        let got = classify_control(&p, TEST_INPUT);
        assert_ne!(got, ControlAssessment::ReturnControl);
        assert_eq!(got, ControlAssessment::Uncertain);
    }

    // Full attacker-controlled data pointer → controlled-address primitive.
    #[test]
    fn classify_controlled_deref_primitive() {
        let p = CrashProbe { pc: Some(PC_CODE), pc_symbolized: true,
            fault_addr: Some(STACK_IN), ..Default::default() };
        assert_eq!(classify_control(&p, TEST_INPUT), ControlAssessment::ControlledDerefPrimitive);
    }

    #[test]
    fn classify_access_arm64_and_x86() {
        // arm64: load = read, store = write.
        assert_eq!(classify_access("ldr w8, [x8]"), Some(Access::Read));
        assert_eq!(classify_access("ldrb w9, [x0, #0x4]"), Some(Access::Read));
        assert_eq!(classify_access("str x0, [x1]"), Some(Access::Write));
        assert_eq!(classify_access("stp x29, x30, [sp, #0x70]"), Some(Access::Write));
        // x86 AT&T: memory destination (last operand) = write; memory source = read.
        assert_eq!(classify_access("mov %rbx,(%rax)"), Some(Access::Write));
        assert_eq!(classify_access("mov (%rax),%rbx"), Some(Access::Read));
        // No memory operand / unknown → None (caller stays neutral).
        assert_eq!(classify_access("nop"), None);
        assert_eq!(classify_access("add x0, x1, x2"), None);
    }

    // The controlled-deref headline must NOT assert a write on a read.
    #[test]
    fn controlled_deref_headline_respects_access_direction() {
        let read_probe = CrashProbe { access: Some(Access::Read), ..Default::default() };
        let h = control_headline(&ControlAssessment::ControlledDerefPrimitive, &read_probe).to_lowercase();
        assert!(h.contains("read"));
        assert!(!h.contains("arbitrary write"));

        let write_probe = CrashProbe { access: Some(Access::Write), ..Default::default() };
        let h = control_headline(&ControlAssessment::ControlledDerefPrimitive, &write_probe).to_lowercase();
        assert!(h.contains("write"));

        let unknown = CrashProbe { access: None, ..Default::default() };
        let h = control_headline(&ControlAssessment::ControlledDerefPrimitive, &unknown).to_lowercase();
        assert!(h.contains("read or write") || h.contains("check the faulting instruction"));
    }

    // The real saved-return slot fully controlled (precise, not a window scan)
    // with $pc in valid code → reachable control through the return.
    #[test]
    fn classify_controlled_return_slot_is_reachable_control() {
        let p = CrashProbe { pc: Some(PC_CODE), pc_symbolized: true,
            ra_slot: Some(STACK_IN), ..Default::default() };
        assert_eq!(classify_control(&p, TEST_INPUT), ControlAssessment::DerefBeforeControllableReturn);
    }

    // Partial overwrite of the real saved-RA slot surfaces instead of hiding.
    #[test]
    fn classify_partial_ra_overwrite() {
        let p = CrashProbe { pc: Some(PC_CODE), pc_symbolized: true,
            ra_slot: Some(FAULT_IN), ..Default::default() }; // FAULT_IN = 4 input bytes
        assert_eq!(classify_control(&p, TEST_INPUT), ControlAssessment::PartialControl(4));
    }

    // A single coincidental input byte in $pc is noise, not partial control.
    #[test]
    fn classify_single_byte_pc_match_is_noise() {
        const PC_ONE: u64 = 0x0000_0001_0000_9941; // low byte = 'A', rest not input
        assert_eq!(le_prefix_run_in_input(PC_ONE, TEST_INPUT), 1);
        let p = CrashProbe { pc: Some(PC_ONE), pc_symbolized: false, ..Default::default() };
        assert_eq!(classify_control(&p, TEST_INPUT), ControlAssessment::Uncertain);
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
}
