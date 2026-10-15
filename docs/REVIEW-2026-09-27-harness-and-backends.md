# Guzzle review: harness correctness + backend architecture

_Written 2026-09-27, from a review session driven off a real target
(`~/code/rain-recovered`, Michael's 2001 packet builder). This is a handoff
for whichever crab picks up Guzzle next. Read it top to bottom once, then work
the checklist at the end._

The review had two halves:

1. A concrete AI-generated harness (DeepSeek, via Guzzle) for a real function
   was audited against its real source. It had three defects, all traceable to
   gaps in Guzzle's harness-gen prompt.
2. A design conversation about how Guzzle should handle multi-file projects and
   closed binaries (DLLs / dynamic libraries), and where the product should aim.

---

## Part 1 — Harness generator: three prompt gaps, found on a live target

Target: `parse_command_line(int argc, char **argv, struct pkt_info *, ... , u_short *)`
in `rain-1.2.9beta1/source/rain_command_line.c`. Guzzle produced a harness that
compiles and even got the tricky part right (it heap-allocates mutable copies of
each argv token, because the target's `filter_argument` writes back into them).
But as written it fuzzes nothing useful and hands back at least one false crash.

Prompts live in `src-tauri/src/commands/ai.rs`:
- `build_prompt` (source mode) — line ~104
- `build_binary_prompt` (prebuilt-binary mode) — line ~188

### Gap 1 — Target-side process terminators (the blocker)

**What happened.** Every error path in the parser calls the `DieWith*` family
(`rain_die.c`), and each of those calls `exit(0)` / `exit(1)`. libFuzzer treats a
target that calls `exit()` as a fatal crash and stops the run. Since almost any
input trips a `Die*` path (an unknown option alone triggers `DieWithBadArg`), the
campaign dies on roughly the first input. It never explores.

**Why the prompt misses it.** Rule 5 says *"Do NOT call exit() or abort()"* — but
that constrains the **harness**, not the **target**. The rain harness obeyed rule
5 perfectly; the `exit()` calls are in the code under test. Nothing in the
pipeline detects or neutralizes a target that terminates the process.

**Fix (this is a build feature, not just a prompt line).**
- Scan the target and its transitive callees for terminators: `exit`, `_exit`,
  `abort`, `quick_exit`, `err`/`errx`/`verr`, `longjmp` to nowhere, and
  project-specific death functions by name pattern (`Die*`, `die_*`, `fatal*`,
  `panic*`, `*_usage`, `bail*`).
- When found, generate a shim: `setjmp` in `LLVMFuzzerTestOneInput`, and provide
  replacements that `longjmp` back instead of exiting. Wire them in via linker
  `--wrap=exit` (and `--wrap=<death fn>`) or weak-symbol overrides so the real
  ones are replaced at link time. libFuzzer also honors
  `-runs`/`ASAN_OPTIONS=abort_on_error`, but wrapping is what actually keeps the
  process alive to fuzz.
- Add a prompt rule: "If the target or its callees can terminate the process
  (exit/abort/err/custom die-functions), the run must intercept them; emit a
  `setjmp` guard around the call and assume the build wraps the terminators."

### Gap 2 — Caller-invariant contracts (a manufactured false positive)

**What happened.** The parser detects a missing option value with
`if (argv[i+1] == NULL) DieWithRequire(...)`, relying on the C guarantee that
`argv[argc] == NULL`. The harness built `argv[0..argc-1]` and **never set
`argv[argc] = NULL`**. When the last token is an option expecting a value (`-t`,
`-c`, `-s`, `-g`, and `--` forms), `argv[i+1]` reads an uninitialized stack slot,
the NULL guard passes on garbage, and you get `strcpy(pkt->daddr, <wild ptr>)` →
SEGV. That crash is the harness's fault, not the target's.

**Fix.** Generalize beyond argv: when the harness fabricates a structure the real
caller normally guarantees invariants for, it must reproduce them. Add a prompt
rule: "When synthesizing NULL-terminated arrays (argv-style), sentinel-terminated
lists, or paired length+buffer arguments, reproduce the terminator/sentinel/length
the real caller guarantees. For `char **argv`, allocate `argc+1` slots and set
`argv[argc] = NULL`." Consider a dedicated `(int argc, char **argv)` recognizer in
the harness templater since CLI parsers are a rich, common bug class.

### Gap 3 — Input generator sized below the target's buffers (coverage gap)

**What happened.** The real bugs in rain are unbounded `strcpy` into fixed
256-byte buffers (`pkt->daddr/saddr/gaddr`, each `u_char[256]`), reachable via
`-t/-T` with **no root check and no type gate** — the cleanest crash in the
program. The harness used `ConsumeRandomLengthString(32)`, capping every argument
at 32 bytes, so it can never fill 256. The fuzzer literally cannot reach the bug
it exists to find.

**Fix.** Add a prompt rule: "Do not cap synthesized string/array lengths at a
small constant. Size them to at least the largest fixed buffer visible in the
target or its context (default generously, e.g. 4096, when unknown), so overflow
sinks are reachable." Where Guzzle parses struct definitions (it already does some
of this in `compile.rs:310`), feed known buffer sizes into the prompt as hints.

### Minor (note, don't over-engineer)

- The opaque struct stubs DeepSeek emitted (`unsigned char storage[4096]`) were
  size-safe here (real `pkt_info` ≈ 1.9 KB) but are an ODR/type-pun that breaks
  silently if a field grows past the guess. In a project tree the real headers are
  reachable — prefer including them over stubbing. The prompt should say: "If the
  real header defining a parameter type is available in context, include it and use
  the real type; only fall back to opaque byte-buffer stubs when no definition
  exists."

---

## Part 2 — Backend architecture: source vs prebuilt is the only real fork

The instinct to add a "project type" dropdown on the first screen is the wrong
abstraction. Taxonomy dropdowns push classification onto the user and then change
nothing downstream. The one decision that actually forks the whole toolchain,
harness shape, and runner is:

- **Build from source** → compile the target with instrumentation
  (`-fsanitize=fuzzer,address`), emit `LLVMFuzzerTestOneInput`, run under
  libFuzzer. This is the mode Guzzle has today (`build_prompt`).
- **Prebuilt binary only** → cannot instrument at compile time, so libFuzzer gets
  **no coverage feedback** and degrades to blind random. Needs a different engine.

Everything else you might dropdown — single-file vs multi-file, C vs C++
mangling, which object holds `main`, the link set, exported symbol names — is
**auto-detectable**. Detect and confirm; don't make the user classify. So the
first screen wants at most one inferred fork (often decidable from what was
dropped in: a `.c`/`Makefile`/`CMakeLists` vs a bare `.so`/`.dylib`/`.dll`).

### Multi-file projects are NOT a new mode

`parse_command_line` calls into other translation units (`filter_argument`,
`DieWith*`, `atohex`, globals like `verbose`/`packetsize`/`sendflags`). "Multi-file
project" is just source mode **plus a link step**: link the program's objects
minus the one containing `main`. Auto-detect the link set by resolving the
target's callees to their defining objects. No dropdown needed.

### The DLL / dynamic-library reality (this is the real gap)

Guzzle already advertises library mode and has scaffolding for it: `compile.rs:189`
resets `-x` to link `.a/.so/.dylib`, `symbols.rs` parses exports (including
`zlib.dll`), the store has `isBinaryMode`/`binaryPath`, and `build_binary_prompt`
exists. But there's a hard limit the current pipeline can't cross:

- **libFuzzer needs coverage baked into the target at compile time.** A prebuilt
  third-party `.so`/`.dylib`/`.dll` you didn't build has none. Linking it and
  running libFuzzer gives you blind black-box fuzzing, not coverage-guided. A
  self-built `.a` compiled *with* the flags is fine — that's really still "build
  from source."
- **`.dll` isn't even in the linked-lib list** (`CompileSettings.tsx:183` says
  `.a/.so/.dylib`). Windows DLLs need `LoadLibrary`/`GetProcAddress` (or an import
  lib), not the same link path.

So for a genuinely closed binary you need **binary instrumentation**, a second
engine, not a prompt tweak:

| Situation | Engine |
|---|---|
| Have source (incl. your own `.a` built with flags) | libFuzzer (current) |
| Closed `.dll` / `.dylib` on Windows / macOS | **TinyInst + Jackalope** (Ivan Fratric) — purpose-built for binaries you didn't compile, cross-platform Win/mac |
| Closed binary on Windows | WinAFL (DynamoRIO or Intel PT) |
| Closed `.so` on Linux | AFL++ frida-mode / qemu-mode |

The closed-binary harness is **not** `LLVMFuzzerTestOneInput`. It's a small loader
that `LoadLibrary`/`dlopen`s the target, resolves the exported symbol, and calls it
once per input file, with the fuzzer driving the process externally.

### Architecture call worth making before more libFuzzer investment

**libFuzzer has been in maintenance-only mode upstream in LLVM for a couple of
years** — no new features. **AFL++ is the actively developed engine, and it spans
both forks under one runner**: source via `afl-cc`, binary-only via frida-mode,
qemu-mode, and nyx. That unification matters: otherwise you maintain libFuzzer for
source + a separate closed-binary stack forever.

Realistic backend map:
- **AFL++** as the spine for source and Linux `.so`.
- **TinyInst / Jackalope** for Windows + macOS closed binaries (matches Michael's
  Win+Mac world better than WinAFL, which is Windows-centric).
- **libFuzzer** demoted to one optional mode, not the foundation.

That also dissolves the first-screen question: no taxonomy, just detect
source-vs-binary and route to the right engine.

---

## Part 3 — Product positioning (so the engineering aims at the goal)

Guzzle's goal (Michael's words): find lots of vulns in OSS + bug bounties, build a
GitHub reputation. Two honest constraints shape where the engineering should go.

- **The easy end of OSS is picked clean.** Google's OSS-Fuzz has fuzzed the famous
  libraries (curl, openssl, sqlite, libpng, ffmpeg, …) continuously since 2016.
  Point Guzzle at curl and find nothing, then wrongly conclude the tool is broken.
  The bugs are in the tier OSS-Fuzz **doesn't** cover: mid-popularity libraries,
  new projects, weird proprietary formats, embedded/IoT firmware, and **closed
  binaries**. That last one is why the closed-binary backend is the commercially
  smart bet, not a nice-to-have — it's the uncontested territory and where bounty
  money lives.
- **False positives are a reputational landmine.** Auto-generated harnesses
  manufacture crashes (Part 1 showed one). Flood maintainers or bounty programs
  with harness-artifact "bugs" and you get blocked and mocked, the opposite of
  fame. The **triage/validation gate is the entire reputation**: minimize,
  reproduce against a *correct* harness, and prove attacker-reachability before
  anything reaches a human. Build that gate before polishing anything else.

**Wedge:** closed-binary fuzzing made genuinely one-click, plus the
harness-correctness intelligence that avoids the Part 1 mistakes. "Point it at a
DLL and get a working harness + corpus + ruthless triage" is underserved and maps
directly to the goal.

---

## Checklist for the next crab

Harness generator (`src-tauri/src/commands/ai.rs`):
- [~] Target-side terminator handling (Gap 1) — **PROMPT SIDE DONE, BUILD SIDE
      DEFERRED**. Added rule 13 (source) / 13 (binary): the model now emits a
      `setjmp` guard around the target call and defines `longjmp`-based
      replacements for project-specific death functions visible in context
      (`Die*`, `fatal*`, etc.). The BUILD-SIDE wrap of libc `exit`/`abort`
      (`--wrap=exit` + weak overrides) is NOT done: `--wrap` is not supported by
      macOS's default `ld64`, and Michael validates on darwin, so it needs a
      linker/toolchain decision (force `-fuse-ld=lld`? cfg-gate per platform?)
      plus link-set surgery to exclude the object defining the death fns. Left
      for Michael — see "Deferred" note below.
- [x] Caller-invariant rule + argv recognizer (Gap 2) — rule 14 both modes:
      allocate `argc + 1` slots, set `argv[argc] = NULL`, honor sentinels and
      length/buffer pairs.
- [x] Stop capping synthesized lengths small (Gap 3) — rule 15 both modes: no
      small caps, size to largest visible buffer, default 4096 when unknown.
      (Feeding parsed struct buffer sizes from `compile.rs` as explicit hints is
      still a nice-to-have; the model can already see buffers in the context.)
- [x] Prefer real headers over opaque stubs when the type definition is in
      context — rule 16 (source mode).

All four covered by new unit tests in `ai.rs`; `cargo test` green (143 passing).

**Deferred (Michael's call, not done autonomously):**
- Build-side terminator wrapping for libc `exit`/`abort` (the other half of
  Gap 1) — needs a linker/toolchain decision because of macOS `ld64`.
- Every Part 2 backend item (AFL++ as spine, TinyInst/Jackalope for closed
  binaries, `.dll` support, first-screen source-vs-prebuilt reframe) — these are
  architectural direction, not edits to make on a peer's say-so.
- Every Part 3 product item (triage gate, target selection).

Backend:
- [ ] Reframe first screen as detected source-vs-prebuilt, not a project-type
      dropdown; auto-detect single/multi-file and the link set.
- [ ] Decide the engine strategy: evaluate AFL++ as the primary spine (spans
      source + binary, actively maintained) vs staying on libFuzzer.
- [ ] Scope a real closed-binary backend (TinyInst/Jackalope for Win+mac,
      AFL++ frida/qemu for Linux `.so`); emit a loader-style harness, not
      `LLVMFuzzerTestOneInput`. Add `.dll` to the binary path.
- [ ] Document the coverage limitation of linking uninstrumented prebuilt libs
      under libFuzzer (blind fuzzing) so users aren't misled by "library mode."

Product:
- [ ] Build a ruthless triage/validation gate (minimize + reproduce on a correct
      harness + reachability) before any reporting features — it's the reputation.
- [ ] Steer target selection away from OSS-Fuzz-covered libs toward the
      uncovered tier and closed binaries.

_Test target to validate fixes against: `~/code/rain-recovered/rain-1.2.9beta1`.
A correct harness for `parse_command_line` (NULL-terminated argv + die-stub +
larger tokens) should find the `-t` unbounded `strcpy` into `daddr[256]` and stay
alive long enough to explore the rest._
