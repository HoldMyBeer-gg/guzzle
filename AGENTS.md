# Guzzle — AI Agent Guide

Guzzle is a desktop app that wraps libFuzzer to make fuzzing C/C++ code accessible. This file tells AI agents (Claude Code, Codex, etc.) how to help a user fuzz their code using Guzzle — either by driving the GUI workflow or by replicating it manually from the CLI.

## What Guzzle does

1. Open a C/C++ source file and pick a function
2. AI generates a libFuzzer harness for that function
3. Compile the harness with clang + AddressSanitizer + libFuzzer
4. Run the fuzzer and capture crashes
5. For each crash: compile a standalone reproducer, extract ROP gadgets, generate a pwntools exploit scaffold

## Driving the workflow manually (CLI / agent-assisted)

If the user wants you to drive fuzzing directly without the GUI, follow these steps:

### 1. Find a target function

Look for functions that handle untrusted input — parsers, decoders, format readers, protocol handlers. Good candidates:
- Take a buffer + length (`const uint8_t *data, size_t size`)
- Take a filename or file pointer
- Parse structured data (images, packets, config files)

### 2. Generate a harness

Write a file `harness.cpp`:

```cpp
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Forward-declare the target
extern "C" int TargetFunction(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // parse / coerce data into what the target expects, then call it
    TargetFunction(data, size);
    return 0;
}
```

Rules:
- No `exit()` or `abort()`
- No platform-specific headers (`<unistd.h>`, `<fcntl.h>`) without `#ifndef _WIN32` guards
- If the function needs a file path, write to `/tmp/guzzle_input` (Linux/macOS) or `C:\Temp\guzzle_input` (Windows) — never the current directory
- Guard all pointer dereferences

### 3. Compile

```bash
# Linux / macOS
clang++ -fsanitize=fuzzer,address -O1 -g \
  harness.cpp target.c \
  -o fuzzer

# Windows (clang-cl / LLVM)
clang++ -fsanitize=fuzzer,address -O1 -g \
  -D_CRT_SECURE_NO_WARNINGS -ldbghelp -lshell32 \
  harness.cpp target.c \
  -o fuzzer.exe
```

If the target has a `main()`, rename it: add `-Dmain=__target_main` to the compile flags.

### 4. Run the fuzzer

```bash
mkdir -p corpus crashes
./fuzzer corpus/ -artifact_prefix=crashes/ -max_total_time=300
```

Crashes are written to `crashes/`. The fuzzer prints `SUMMARY: AddressSanitizer` on a find.

### 5. Reproduce a crash

```bash
./fuzzer crashes/crash-<hash>
```

Or compile a standalone reproducer (no libFuzzer dependency):

```c
// reproducer_main.c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    uint8_t *buf = malloc(sz);
    fread(buf, 1, sz, f); fclose(f);
    LLVMFuzzerTestOneInput(buf, sz);
    free(buf);
}
```

```bash
clang++ -O0 -no-pie -fno-stack-protector -g \
  harness.cpp target.c reproducer_main.c \
  -o reproducer
./reproducer crashes/crash-<hash>
```

### 6. Triage the crash

Run the fuzzer binary (not the reproducer) on the crash file to get the full ASan report:

```bash
./fuzzer crashes/crash-<hash>
```

The report tells you the bug class, the exact write address and size, and both stack traces
(allocation site + overflow site). That determines severity and next steps:

| ASan report says | Severity / exploitability |
|---|---|
| `heap-buffer-overflow` | High — corrupts adjacent heap state; assess reachability on the target |
| `stack-buffer-overflow` | High — may reach the saved return address |
| `heap-use-after-free` | High — type-confusion potential |
| `SEGV on unknown address 0x0` | Usually a null deref, typically not directly exploitable |

### 7. Extract ROP gadgets

```bash
# macOS (Mach-O):
r2 -q -c "aaa;/R;q" reproducer
# Linux (ELF):
ROPgadget --binary reproducer --rop --nosys | head -200
# or: ropper -f reproducer
```

### 8. Multi-stage crashes (iterative loop)

The GUI's Gen PoC produces a one-shot scaffold. Some crashes (multi-stage heap bugs) need
iteration before they become a usable PoC. This is reasoning about a **specific crash on a
target you are authorized to test** — not a generic recipe. The exact adjacent object, field,
and offsets are all target-specific, so work them against the concrete artifact in front of
you rather than a canned sequence. The loop:

```
read source → understand allocator state → craft input → run → observe → refine
```

Bring the concrete ASan report and the target source into the loop and iterate from there.

Useful mechanics for that loop:

```bash
# Minimise the crash input first — smaller input, easier layout to reason about
./fuzzer -minimize_crash=1 -exact_artifact_path=crashes/min-<hash> crashes/crash-<hash>

# Inspect memory around the fault under a debugger
#   Linux: gdb reproducer core   (gef/pwndbg give 'heap chunks', 'x/32gx <addr>')
#   macOS: lldb -- ./reproducer crashes/crash-<hash>   ('memory read --format x <addr>')

# Disable ASLR for stable addresses while developing
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

For anything beyond triage, work the concrete crash with the operator — the target-specific
analysis is where the actual progress happens, and it can't be pre-written here.

## Tips for agents

- **Start simple**: fuzz one function at a time, not the whole binary
- **Check for companion headers**: if fuzzing `msgparse.c`, include `msgparse.h` in the harness for type definitions
- **Seed the corpus**: put small valid inputs in `corpus/` before running — the fuzzer explores much faster
- **ASLR**: disable for reliable addresses: `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`
- **Crash triage**: `AddressSanitizer: heap-buffer-overflow` and `stack-buffer-overflow` are the most exploitable; `SEGV on unknown address 0x0` is usually just a null deref
- **The GUI Gen PoC is a scaffold**: it gets you the bug class and a starting script; multi-stage crashes need the iterative loop in section 8, worked against the concrete target
- **Iterate on the concrete crash**: read the ASan shadow output after each attempt and adjust the input based on what it shows
- **Minimise before exploiting**: `./fuzzer -minimize_crash=1` strips the crash input to its essential bytes, making the heap layout easier to reason about

## Fuzzing third-party libraries (e.g. ZNC, OpenSSL, libpng)

When the target file includes library headers (`#include <znc/Message.h>`,
`#include <openssl/ssl.h>`, etc.), Guzzle automatically resolves them on file
open:

1. **Include path auto-detection** — Guzzle scans `#include <lib/header.h>`
   directives and searches candidate system directories (Homebrew prefixes on
   macOS, standard paths on Linux, LLVM/Scoop paths on Windows, plus `CPATH`
   and `C_INCLUDE_PATH` env vars). Headers found are split into:
   - `include_dirs` — non-default directories added to **Include Paths** in
     the Compile step automatically (e.g. `/opt/homebrew/include`)
   - `available_headers` — passed to the AI prompt so it knows which
     `#include <...>` directives are safe to use (e.g. `znc/Message.h`)

2. **What this means for you as an agent** — if you're driving the workflow
   from the CLI, run the equivalent yourself before generating the harness:
   ```bash
   # Find where the library headers live
   find /usr /opt/homebrew/include /usr/local/include -name "Message.h" 2>/dev/null
   # e.g. found at /opt/homebrew/include/znc/Message.h → add -I/opt/homebrew/include
   ```
   Then pass the resolved directories as `-I` flags in the compile command and
   tell the AI which headers it can include.

3. **Pre-compiled library** — if the library itself needs to be linked, add the
   `.a`/`.so`/`.dylib` in the Compile step under **+ Add library**, or pass it
   directly on the clang++ command line.

   Example for ZNC (headers installed via package manager, library built from source):
   ```bash
   clang++ -fsanitize=fuzzer,address -O1 -g \
     -I/opt/homebrew/include \
     harness.cpp target.cpp \
     -L/opt/homebrew/lib -lznc \
     -o fuzzer
   ```

## Guzzle GUI quick reference

| Step | What happens |
|---|---|
| Open file | Load C/C++ source into Monaco editor; auto-detects library include paths |
| Click function | Tree-sitter parses and identifies the function signature |
| Fuzz Wizard → Harness | AI generates the harness; you can edit before compiling |
| Fuzz Wizard → Compile | clang + ASan + libFuzzer; output goes to `.guzzle/fuzzer` |
| Fuzz Wizard → Running | Fuzzer runs; crashes appear in real time |
| Results → Gen PoC | Compiles reproducer, extracts ROP gadgets, calls AI for pwntools script |

All artifacts live in `.guzzle/` next to your source file:
```
.guzzle/
  fuzzer           # compiled fuzzer binary
  reproducer       # standalone crash reproducer
  corpus/          # fuzzer-generated test cases
  crashes/         # crash inputs
  harness.cpp      # the harness as compiled
  harness_cache.json  # cached AI-generated harnesses (keyed by file hash + function name)
```
