use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportedSymbol {
    /// Demangled / display name (leading `_` stripped on macOS)
    pub name: String,
    /// Raw symbol name as reported by the tool
    pub raw_name: String,
    /// Single-char type code from nm (e.g. "T", "D", "U")
    pub symbol_type: String,
    /// True when symbol_type is "T" (text/code section) — a function
    pub is_function: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SymbolList {
    pub symbols: Vec<ExportedSymbol>,
    /// Which tool was used to extract symbols
    pub tool_used: String,
    pub binary_path: String,
}

/// Parse POSIX-format `nm` output.
///
/// Each line looks like:
///   `_compress2 T 00001234 000000a0`   (macOS)
///   `compress2 T 00001234 000000a0`    (Linux)
///
/// We only care about defined external symbols (`--defined-only --extern-only`).
pub fn parse_nm_output(output: &str, strip_leading_underscore: bool) -> Vec<ExportedSymbol> {
    let mut symbols = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // POSIX format: name type [value [size]]
        let mut parts = line.split_whitespace();
        let Some(raw_name) = parts.next() else { continue };
        let Some(type_char) = parts.next() else { continue };
        // Skip undefined symbols (lowercase 'u' or 'U' in some nm versions)
        if type_char.eq_ignore_ascii_case("u") {
            continue;
        }
        let raw_name = raw_name.to_string();
        let name = if strip_leading_underscore {
            raw_name.trim_start_matches('_').to_string()
        } else {
            raw_name.clone()
        };
        let symbol_type = type_char.to_uppercase().to_string();
        let is_function = symbol_type == "T";
        symbols.push(ExportedSymbol { name, raw_name, symbol_type, is_function });
    }
    symbols
}

/// Parse `dumpbin /EXPORTS` output (Windows).
///
/// The interesting lines look like:
///   `          1    0 00001000 compress2`
/// We stop at the "Summary" section to avoid garbage lines.
#[cfg(target_os = "windows")]
pub fn parse_dumpbin_output(output: &str) -> Vec<ExportedSymbol> {
    let mut symbols = Vec::new();
    let mut in_exports = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Summary") {
            break;
        }
        // The exports section starts after a header line containing "ordinal"
        if !in_exports {
            if trimmed.to_lowercase().contains("ordinal") && trimmed.to_lowercase().contains("name") {
                in_exports = true;
            }
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        // Lines: ordinal  hint  rva  name
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        // Need at least 4 columns and the ordinal must be a number
        if parts.len() < 4 {
            continue;
        }
        if parts[0].parse::<u32>().is_err() {
            continue;
        }
        let raw_name = parts[3].to_string();
        symbols.push(ExportedSymbol {
            name: raw_name.clone(),
            raw_name,
            symbol_type: "T".to_string(),
            is_function: true,
        });
    }
    symbols
}

#[tauri::command]
pub async fn extract_symbols(binary_path: String) -> Result<SymbolList, String> {
    use std::process::Command;

    if !std::path::Path::new(&binary_path).exists() {
        return Err(format!("File not found: {binary_path}"));
    }

    // ── Windows: try dumpbin first, fall back to nm ────────────────────────
    #[cfg(target_os = "windows")]
    {
        // Try dumpbin /EXPORTS
        if let Ok(out) = Command::new("dumpbin").args(["/EXPORTS", &binary_path]).output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout).to_string();
                let symbols = parse_dumpbin_output(&text);
                return Ok(SymbolList {
                    symbols,
                    tool_used: "dumpbin".to_string(),
                    binary_path,
                });
            }
        }
        // Fallback: nm.exe
        let out = Command::new("nm")
            .args(["--defined-only", "--extern-only", "--format=posix", &binary_path])
            .output()
            .map_err(|e| format!("nm not found: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(format!("nm failed: {stderr}"));
        }
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let symbols = parse_nm_output(&text, false);
        return Ok(SymbolList {
            symbols,
            tool_used: "nm".to_string(),
            binary_path,
        });
    }

    // ── macOS / Linux: nm ─────────────────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    {
        let out = Command::new("nm")
            .args(["--defined-only", "--extern-only", "--format=posix", &binary_path])
            .output()
            .map_err(|e| format!("nm not found: {e}"))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(format!("nm failed: {stderr}"));
        }

        let text = String::from_utf8_lossy(&out.stdout).to_string();
        // macOS nm prefixes C symbols with a leading underscore
        let strip = cfg!(target_os = "macos");
        let symbols = parse_nm_output(&text, strip);
        Ok(SymbolList {
            symbols,
            tool_used: "nm".to_string(),
            binary_path,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_parse_basic() {
        let output = "compress2 T 00001234 000000a0\ndeflate T 00002000 00000080\n";
        let syms = parse_nm_output(output, false);
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].name, "compress2");
        assert!(syms[0].is_function);
        assert_eq!(syms[0].symbol_type, "T");
    }

    #[test]
    fn posix_parse_skips_undefined() {
        // Lines with 'u' or 'U' type must be skipped
        let output = "malloc U\ncompress2 T 00001234\n";
        let syms = parse_nm_output(output, false);
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "compress2");
    }

    #[test]
    fn posix_parse_non_function_symbol() {
        let output = "some_data D 00003000\n";
        let syms = parse_nm_output(output, false);
        assert_eq!(syms.len(), 1);
        assert!(!syms[0].is_function);
        assert_eq!(syms[0].symbol_type, "D");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn posix_parse_strips_leading_underscore_on_macos() {
        let output = "_compress2 T 00001234 000000a0\n";
        let syms = parse_nm_output(output, true);
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "compress2", "leading underscore must be stripped");
        assert_eq!(syms[0].raw_name, "_compress2", "raw_name must preserve underscore");
    }

    #[test]
    fn posix_parse_no_strip_underscore_when_false() {
        let output = "_compress2 T 00001234\n";
        let syms = parse_nm_output(output, false);
        assert_eq!(syms[0].name, "_compress2");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dumpbin_parse_basic() {
        let output = "\
            Section contains the following exports for zlib.dll\r\n\
            \r\n\
                  ordinal hint RVA      name\r\n\
            \r\n\
                        1    0 00001000 compress2\r\n\
                        2    1 00002000 deflate\r\n\
            \r\n\
          Summary\r\n\
            00001000 .text\r\n\
        ";
        let syms = parse_dumpbin_output(output);
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].name, "compress2");
        assert!(syms[0].is_function);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dumpbin_stops_at_summary() {
        let output = "\
              ordinal hint RVA      name\r\n\
                    1    0 00001000 foo\r\n\
          Summary\r\n\
                    2    1 00002000 bar\r\n\
        ";
        let syms = parse_dumpbin_output(output);
        // "bar" appears after "Summary" — must not be included
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "foo");
    }

    #[tokio::test]
    async fn nonexistent_file_returns_error() {
        let result = extract_symbols("/nonexistent/path/libfoo.so".to_string()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }
}
