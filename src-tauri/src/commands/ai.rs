use serde::{Deserialize, Serialize};

use super::parser::FunctionSignature;

/// Which wire format the provider speaks.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ApiFormat {
    /// OpenAI-compatible /v1/chat/completions (DeepSeek, Ollama, OpenAI, etc.)
    Openai,
    /// Anthropic /v1/messages
    Anthropic,
}

/// Provider configuration passed from the frontend.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AiProvider {
    /// Human-readable name, also used as the keyring account name.
    pub name: String,
    /// Base URL, e.g. "https://api.deepseek.com" or "http://localhost:11434"
    pub base_url: String,
    /// Model identifier, e.g. "deepseek-chat" or "llama3"
    pub model: String,
    /// API key (empty string for local Ollama)
    pub api_key: String,
    /// Which request/response format to use
    pub format: ApiFormat,
}

// ── OpenAI-compat structs ────────────────────────────────────────────────────

#[derive(Serialize)]
struct OaiMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct OaiRequest {
    model: String,
    messages: Vec<OaiMessage>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Deserialize)]
struct OaiResponse {
    choices: Vec<OaiChoice>,
}

#[derive(Deserialize)]
struct OaiChoice {
    message: OaiMessage2,
}

#[derive(Deserialize)]
struct OaiMessage2 {
    content: String,
}

// ── Anthropic structs ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<AnthropicMessage>,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicBlock>,
}

#[derive(Deserialize)]
struct AnthropicBlock {
    #[serde(rename = "type")]
    block_type: String,
    text: Option<String>,
}

// ── Prompt building ──────────────────────────────────────────────────────────

fn build_prompt(signature: &FunctionSignature, context_lines: &str, include_hints: &[String]) -> (String, String) {
    let param_str = signature
        .params
        .iter()
        .map(|p| format!("{} {}", p.type_name, p.param_name))
        .collect::<Vec<_>>()
        .join(", ");

    let func_sig = format!(
        "{} {}({})",
        signature.return_type, signature.name, param_str
    );

    let system = "You are an expert C/C++ security engineer specializing in fuzzing with libFuzzer. \
        Generate minimal, correct, safe fuzzer harnesses. \
        Output only raw C/C++ source code with no markdown fences and no explanation."
        .to_string();

    let user = format!(
        r#"Generate a libFuzzer harness for the following C/C++ function.

Function signature:
```c
{func_sig}
```

Surrounding code context:
```c
{context_lines}
```

Requirements:
1. Implement `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`

2. Prefer FuzzedDataProvider (`<fuzzer/FuzzedDataProvider.h>`) for typed arguments:
     FuzzedDataProvider fdp(data, size);
   Declare and initialize it in one statement — it has no default constructor and
   its copy-assignment operator is deleted. Fall back to raw data/size only when
   the function genuinely expects an unstructured byte buffer.

3. Derive valid arguments for `{func_name}` from the fuzzer input.
   Guard against null pointers and out-of-bounds access before each call.

4. Include only standard C/C++ headers (`<stdint.h>`, `<stddef.h>`, `<stdlib.h>`,
   `<string.h>`, `<stdio.h>`). Do NOT use `<unistd.h>`, `<fcntl.h>`, or any
   other POSIX-only header — the harness must also compile on Windows.

5. Do NOT call exit() or abort().

6. Do NOT use mkstemp or any platform-specific temp-file API. Use a fixed path:
   `"/tmp/guzzle_input"` on Linux/macOS, `"C:\\Temp\\guzzle_input"` on Windows
   (guard with `#ifdef _WIN32`). Do NOT write to the current directory.

7. Do NOT add `#define _CRT_SECURE_NO_WARNINGS` — it is already a compiler flag.

8. The harness is compiled as C++ (`clang++ -x c++`). Cast every malloc/realloc:
   `MyType *p = (MyType *)malloc(n);`

9. Zero-initialize output structs before passing them to the target:
   `MyStruct s = {{0}};`

10. Free each heap pointer exactly once. For tagged/union fields use if/else so
    no pointer is freed in more than one branch.

11. If the context includes a "// Macro definitions from source file:" section,
    copy every `#define` from it verbatim into the harness before any use.

12. If the target function is declared `static` in the context, it has internal
    linkage and CANNOT be called from the harness — no exported symbol exists.
    Do NOT forward-declare it and do NOT call it. Call the public (non-static)
    function in the same file that invokes it internally.
{include_rule}
Return ONLY the C/C++ source code, no markdown fences."#,
        func_name = signature.name,
        include_rule = if include_hints.is_empty() {
            String::new()
        } else {
            let list = include_hints.iter()
                .map(|h| format!("   <{h}>"))
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "\n13. The following system headers were confirmed to exist on this machine — \
                you MAY use #include <...> for any of them:\n{list}\n    \
                Do NOT #include library headers that are not in this list."
            )
        },
    );

    (system, user)
}

fn build_binary_prompt(
    symbol_name: &str,
    include_hints: &[String],
    companion_header: Option<&str>,
) -> (String, String) {
    let system = "You are an expert C/C++ security engineer specializing in fuzzing with libFuzzer. \
        Generate minimal, correct, safe fuzzer harnesses. \
        Output only raw C/C++ source code with no markdown fences and no explanation."
        .to_string();

    let header_section = if let Some(hdr) = companion_header {
        format!(
            "A companion header is provided — use the exact types and signature from it:\n\
             ```c\n{hdr}\n```\n"
        )
    } else {
        format!(
            "No header is available. Declare the function with `extern \"C\"` using common \
             conventions for the function name `{symbol_name}`. For example:\n\
             ```c\nextern \"C\" int {symbol_name}(/* inferred params */);\n```\n"
        )
    };

    let extern_c_rule = if companion_header.is_none() {
        "\n13. Declare the target function with `extern \"C\"` before calling it — \
             it lives in a pre-built binary and has C linkage."
            .to_string()
    } else {
        String::new()
    };

    let user = format!(
        r#"Generate a libFuzzer harness that fuzzes the function `{symbol_name}` from a pre-built binary library.

{header_section}
Requirements:
1. Implement `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`

2. Prefer FuzzedDataProvider (`<fuzzer/FuzzedDataProvider.h>`) for typed arguments:
     FuzzedDataProvider fdp(data, size);
   Declare and initialize it in one statement — it has no default constructor and
   its copy-assignment operator is deleted. Fall back to raw data/size only when
   the function genuinely expects an unstructured byte buffer.

3. Derive valid arguments for `{symbol_name}` from the fuzzer input.
   Guard against null pointers and out-of-bounds access before each call.

4. Include only standard C/C++ headers (`<stdint.h>`, `<stddef.h>`, `<stdlib.h>`,
   `<string.h>`, `<stdio.h>`). Do NOT use `<unistd.h>`, `<fcntl.h>`, or any
   other POSIX-only header — the harness must also compile on Windows.

5. Do NOT call exit() or abort().

6. Do NOT use mkstemp or any platform-specific temp-file API. Use a fixed path:
   `"/tmp/guzzle_input"` on Linux/macOS, `"C:\\Temp\\guzzle_input"` on Windows
   (guard with `#ifdef _WIN32`). Do NOT write to the current directory.

7. Do NOT add `#define _CRT_SECURE_NO_WARNINGS` — it is already a compiler flag.

8. The harness is compiled as C++ (`clang++ -x c++`). Cast every malloc/realloc:
   `MyType *p = (MyType *)malloc(n);`

9. Zero-initialize output structs before passing them to the target:
   `MyStruct s = {{0}};`

10. Free each heap pointer exactly once. For tagged/union fields use if/else so
    no pointer is freed in more than one branch.

11. If the context includes a "// Macro definitions from source file:" section,
    copy every `#define` from it verbatim into the harness before any use.

12. Do NOT include any source-context section — this is a pre-built binary with
    no source available.{extern_c_rule}
{include_rule}
Return ONLY the C/C++ source code, no markdown fences."#,
        include_rule = if include_hints.is_empty() {
            String::new()
        } else {
            let list = include_hints.iter()
                .map(|h| format!("   <{h}>"))
                .collect::<Vec<_>>()
                .join("\n");
            let rule_num = if companion_header.is_none() { 14 } else { 13 };
            format!(
                "\n{rule_num}. The following system headers were confirmed to exist on this machine — \
                you MAY use #include <...> for any of them:\n{list}\n    \
                Do NOT #include library headers that are not in this list."
            )
        },
    );

    (system, user)
}

#[tauri::command]
pub async fn generate_harness_binary(
    provider: AiProvider,
    symbol_name: String,
    companion_header_content: Option<String>,
    include_hints: Option<Vec<String>>,
) -> Result<String, String> {
    let hints = include_hints.unwrap_or_default();
    let (system, user) = build_binary_prompt(
        &symbol_name,
        &hints,
        companion_header_content.as_deref(),
    );
    let client = make_client()?;

    let raw = match provider.format {
        ApiFormat::Openai => call_openai_compat(&client, &provider, system, user).await,
        ApiFormat::Anthropic => call_anthropic(&client, &provider, system, user).await,
    }?;

    // Close any unclosed braces if the model was cut off
    let open: i32 = raw.chars().filter(|&c| c == '{').count() as i32;
    let close: i32 = raw.chars().filter(|&c| c == '}').count() as i32;
    let raw = if open > close {
        format!("{}\n{}", raw, "}".repeat((open - close) as usize))
    } else {
        raw
    };

    Ok(raw)
}

fn make_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        // AI responses (especially PoC scripts) can take a while — 5 min timeout.
        .timeout(std::time::Duration::from_secs(300))
        // Send TCP keepalive probes every 30 s so NAT routers don't drop the
        // connection while the AI server is generating a long response.
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))
}

fn fmt_err(e: &reqwest::Error) -> String {
    use std::error::Error;
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(cause) = src {
        msg.push_str(&format!(" → {cause}"));
        src = cause.source();
    }
    msg
}

/// Generic AI call — used by both harness generation and PoC generation.
pub async fn call_ai(provider: &AiProvider, system: String, user: String) -> Result<String, String> {
    let client = make_client()?;
    match provider.format {
        ApiFormat::Openai => call_openai_compat(&client, provider, system, user).await,
        ApiFormat::Anthropic => call_anthropic(&client, provider, system, user).await,
    }
}

// ── Main command ─────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn generate_harness(
    provider: AiProvider,
    signature: FunctionSignature,
    context_lines: String,
    include_hints: Option<Vec<String>>,
) -> Result<String, String> {
    let hints = include_hints.unwrap_or_default();
    let (system, user) = build_prompt(&signature, &context_lines, &hints);
    let client = make_client()?;

    let raw = match provider.format {
        ApiFormat::Openai => call_openai_compat(&client, &provider, system, user).await,
        ApiFormat::Anthropic => call_anthropic(&client, &provider, system, user).await,
    }?;

    // If the model was cut off mid-function, close any unclosed braces.
    let open: i32 = raw.chars().filter(|&c| c == '{').count() as i32;
    let close: i32 = raw.chars().filter(|&c| c == '}').count() as i32;
    let raw = if open > close {
        format!("{}\n{}", raw, "}".repeat((open - close) as usize))
    } else {
        raw
    };

    Ok(raw)
}

async fn call_openai_compat(
    client: &reqwest::Client,
    provider: &AiProvider,
    system: String,
    user: String,
) -> Result<String, String> {
    let url = format!("{}/v1/chat/completions", provider.base_url.trim_end_matches('/'));

    let request = OaiRequest {
        model: provider.model.clone(),
        messages: vec![
            OaiMessage { role: "system".into(), content: system },
            OaiMessage { role: "user".into(), content: user },
        ],
        max_tokens: 4096,
        temperature: 0.2,
    };

    let mut req = client.post(&url).json(&request);
    if !provider.api_key.is_empty() {
        req = req.bearer_auth(&provider.api_key);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", fmt_err(&e)))?;

    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| format!("Failed to read response body: {}", fmt_err(&e)))?;
    let body = String::from_utf8_lossy(&bytes).to_string();

    if !status.is_success() {
        return Err(format!("{} API error {status}: {body}", provider.name));
    }

    let oai: OaiResponse = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse response: {e}\nRaw body: {body}"))?;

    oai.choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .ok_or_else(|| "Empty response from model".into())
}

async fn call_anthropic(
    client: &reqwest::Client,
    provider: &AiProvider,
    system: String,
    user: String,
) -> Result<String, String> {
    let url = format!("{}/v1/messages", provider.base_url.trim_end_matches('/'));

    let request = AnthropicRequest {
        model: provider.model.clone(),
        max_tokens: 4096,
        system,
        messages: vec![AnthropicMessage { role: "user".into(), content: user }],
    };

    let resp = client
        .post(&url)
        .header("x-api-key", &provider.api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("HTTP error: {e}"))?;

    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| format!("Failed to read Anthropic response body: {e}"))?;
    let body = String::from_utf8_lossy(&bytes).to_string();

    if !status.is_success() {
        return Err(format!("Anthropic API error {status}: {body}"));
    }

    let ar: AnthropicResponse = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse Anthropic response: {e}\nRaw body: {body}"))?;

    let text = ar
        .content
        .into_iter()
        .filter(|b| b.block_type == "text")
        .filter_map(|b| b.text)
        .collect::<Vec<_>>()
        .join("");

    if text.is_empty() {
        Err("Empty response from Anthropic".into())
    } else {
        Ok(text)
    }
}

// ── Keyring (keyed by provider name) ─────────────────────────────────────────

const KEYRING_SERVICE: &str = "guzzle";

#[tauri::command]
pub async fn save_api_key(provider_name: String, key: String) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &provider_name)
        .map_err(|e| format!("Keyring error: {e}"))?;
    entry.set_password(&key).map_err(|e| format!("Keyring error: {e}"))
}

#[tauri::command]
pub async fn load_api_key(provider_name: String) -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &provider_name)
        .map_err(|e| format!("Keyring error: {e}"))?;
    match entry.get_password() {
        Ok(key) => Ok(Some(key)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Keyring error: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_sig(name: &str) -> FunctionSignature {
        FunctionSignature {
            name: name.to_string(),
            return_type: "int".to_string(),
            params: vec![],
            start_line: 1,
            end_line: 5,
        }
    }

    #[test]
    fn build_prompt_contains_function_name() {
        let sig = dummy_sig("ProcessImage");
        let (system, user) = build_prompt(&sig, "// context", &[]);
        assert!(user.contains("ProcessImage"));
        assert!(!system.is_empty());
    }

    #[test]
    fn build_prompt_contains_context() {
        let sig = dummy_sig("foo");
        let (_, user) = build_prompt(&sig, "int foo() {}", &[]);
        assert!(user.contains("int foo() {}"));
    }

    #[test]
    fn build_prompt_no_markdown_fences_in_system() {
        let sig = dummy_sig("foo");
        let (system, _) = build_prompt(&sig, "", &[]);
        // System prompt should instruct to omit markdown fences
        assert!(system.contains("no markdown"));
    }

    #[test]
    fn build_prompt_includes_llvmfuzzer_requirement() {
        let sig = dummy_sig("foo");
        let (_, user) = build_prompt(&sig, "", &[]);
        assert!(user.contains("LLVMFuzzerTestOneInput"));
    }

    #[test]
    fn build_prompt_mentions_fuzzed_data_provider() {
        let sig = dummy_sig("ParseData");
        let (_, user) = build_prompt(&sig, "", &[]);
        assert!(
            user.contains("FuzzedDataProvider"),
            "prompt must mention FuzzedDataProvider for structured input consumption"
        );
    }

    #[test]
    fn build_prompt_requires_malloc_cast() {
        let sig = dummy_sig("foo");
        let (_, user) = build_prompt(&sig, "", &[]);
        assert!(user.contains("malloc") && (user.contains("cast") || user.contains("Cast")));
    }

    #[test]
    fn build_prompt_requires_zero_init() {
        let sig = dummy_sig("foo");
        let (_, user) = build_prompt(&sig, "", &[]);
        assert!(user.contains("zero-init") || user.contains("memset") || user.contains("{0}"),
            "prompt must instruct AI to zero-initialize output structs");
    }

    #[test]
    fn build_prompt_requires_single_free() {
        let sig = dummy_sig("foo");
        let (_, user) = build_prompt(&sig, "", &[]);
        assert!(user.contains("exactly once") || user.contains("free a pointer and") || user.contains("if/else"),
            "prompt must instruct AI to free each pointer exactly once");
    }

    #[test]
    fn build_prompt_requires_copying_context_defines() {
        let sig = dummy_sig("foo");
        let (_, user) = build_prompt(&sig, "", &[]);
        // Reactive: AI uses #define names from context without copying their definitions
        // into the harness, producing "undeclared identifier" compile errors.
        assert!(
            user.contains("Macro definitions from source file") && user.contains("copy"),
            "prompt must instruct AI to copy #define lines from context into the harness"
        );
    }

    #[test]
    fn build_prompt_no_posix_headers_required() {
        let sig = dummy_sig("foo");
        let (_, user) = build_prompt(&sig, "", &[]);
        // Prompt must not require POSIX-only headers without Windows guard
        assert!(user.contains("unistd.h") == false || user.contains("_WIN32"));
    }

    #[test]
    fn build_prompt_includes_hint_headers_in_rule() {
        let sig = dummy_sig("foo");
        let hints = vec!["znc/Message.h".to_string(), "openssl/ssl.h".to_string()];
        let (_, user) = build_prompt(&sig, "", &hints);
        assert!(user.contains("znc/Message.h"), "prompt must list confirmed headers");
        assert!(user.contains("openssl/ssl.h"));
        assert!(user.contains("confirmed to exist"));
    }

    #[test]
    fn build_prompt_no_include_rule_when_hints_empty() {
        let sig = dummy_sig("foo");
        let (_, user) = build_prompt(&sig, "", &[]);
        assert!(!user.contains("confirmed to exist"),
            "include hint rule must be absent when no hints provided");
    }

    // ── build_binary_prompt tests ────────────────────────────────────────────

    #[test]
    fn binary_prompt_contains_symbol_name() {
        let (_, user) = build_binary_prompt("compress2", &[], None);
        assert!(user.contains("compress2"), "prompt must mention the symbol name");
    }

    #[test]
    fn binary_prompt_no_source_context_section() {
        let (_, user) = build_binary_prompt("compress2", &[], None);
        assert!(!user.contains("Surrounding code context"),
            "binary prompt must not include a source-context section");
    }

    #[test]
    fn binary_prompt_includes_header_when_provided() {
        let header = "int compress2(void *dest, unsigned long *destLen, const void *source, unsigned long sourceLen, int level);";
        let (_, user) = build_binary_prompt("compress2", &[], Some(header));
        assert!(user.contains(header), "companion header must appear verbatim in the prompt");
    }

    #[test]
    fn binary_prompt_extern_c_instruction_when_no_header() {
        let (_, user) = build_binary_prompt("compress2", &[], None);
        assert!(user.contains("extern \"C\""),
            "prompt must instruct AI to use extern \"C\" declaration when no header");
    }

    #[test]
    fn binary_prompt_no_extern_c_rule_when_header_provided() {
        let header = "int compress2(void *dest, unsigned long *destLen);";
        let (_, user) = build_binary_prompt("compress2", &[], Some(header));
        // Rule 13 about extern "C" declaration should not appear since header is provided
        assert!(!user.contains("lives in a pre-built binary and has C linkage"),
            "extern-C rule must be omitted when header is provided");
    }

    #[test]
    fn binary_prompt_requires_llvmfuzzer() {
        let (_, user) = build_binary_prompt("foo", &[], None);
        assert!(user.contains("LLVMFuzzerTestOneInput"));
    }

    #[test]
    fn binary_prompt_no_posix_headers() {
        let (_, user) = build_binary_prompt("foo", &[], None);
        // Must not require POSIX-only headers without a Windows guard
        assert!(!user.contains("unistd.h") || user.contains("_WIN32"));
    }

    #[test]
    fn make_client_succeeds() {
        make_client().expect("reqwest client with 5-min timeout and gzip disabled should build successfully");
    }

    #[test]
    fn oai_response_deserializes() {
        let json = r#"{"choices":[{"message":{"role":"assistant","content":"hello"}}]}"#;
        let r: OaiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.choices[0].message.content, "hello");
    }

    #[test]
    fn anthropic_response_deserializes() {
        let json = r#"{"content":[{"type":"text","text":"hello"}]}"#;
        let r: AnthropicResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.content[0].block_type, "text");
        assert_eq!(r.content[0].text.as_deref(), Some("hello"));
    }

    #[test]
    fn anthropic_response_ignores_non_text_blocks() {
        let json = r#"{"content":[{"type":"thinking","thinking":"chain"},{"type":"text","text":"result"}]}"#;
        let r: AnthropicResponse = serde_json::from_str(json).unwrap();
        let text: String = r.content.into_iter()
            .filter(|b| b.block_type == "text")
            .filter_map(|b| b.text)
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(text, "result");
    }
}
