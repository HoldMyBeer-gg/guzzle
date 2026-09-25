mod commands;

use commands::{toolchain, parser, ai, compile, fuzzer, poc, cache, includes, symbols};

#[tauri::command]
fn reveal_in_finder(path: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    std::process::Command::new("open")
        .arg(&path)
        .spawn()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "linux")]
    std::process::Command::new("xdg-open")
        .arg(&path)
        .spawn()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    std::process::Command::new("explorer")
        .arg(&path)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            toolchain::check_toolchain,
            toolchain::check_toolchain_at,
            parser::parse_function_at_line,
            ai::generate_harness,
            compile::compile_harness,
            fuzzer::start_fuzzer,
            fuzzer::stop_fuzzer,
            fuzzer::read_crash_files,
            ai::save_api_key,
            ai::load_api_key,
            poc::generate_poc,
            cache::get_cached_harness,
            cache::save_cached_harness,
            includes::resolve_includes,
            symbols::extract_symbols,
            ai::generate_harness_binary,
            reveal_in_finder,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
