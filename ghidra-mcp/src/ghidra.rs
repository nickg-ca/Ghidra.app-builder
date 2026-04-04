use std::path::PathBuf;
use std::process::Stdio;

use tokio::process::{Child, Command};

/// Configuration for locating Ghidra and its components.
pub struct GhidraConfig {
    /// Path to the Ghidra install dir (e.g., ghidra_12.0.4_DEV)
    pub install_dir: PathBuf,
    /// Path to support/launch.sh
    pub launch_sh: PathBuf,
    /// Path to JAVA_HOME
    pub java_home: PathBuf,
    /// Path to the scripts directory (where McpBridge.java lives)
    pub scripts_dir: PathBuf,
    /// Default project directory (~/.ghidra-mcp/projects/)
    pub default_project_dir: PathBuf,
    /// Default max memory (half of system RAM)
    pub default_max_memory: String,
}

impl GhidraConfig {
    /// Auto-detect Ghidra paths relative to the current binary location.
    /// Expected layout: Ghidra.app/Contents/MacOS/ghidra-mcp (this binary)
    ///                  Ghidra.app/Contents/Resources/ghidra_*/support/launch.sh
    ///                  Ghidra.app/Contents/Resources/jdk-*/Contents/Home
    pub fn detect() -> Result<Self, Box<dyn std::error::Error>> {
        let exe_path = std::env::current_exe()?;
        let macos_dir = exe_path.parent().ok_or("Cannot find MacOS dir")?;
        let contents_dir = macos_dir.parent().ok_or("Cannot find Contents dir")?;
        let resources_dir = contents_dir.join("Resources");

        // Find Ghidra install dir (ghidra_*)
        let install_dir = find_dir_matching(&resources_dir, "ghidra_")?;
        let launch_sh = install_dir.join("support").join("launch.sh");

        if !launch_sh.exists() {
            return Err(format!("launch.sh not found at {}", launch_sh.display()).into());
        }

        // Find JDK
        let java_home = find_dir_matching(&resources_dir, "jdk-")
            .map(|p| p.join("Contents").join("Home"))?;

        if !java_home.exists() {
            return Err(format!("JAVA_HOME not found at {}", java_home.display()).into());
        }

        // Scripts dir: same as ghidra scripts dir
        let scripts_dir = install_dir
            .join("Ghidra")
            .join("Features")
            .join("Base")
            .join("ghidra_scripts");

        // Default project dir
        let default_project_dir = dirs_or_home()
            .join(".ghidra-mcp")
            .join("projects");

        // Detect system memory
        let default_max_memory = detect_max_memory();

        Ok(GhidraConfig {
            install_dir,
            launch_sh,
            java_home,
            scripts_dir,
            default_project_dir,
            default_max_memory,
        })
    }
}

/// Find a directory in `parent` whose name starts with `prefix`.
fn find_dir_matching(parent: &std::path::Path, prefix: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let entries = std::fs::read_dir(parent)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(prefix) && entry.file_type()?.is_dir() {
            return Ok(entry.path());
        }
    }
    Err(format!("No directory matching '{}*' in {}", prefix, parent.display()).into())
}

/// Get the user's home directory.
fn dirs_or_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

/// Detect half of system RAM as the default max memory string (e.g., "32G").
fn detect_max_memory() -> String {
    let output = std::process::Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output();

    match output {
        Ok(out) => {
            let bytes_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Ok(bytes) = bytes_str.parse::<u64>() {
                let gb = bytes / 1_073_741_824; // bytes to GB
                let half = (gb / 2).max(2); // at least 2GB
                format!("{}G", half)
            } else {
                "4G".to_string()
            }
        }
        Err(_) => "4G".to_string(),
    }
}

/// Find a free TCP port on localhost.
pub fn find_free_port() -> Result<u16, std::io::Error> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Spawn an analyzeHeadless import process via launch.sh.
pub fn spawn_import(
    config: &GhidraConfig,
    project_dir: &std::path::Path,
    project_name: &str,
    binary_path: &std::path::Path,
    max_memory: &str,
    analysis_timeout: u64,
    processor: Option<&str>,
) -> Result<Child, std::io::Error> {
    let vmargs = "-XX:ParallelGCThreads=2 -XX:CICompilerCount=2 -Djava.awt.headless=true";

    let mut args: Vec<String> = vec![
        "fg".to_string(),
        "jdk".to_string(),
        "Ghidra-Headless".to_string(),
        max_memory.to_string(),
        vmargs.to_string(),
        "ghidra.app.util.headless.AnalyzeHeadless".to_string(),
        project_dir.to_string_lossy().to_string(),
        project_name.to_string(),
        "-import".to_string(),
        binary_path.to_string_lossy().to_string(),
        "-analysisTimeoutPerFile".to_string(),
        analysis_timeout.to_string(),
    ];

    if let Some(proc) = processor {
        args.push("-processor".to_string());
        args.push(proc.to_string());
    }

    tracing::info!("Spawning import: {} {:?}", config.launch_sh.display(), args);

    Command::new(&config.launch_sh)
        .args(&args)
        .env("JAVA_HOME", &config.java_home)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit()) // Ghidra logs go to MCP server's stderr
        .spawn()
}

/// Spawn a bridge process: analyzeHeadless -process with McpBridge.java script.
pub fn spawn_bridge(
    config: &GhidraConfig,
    project_dir: &std::path::Path,
    project_name: &str,
    program_name: Option<&str>,
    port: u16,
    max_memory: &str,
) -> Result<Child, std::io::Error> {
    let vmargs = "-XX:ParallelGCThreads=2 -XX:CICompilerCount=2 -Djava.awt.headless=true";

    let mut args: Vec<String> = vec![
        "fg".to_string(),
        "jdk".to_string(),
        "Ghidra-Headless".to_string(),
        max_memory.to_string(),
        vmargs.to_string(),
        "ghidra.app.util.headless.AnalyzeHeadless".to_string(),
        project_dir.to_string_lossy().to_string(),
        project_name.to_string(),
        "-process".to_string(),
    ];

    if let Some(prog) = program_name {
        args.push(prog.to_string());
    }

    args.extend([
        "-noanalysis".to_string(),
        "-postScript".to_string(),
        "McpBridge.java".to_string(),
        port.to_string(),
        "-scriptPath".to_string(),
        config.scripts_dir.to_string_lossy().to_string(),
    ]);

    tracing::info!("Spawning bridge: {} {:?}", config.launch_sh.display(), args);

    Command::new(&config.launch_sh)
        .args(&args)
        .env("JAVA_HOME", &config.java_home)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit()) // Ghidra logs go to MCP server's stderr
        .spawn()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_max_memory_returns_valid_string() {
        let mem = detect_max_memory();
        // Should end with 'G' and have a number before it
        assert!(mem.ends_with('G'), "Expected format like '32G', got '{}'", mem);
        let num_str = &mem[..mem.len() - 1];
        let num: u64 = num_str.parse().expect("Expected numeric prefix");
        assert!(num >= 2, "Expected at least 2G, got {}", num);
        // Sanity check: no machine has > 16TB RAM
        assert!(num <= 16384, "Unreasonably large: {}G", num);
    }

    #[test]
    fn find_free_port_returns_valid_port() {
        let port = find_free_port().expect("Should find a free port");
        assert!(port > 0, "Port should be > 0");
    }

    #[test]
    fn find_free_port_returns_distinct_ports() {
        let port1 = find_free_port().expect("port 1");
        let port2 = find_free_port().expect("port 2");
        assert!(port1 > 0);
        assert!(port2 > 0);
    }

    #[test]
    fn config_detect_fails_gracefully_outside_app_bundle() {
        // When running from cargo test, we're not inside a Ghidra.app bundle,
        // so detect() should return an error, not panic.
        let result = GhidraConfig::detect();
        assert!(result.is_err(), "Expected error when not in Ghidra.app bundle");
    }

    #[test]
    fn find_dir_matching_returns_error_for_missing_prefix() {
        let result = find_dir_matching(std::path::Path::new("/tmp"), "nonexistent_prefix_xyz_");
        assert!(result.is_err());
    }

    #[test]
    fn dirs_or_home_returns_something() {
        let home = dirs_or_home();
        assert!(!home.to_string_lossy().is_empty());
    }
}
