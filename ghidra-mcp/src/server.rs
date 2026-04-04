use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    schemars, tool, tool_handler, tool_router,
};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::bridge::Bridge;
use crate::ghidra::GhidraConfig;

const INSTRUCTIONS: &str = r#"Ghidra MCP Server - AI-Assisted Reverse Engineering

WORKFLOW:
1. IMPORT: ghidra_import to import+analyze a binary (one-time, slow for large bins).
   This runs Ghidra's headless analyzer. For large binaries like dyld, this can take
   hours and use many GB of RAM.
2. OPEN: ghidra_open to load an analyzed program into memory (slow initial load, then fast queries).
   This starts a persistent Ghidra bridge process that keeps the program loaded.
3. EXPLORE: ghidra_info -> ghidra_functions -> ghidra_decompile -> ghidra_xrefs
4. ANNOTATE: ghidra_rename, ghidra_comment, ghidra_retype_function
5. SAVE: ghidra_save to persist, ghidra_close when done

TIPS:
- Large binaries: use pagination (offset/limit) with ghidra_functions, ghidra_symbols
- ghidra_search_bytes for pattern matching on instruction encodings
- ghidra_callgraph for understanding function relationships
- Always decompile before renaming — understand the function first
- session_id auto-resolves when only one session is active
"#;

/// An active bridge session to a loaded Ghidra program.
pub struct Session {
    pub id: String,
    pub project_dir: PathBuf,
    pub project_name: String,
    pub program_name: String,
    pub bridge: Bridge,
    pub child: tokio::process::Child,
}

/// Tracks a running import operation.
pub struct ImportTask {
    pub project_dir: PathBuf,
    pub project_name: String,
    pub binary_path: String,
    pub status: Arc<Mutex<ImportStatus>>,
}

#[derive(Clone)]
pub enum ImportStatus {
    Running,
    Completed,
    Failed(String),
}

/// The main MCP server struct.
#[derive(Clone)]
pub struct GhidraMcpServer {
    pub sessions: Arc<Mutex<HashMap<String, Session>>>,
    pub imports: Arc<Mutex<HashMap<String, ImportTask>>>,
    pub ghidra: Arc<GhidraConfig>,
    pub next_session_id: Arc<Mutex<u64>>,
    tool_router: ToolRouter<GhidraMcpServer>,
}

// -- Parameter types for tools --

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ImportParams {
    /// Absolute path to the binary file to import
    pub binary_path: String,
    /// Directory to store the Ghidra project. Defaults to ~/.ghidra-mcp/projects/
    pub project_dir: Option<String>,
    /// Name for the Ghidra project. Defaults to the binary filename.
    pub project_name: Option<String>,
    /// Maximum JVM heap size (e.g. '4G', '16G'). Default: half of system RAM.
    pub max_memory: Option<String>,
    /// Analysis timeout in seconds per file. Default: 3600 (1 hour).
    pub analysis_timeout: Option<u64>,
    /// Ghidra language ID (e.g. 'x86:LE:64:default'). Usually auto-detected.
    pub processor: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OpenParams {
    /// Directory containing the Ghidra project
    pub project_dir: String,
    /// Name of the Ghidra project
    pub project_name: String,
    /// Name of the program within the project. If omitted, uses the first program.
    pub program_name: Option<String>,
    /// Maximum JVM heap size. Default: half of system RAM.
    pub max_memory: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionIdParam {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProjectsParams {
    /// Directory to scan for projects. Defaults to ~/.ghidra-mcp/projects/
    pub project_dir: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct InfoParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FunctionsParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Substring filter for function names
    pub filter: Option<String>,
    /// Number of results to skip
    pub offset: Option<u64>,
    /// Maximum number of results to return (default 100)
    pub limit: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DecompileParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Address of the function (hex, e.g. "0x100003f40")
    pub address: Option<String>,
    /// Name of the function
    pub name: Option<String>,
    /// Decompilation timeout in seconds (default 60)
    pub timeout: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DisassembleParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Address to start disassembly (hex, e.g. "0x100003f40")
    pub address: String,
    /// Number of instructions to disassemble (default 50)
    pub count: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct XrefsParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Address to get cross-references for (hex)
    pub address: String,
    /// Direction: "to", "from", or "both" (default "to")
    pub direction: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CallgraphParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Address of the function (hex)
    pub address: Option<String>,
    /// Name of the function
    pub name: Option<String>,
    /// Depth of the call graph (default 1)
    pub depth: Option<u64>,
    /// Direction: "callers", "callees", or "both" (default "both")
    pub direction: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StringsParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Number of results to skip
    pub offset: Option<u64>,
    /// Maximum number of results to return (default 100)
    pub limit: Option<u64>,
    /// Minimum string length (default 4)
    pub min_length: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SymbolsParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Filter by namespace
    pub namespace: Option<String>,
    /// Substring filter for symbol names
    pub filter: Option<String>,
    /// Number of results to skip
    pub offset: Option<u64>,
    /// Maximum number of results to return (default 100)
    pub limit: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DataParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Address to read data from (hex)
    pub address: String,
    /// Number of bytes to read (default 256)
    pub length: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SegmentsParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TypesParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Substring filter for type names
    pub filter: Option<String>,
    /// Filter by category path
    pub category: Option<String>,
    /// Number of results to skip
    pub offset: Option<u64>,
    /// Maximum number of results to return (default 100)
    pub limit: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TypeDetailParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Name of the data type
    pub name: String,
    /// Category path of the data type
    pub category: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ImportsExportsParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Number of results to skip
    pub offset: Option<u64>,
    /// Maximum number of results to return (default 100)
    pub limit: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchBytesParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Hex byte pattern to search for (e.g. "48 89 e5")
    pub bytes: String,
    /// Number of results to skip
    pub offset: Option<u64>,
    /// Maximum number of results to return (default 100)
    pub limit: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RenameParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Address of the function or symbol (hex)
    pub address: Option<String>,
    /// Current name of the function or symbol
    pub old_name: Option<String>,
    /// New name
    pub new_name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CommentParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Address to set comment at (hex)
    pub address: String,
    /// The comment text
    pub comment: String,
    /// Comment type: "eol", "pre", "post", "plate", or "repeatable" (default "eol")
    pub comment_type: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RetypeFunctionParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Address of the function (hex)
    pub address: Option<String>,
    /// Name of the function
    pub name: Option<String>,
    /// C-style function prototype (e.g. "int foo(char *buf, int len)")
    pub prototype: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RetypeDataParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Address to apply data type at (hex)
    pub address: String,
    /// Data type name (e.g. "int", "char *", "MyStruct")
    pub data_type: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateFunctionParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Address to create function at (hex)
    pub address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BookmarkParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
    /// Address to bookmark (hex)
    pub address: String,
    /// Bookmark category
    pub category: String,
    /// Bookmark comment
    pub comment: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SaveParams {
    /// Session ID. If omitted and only one session exists, uses that one.
    pub session_id: Option<String>,
}

impl GhidraMcpServer {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let ghidra = GhidraConfig::detect()?;
        Ok(Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            imports: Arc::new(Mutex::new(HashMap::new())),
            ghidra: Arc::new(ghidra),
            next_session_id: Arc::new(Mutex::new(1)),
            tool_router: Self::tool_router(),
        })
    }

    /// Create a server for testing without a real Ghidra installation.
    #[cfg(test)]
    pub fn new_for_test() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            imports: Arc::new(Mutex::new(HashMap::new())),
            ghidra: Arc::new(GhidraConfig {
                install_dir: PathBuf::from("/nonexistent"),
                launch_sh: PathBuf::from("/nonexistent"),
                java_home: PathBuf::from("/nonexistent"),
                scripts_dir: PathBuf::from("/nonexistent"),
                default_project_dir: PathBuf::from("/tmp/ghidra-mcp-test"),
                default_max_memory: "4G".to_string(),
            }),
            next_session_id: Arc::new(Mutex::new(1)),
            tool_router: Self::tool_router(),
        }
    }

    /// Resolve a session by ID, or auto-resolve if only one session exists.
    async fn resolve_session_id(&self, session_id: Option<&str>) -> Result<String, McpError> {
        let sessions = self.sessions.lock().await;
        match session_id {
            Some(id) => {
                if sessions.contains_key(id) {
                    Ok(id.to_string())
                } else {
                    Err(McpError::invalid_params(
                        format!("No session with id '{}'", id),
                        None,
                    ))
                }
            }
            None => {
                if sessions.len() == 1 {
                    Ok(sessions.keys().next().unwrap().clone())
                } else if sessions.is_empty() {
                    Err(McpError::invalid_params(
                        "No active sessions. Use ghidra_open first.",
                        None,
                    ))
                } else {
                    Err(McpError::invalid_params(
                        "Multiple sessions active. Specify session_id.",
                        None,
                    ))
                }
            }
        }
    }

    /// Send a command to a bridge session and return the text result.
    async fn bridge_command(
        &self,
        session_id: Option<&str>,
        cmd: &str,
        params: serde_json::Value,
    ) -> Result<CallToolResult, McpError> {
        let sid = self.resolve_session_id(session_id).await?;
        let mut sessions = self.sessions.lock().await;
        let session = sessions.get_mut(&sid).ok_or_else(|| {
            McpError::invalid_params(format!("Session '{}' not found", sid), None)
        })?;

        let response = session.bridge.send_command(cmd, params).await.map_err(|e| {
            McpError::internal_error(format!("Bridge communication error: {}", e), None)
        })?;

        if let Some(false) = response.get("ok").and_then(|v| v.as_bool()) {
            let error_msg = response
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown bridge error");
            return Ok(CallToolResult::error(vec![Content::text(error_msg)]));
        }

        // Remove control fields, return the rest as formatted text
        let mut display = response.clone();
        if let Some(obj) = display.as_object_mut() {
            obj.remove("id");
            obj.remove("ok");
        }
        let text = serde_json::to_string_pretty(&display).unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    async fn gen_session_id(&self) -> String {
        let mut id = self.next_session_id.lock().await;
        let session_id = format!("ghidra-{}", *id);
        *id += 1;
        session_id
    }
}

#[tool_router]
impl GhidraMcpServer {
    // -- Project Management Tools --

    /// Import a binary file into a Ghidra project and run initial auto-analysis.
    /// This is a one-time operation that can take minutes to hours for large binaries.
    /// The import runs in the background — use ghidra_import_status to check progress.
    /// The resulting project is saved to disk and can be opened later with ghidra_open.
    #[tool(name = "ghidra_import")]
    async fn ghidra_import(
        &self,
        Parameters(params): Parameters<ImportParams>,
    ) -> Result<CallToolResult, McpError> {
        let binary_path = PathBuf::from(&params.binary_path);
        if !binary_path.exists() {
            return Err(McpError::invalid_params(
                format!("Binary not found: {}", params.binary_path),
                None,
            ));
        }

        let project_dir = params
            .project_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| self.ghidra.default_project_dir.clone());

        let project_name = params.project_name.unwrap_or_else(|| {
            binary_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        });

        let max_memory = params
            .max_memory
            .unwrap_or_else(|| self.ghidra.default_max_memory.clone());

        let analysis_timeout = params.analysis_timeout.unwrap_or(3600);

        // Check if import is already running for this project
        {
            let imports = self.imports.lock().await;
            if let Some(task) = imports.get(&project_name) {
                let status = task.status.lock().await;
                match &*status {
                    ImportStatus::Running => {
                        return Ok(CallToolResult::success(vec![Content::text(format!(
                            "Import already running for project '{}'. Use ghidra_import_status to check progress.",
                            project_name
                        ))]));
                    }
                    _ => {}
                }
            }
        }

        // Create project directory if needed
        tokio::fs::create_dir_all(&project_dir).await.map_err(|e| {
            McpError::internal_error(format!("Failed to create project dir: {}", e), None)
        })?;

        tracing::info!(
            "Importing {} into {}/{}",
            params.binary_path,
            project_dir.display(),
            project_name
        );

        let mut child = crate::ghidra::spawn_import(
            &self.ghidra,
            &project_dir,
            &project_name,
            &binary_path,
            &max_memory,
            analysis_timeout,
            params.processor.as_deref(),
        )
        .map_err(|e| McpError::internal_error(format!("Failed to spawn import: {}", e), None))?;

        // Track the import
        let status = Arc::new(Mutex::new(ImportStatus::Running));
        let task = ImportTask {
            project_dir: project_dir.clone(),
            project_name: project_name.clone(),
            binary_path: params.binary_path.clone(),
            status: status.clone(),
        };
        self.imports.lock().await.insert(project_name.clone(), task);

        // Spawn background task to wait for completion
        let imports = self.imports.clone();
        let pname = project_name.clone();
        let pdir = project_dir.clone();
        tokio::spawn(async move {
            match child.wait().await {
                Ok(exit_status) => {
                    if exit_status.success() {
                        tracing::info!("Import complete for {}", pname);
                        *status.lock().await = ImportStatus::Completed;
                    } else {
                        let msg = format!("Exit code: {:?}", exit_status.code());
                        tracing::error!("Import failed for {}: {}", pname, msg);
                        *status.lock().await = ImportStatus::Failed(msg);
                    }
                }
                Err(e) => {
                    tracing::error!("Import process error for {}: {}", pname, e);
                    *status.lock().await = ImportStatus::Failed(e.to_string());
                }
            }
            // Clean up completed/failed imports after a while
            // (keep them around for status checks)
            let _ = imports;
            let _ = pdir;
        });

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Import started for '{}' in background.\n\
             Binary: {}\n\
             Project: {}/{}\n\
             Max memory: {}\n\
             Analysis timeout: {}s\n\n\
             Use ghidra_import_status to check progress.\n\
             Use ghidra_open to load the program once import is complete.",
            project_name,
            params.binary_path,
            project_dir.display(),
            project_name,
            max_memory,
            analysis_timeout
        ))]))
    }

    /// Check the status of a running or completed import operation.
    #[tool(name = "ghidra_import_status")]
    async fn ghidra_import_status(
        &self,
        Parameters(_params): Parameters<ProjectsParams>,
    ) -> Result<CallToolResult, McpError> {
        let imports = self.imports.lock().await;

        if imports.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                "No import operations tracked.",
            )]));
        }

        let mut text = String::new();
        for (name, task) in imports.iter() {
            let status = task.status.lock().await;
            let status_str = match &*status {
                ImportStatus::Running => "RUNNING".to_string(),
                ImportStatus::Completed => "COMPLETED".to_string(),
                ImportStatus::Failed(msg) => format!("FAILED: {}", msg),
            };
            text.push_str(&format!(
                "- {} : {} (binary: {}, project: {}/{})\n",
                name,
                status_str,
                task.binary_path,
                task.project_dir.display(),
                task.project_name
            ));
        }

        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    /// Open an already-analyzed program from a Ghidra project, starting a persistent
    /// bridge session. This loads the full program database into memory. Once open,
    /// all query and mutation tools become fast. Returns a session_id.
    #[tool(name = "ghidra_open")]
    async fn ghidra_open(
        &self,
        Parameters(params): Parameters<OpenParams>,
    ) -> Result<CallToolResult, McpError> {
        let project_dir = PathBuf::from(&params.project_dir);
        if !project_dir.exists() {
            return Err(McpError::invalid_params(
                format!("Project directory not found: {}", params.project_dir),
                None,
            ));
        }

        let max_memory = params
            .max_memory
            .unwrap_or_else(|| self.ghidra.default_max_memory.clone());

        let port = crate::ghidra::find_free_port().map_err(|e| {
            McpError::internal_error(format!("Failed to find free port: {}", e), None)
        })?;

        tracing::info!(
            "Opening {}/{} on port {}",
            params.project_dir,
            params.project_name,
            port
        );

        let child = crate::ghidra::spawn_bridge(
            &self.ghidra,
            &project_dir,
            &params.project_name,
            params.program_name.as_deref(),
            port,
            &max_memory,
        )
        .map_err(|e| McpError::internal_error(format!("Failed to spawn bridge: {}", e), None))?;

        // Wait for the bridge to become available (retry TCP connect)
        let bridge = Bridge::connect_with_retry(port, std::time::Duration::from_secs(300))
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to connect to bridge: {}", e), None)
            })?;

        let session_id = self.gen_session_id().await;
        let program_name = params.program_name.unwrap_or_default();

        let session = Session {
            id: session_id.clone(),
            project_dir,
            project_name: params.project_name.clone(),
            program_name: program_name.clone(),
            bridge,
            child,
        };

        self.sessions.lock().await.insert(session_id.clone(), session);

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Session '{}' opened for project '{}'.\nAll query and mutation tools are now available.",
            session_id, params.project_name
        ))]))
    }

    /// List active Ghidra bridge sessions showing which programs are loaded.
    #[tool(name = "ghidra_sessions")]
    async fn ghidra_sessions(&self) -> Result<CallToolResult, McpError> {
        let sessions = self.sessions.lock().await;
        if sessions.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                "No active sessions.",
            )]));
        }
        let mut text = String::new();
        for (id, session) in sessions.iter() {
            text.push_str(&format!(
                "- {} : {}/{} (program: {})\n",
                id, session.project_dir.display(), session.project_name, session.program_name
            ));
        }
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    /// Close a Ghidra bridge session, saving changes and freeing memory.
    #[tool(name = "ghidra_close")]
    async fn ghidra_close(
        &self,
        Parameters(params): Parameters<SessionIdParam>,
    ) -> Result<CallToolResult, McpError> {
        let sid = self.resolve_session_id(params.session_id.as_deref()).await?;
        let mut sessions = self.sessions.lock().await;
        if let Some(mut session) = sessions.remove(&sid) {
            // Try to save and shut down gracefully
            let _ = session
                .bridge
                .send_command("save", serde_json::json!({}))
                .await;
            let _ = session
                .bridge
                .send_command("shutdown", serde_json::json!({}))
                .await;
            let _ = session.child.kill().await;
            Ok(CallToolResult::success(vec![Content::text(format!(
                "Session '{}' closed.",
                sid
            ))]))
        } else {
            Err(McpError::invalid_params(
                format!("Session '{}' not found", sid),
                None,
            ))
        }
    }

    /// List known Ghidra projects on disk that can be opened.
    #[tool(name = "ghidra_projects")]
    async fn ghidra_projects(
        &self,
        Parameters(params): Parameters<ProjectsParams>,
    ) -> Result<CallToolResult, McpError> {
        let dir = params
            .project_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| self.ghidra.default_project_dir.clone());

        if !dir.exists() {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "Project directory does not exist: {}",
                dir.display()
            ))]));
        }

        let mut projects = Vec::new();
        let mut entries = tokio::fs::read_dir(&dir).await.map_err(|e| {
            McpError::internal_error(format!("Failed to read directory: {}", e), None)
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            McpError::internal_error(format!("Failed to read entry: {}", e), None)
        })? {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "gpr") {
                projects.push(
                    path.file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                );
            }
        }

        if projects.is_empty() {
            Ok(CallToolResult::success(vec![Content::text(format!(
                "No Ghidra projects found in {}",
                dir.display()
            ))]))
        } else {
            let text = projects
                .iter()
                .map(|p| format!("- {} (in {})", p, dir.display()))
                .collect::<Vec<_>>()
                .join("\n");
            Ok(CallToolResult::success(vec![Content::text(text)]))
        }
    }

    // -- Query Tools --

    /// Get program metadata: name, architecture, base address, function count, etc.
    #[tool(name = "ghidra_info")]
    async fn ghidra_info(
        &self,
        Parameters(params): Parameters<InfoParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(params.session_id.as_deref(), "info", serde_json::json!({}))
            .await
    }

    /// List and search functions with pagination. Essential for large binaries.
    #[tool(name = "ghidra_functions")]
    async fn ghidra_functions(
        &self,
        Parameters(params): Parameters<FunctionsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "list_functions",
            serde_json::json!({
                "filter": params.filter,
                "offset": params.offset.unwrap_or(0),
                "limit": params.limit.unwrap_or(100),
            }),
        )
        .await
    }

    /// Decompile a function to C pseudocode. Specify by address or name.
    #[tool(name = "ghidra_decompile")]
    async fn ghidra_decompile(
        &self,
        Parameters(params): Parameters<DecompileParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "decompile",
            serde_json::json!({
                "address": params.address,
                "name": params.name,
                "timeout": params.timeout.unwrap_or(60),
            }),
        )
        .await
    }

    /// Get disassembly at an address.
    #[tool(name = "ghidra_disassemble")]
    async fn ghidra_disassemble(
        &self,
        Parameters(params): Parameters<DisassembleParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "disassemble",
            serde_json::json!({
                "address": params.address,
                "count": params.count.unwrap_or(50),
            }),
        )
        .await
    }

    /// Get cross-references to or from an address.
    #[tool(name = "ghidra_xrefs")]
    async fn ghidra_xrefs(
        &self,
        Parameters(params): Parameters<XrefsParams>,
    ) -> Result<CallToolResult, McpError> {
        let direction = params.direction.as_deref().unwrap_or("to");
        let cmd = match direction {
            "from" => "get_xrefs_from",
            "both" => "get_xrefs_both",
            _ => "get_xrefs_to",
        };
        self.bridge_command(
            params.session_id.as_deref(),
            cmd,
            serde_json::json!({
                "address": params.address,
            }),
        )
        .await
    }

    /// Get call graph around a function.
    #[tool(name = "ghidra_callgraph")]
    async fn ghidra_callgraph(
        &self,
        Parameters(params): Parameters<CallgraphParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "get_callgraph",
            serde_json::json!({
                "address": params.address,
                "name": params.name,
                "depth": params.depth.unwrap_or(1),
                "direction": params.direction.as_deref().unwrap_or("both"),
            }),
        )
        .await
    }

    /// List defined strings in the program.
    #[tool(name = "ghidra_strings")]
    async fn ghidra_strings(
        &self,
        Parameters(params): Parameters<StringsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "list_strings",
            serde_json::json!({
                "offset": params.offset.unwrap_or(0),
                "limit": params.limit.unwrap_or(100),
                "min_length": params.min_length.unwrap_or(4),
            }),
        )
        .await
    }

    /// List and search symbols.
    #[tool(name = "ghidra_symbols")]
    async fn ghidra_symbols(
        &self,
        Parameters(params): Parameters<SymbolsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "list_symbols",
            serde_json::json!({
                "namespace": params.namespace,
                "filter": params.filter,
                "offset": params.offset.unwrap_or(0),
                "limit": params.limit.unwrap_or(100),
            }),
        )
        .await
    }

    /// Read data or bytes at an address.
    #[tool(name = "ghidra_data")]
    async fn ghidra_data(
        &self,
        Parameters(params): Parameters<DataParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "get_data_at",
            serde_json::json!({
                "address": params.address,
                "length": params.length.unwrap_or(256),
            }),
        )
        .await
    }

    /// List memory segments/blocks.
    #[tool(name = "ghidra_segments")]
    async fn ghidra_segments(
        &self,
        Parameters(params): Parameters<SegmentsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "list_segments",
            serde_json::json!({}),
        )
        .await
    }

    /// List and search data types.
    #[tool(name = "ghidra_types")]
    async fn ghidra_types(
        &self,
        Parameters(params): Parameters<TypesParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "get_types",
            serde_json::json!({
                "filter": params.filter,
                "category": params.category,
                "offset": params.offset.unwrap_or(0),
                "limit": params.limit.unwrap_or(100),
            }),
        )
        .await
    }

    /// Get full definition of a struct, enum, or other data type.
    #[tool(name = "ghidra_type_detail")]
    async fn ghidra_type_detail(
        &self,
        Parameters(params): Parameters<TypeDetailParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "get_type_detail",
            serde_json::json!({
                "name": params.name,
                "category": params.category,
            }),
        )
        .await
    }

    /// List imported symbols (external references).
    #[tool(name = "ghidra_imports")]
    async fn ghidra_imports(
        &self,
        Parameters(params): Parameters<ImportsExportsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "list_imports",
            serde_json::json!({
                "offset": params.offset.unwrap_or(0),
                "limit": params.limit.unwrap_or(100),
            }),
        )
        .await
    }

    /// List exported symbols.
    #[tool(name = "ghidra_exports")]
    async fn ghidra_exports(
        &self,
        Parameters(params): Parameters<ImportsExportsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "list_exports",
            serde_json::json!({
                "offset": params.offset.unwrap_or(0),
                "limit": params.limit.unwrap_or(100),
            }),
        )
        .await
    }

    /// Search memory for byte patterns.
    #[tool(name = "ghidra_search_bytes")]
    async fn ghidra_search_bytes(
        &self,
        Parameters(params): Parameters<SearchBytesParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "search_memory",
            serde_json::json!({
                "bytes": params.bytes,
                "offset": params.offset.unwrap_or(0),
                "limit": params.limit.unwrap_or(100),
            }),
        )
        .await
    }

    // -- Mutation Tools --

    /// Rename a function or symbol.
    #[tool(name = "ghidra_rename")]
    async fn ghidra_rename(
        &self,
        Parameters(params): Parameters<RenameParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "rename_function",
            serde_json::json!({
                "address": params.address,
                "old_name": params.old_name,
                "new_name": params.new_name,
            }),
        )
        .await
    }

    /// Set a comment at an address.
    #[tool(name = "ghidra_comment")]
    async fn ghidra_comment(
        &self,
        Parameters(params): Parameters<CommentParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "set_comment",
            serde_json::json!({
                "address": params.address,
                "comment": params.comment,
                "type": params.comment_type.as_deref().unwrap_or("eol"),
            }),
        )
        .await
    }

    /// Change a function's signature using a C-style prototype.
    #[tool(name = "ghidra_retype_function")]
    async fn ghidra_retype_function(
        &self,
        Parameters(params): Parameters<RetypeFunctionParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "set_function_prototype",
            serde_json::json!({
                "address": params.address,
                "name": params.name,
                "prototype": params.prototype,
            }),
        )
        .await
    }

    /// Apply a data type at an address.
    #[tool(name = "ghidra_retype_data")]
    async fn ghidra_retype_data(
        &self,
        Parameters(params): Parameters<RetypeDataParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "set_data_type",
            serde_json::json!({
                "address": params.address,
                "data_type": params.data_type,
            }),
        )
        .await
    }

    /// Create a function at an address where Ghidra didn't auto-detect one.
    #[tool(name = "ghidra_create_function")]
    async fn ghidra_create_function(
        &self,
        Parameters(params): Parameters<CreateFunctionParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "create_function",
            serde_json::json!({
                "address": params.address,
            }),
        )
        .await
    }

    /// Create a bookmark at an address for later reference.
    #[tool(name = "ghidra_bookmark")]
    async fn ghidra_bookmark(
        &self,
        Parameters(params): Parameters<BookmarkParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(
            params.session_id.as_deref(),
            "create_bookmark",
            serde_json::json!({
                "address": params.address,
                "category": params.category,
                "comment": params.comment,
            }),
        )
        .await
    }

    /// Save all changes in a session to the Ghidra project database.
    #[tool(name = "ghidra_save")]
    async fn ghidra_save(
        &self,
        Parameters(params): Parameters<SaveParams>,
    ) -> Result<CallToolResult, McpError> {
        self.bridge_command(params.session_id.as_deref(), "save", serde_json::json!({}))
            .await
    }
}

#[tool_handler]
impl ServerHandler for GhidraMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::default(),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation {
                name: "ghidra-mcp".to_string(),
                title: Some("Ghidra MCP Server".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: Some("AI-controlled Ghidra reverse engineering".to_string()),
                icons: None,
                website_url: None,
            },
            instructions: Some(INSTRUCTIONS.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to insert a dummy session (we can't create a real Bridge for unit tests,
    // so we test resolve_session_id by directly manipulating the sessions map).
    // We use a mock bridge by connecting to a local echo server.
    async fn insert_dummy_session(server: &GhidraMcpServer, id: &str, port: u16) {
        // Start a tiny echo server so Bridge::connect doesn't fail
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, write) = stream.into_split();
            let mut reader = tokio::io::BufReader::new(read);
            let mut writer = tokio::io::BufWriter::new(write);
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let _ = writer.write_all(b"{\"id\":0,\"ok\":true}\n").await;
                        let _ = writer.flush().await;
                    }
                }
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let bridge = Bridge::from_stream(stream);

        // We need a dummy child process — use `sleep` as a harmless long-running process
        let child = tokio::process::Command::new("sleep")
            .arg("3600")
            .spawn()
            .unwrap();

        let session = Session {
            id: id.to_string(),
            project_dir: PathBuf::from("/tmp/test"),
            project_name: "TestProject".to_string(),
            program_name: "test_binary".to_string(),
            bridge,
            child,
        };

        server
            .sessions
            .lock()
            .await
            .insert(id.to_string(), session);
    }

    // Clean up child processes spawned during tests
    async fn cleanup_sessions(server: &GhidraMcpServer) {
        let mut sessions = server.sessions.lock().await;
        for (_, session) in sessions.iter_mut() {
            let _ = session.child.kill().await;
        }
        sessions.clear();
    }

    #[tokio::test]
    async fn resolve_session_no_sessions() {
        let server = GhidraMcpServer::new_for_test();
        let result = server.resolve_session_id(None).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.message.contains("No active sessions"),
            "Expected 'No active sessions', got: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn resolve_session_auto_single() {
        let server = GhidraMcpServer::new_for_test();
        let port = crate::ghidra::find_free_port().unwrap();
        insert_dummy_session(&server, "ghidra-1", port).await;

        let result = server.resolve_session_id(None).await;
        assert_eq!(result.unwrap(), "ghidra-1");

        cleanup_sessions(&server).await;
    }

    #[tokio::test]
    async fn resolve_session_explicit_id() {
        let server = GhidraMcpServer::new_for_test();
        let port = crate::ghidra::find_free_port().unwrap();
        insert_dummy_session(&server, "ghidra-1", port).await;

        let result = server.resolve_session_id(Some("ghidra-1")).await;
        assert_eq!(result.unwrap(), "ghidra-1");

        cleanup_sessions(&server).await;
    }

    #[tokio::test]
    async fn resolve_session_wrong_id() {
        let server = GhidraMcpServer::new_for_test();
        let port = crate::ghidra::find_free_port().unwrap();
        insert_dummy_session(&server, "ghidra-1", port).await;

        let result = server.resolve_session_id(Some("ghidra-999")).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("No session with id"));

        cleanup_sessions(&server).await;
    }

    #[tokio::test]
    async fn resolve_session_ambiguous() {
        let server = GhidraMcpServer::new_for_test();
        let port1 = crate::ghidra::find_free_port().unwrap();
        let port2 = crate::ghidra::find_free_port().unwrap();
        insert_dummy_session(&server, "ghidra-1", port1).await;
        insert_dummy_session(&server, "ghidra-2", port2).await;

        let result = server.resolve_session_id(None).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message
            .contains("Multiple sessions active"));

        cleanup_sessions(&server).await;
    }

    #[tokio::test]
    async fn resolve_session_explicit_with_multiple() {
        let server = GhidraMcpServer::new_for_test();
        let port1 = crate::ghidra::find_free_port().unwrap();
        let port2 = crate::ghidra::find_free_port().unwrap();
        insert_dummy_session(&server, "ghidra-1", port1).await;
        insert_dummy_session(&server, "ghidra-2", port2).await;

        let result = server.resolve_session_id(Some("ghidra-2")).await;
        assert_eq!(result.unwrap(), "ghidra-2");

        cleanup_sessions(&server).await;
    }

    #[tokio::test]
    async fn gen_session_id_increments() {
        let server = GhidraMcpServer::new_for_test();
        let id1 = server.gen_session_id().await;
        let id2 = server.gen_session_id().await;
        let id3 = server.gen_session_id().await;

        assert_eq!(id1, "ghidra-1");
        assert_eq!(id2, "ghidra-2");
        assert_eq!(id3, "ghidra-3");
    }

    #[tokio::test]
    async fn bridge_command_no_session_returns_error() {
        let server = GhidraMcpServer::new_for_test();
        let result = server
            .bridge_command(None, "info", serde_json::json!({}))
            .await;
        assert!(result.is_err());
    }
}
