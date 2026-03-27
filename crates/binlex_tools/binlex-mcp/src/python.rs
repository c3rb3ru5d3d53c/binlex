use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info};

use crate::error::DynError;

const PYTHON_WRAPPER: &str = r#"
import contextlib
import io
import json
import os
import sys
import traceback

code = os.environ.get("BINLEX_MCP_CODE", "")
path = os.environ.get("BINLEX_MCP_PATH")
paths = json.loads(os.environ.get("BINLEX_MCP_PATHS", "[]"))
args = json.loads(os.environ.get("BINLEX_MCP_ARGS", "null"))

stdout_buffer = io.StringIO()
stderr_buffer = io.StringIO()
result = None

def emit(value):
    global result
    result = value

namespace = {
    "__name__": "__main__",
    "path": path,
    "paths": paths,
    "args": args,
    "emit": emit,
    "result": None,
}

exit_code = 0
with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(stderr_buffer):
    try:
        exec(code, namespace, namespace)
    except Exception:
        traceback.print_exc()
        exit_code = 1

if namespace.get("result") is not None:
    result = namespace["result"]

payload = {
    "stdout": stdout_buffer.getvalue(),
    "stderr": stderr_buffer.getvalue(),
    "result": result,
}

def fallback(value):
    return repr(value)

sys.__stdout__.write(json.dumps(payload, default=fallback))
sys.exit(exit_code)
"#;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PythonRequest {
    pub code: String,
    pub path: Option<String>,
    #[schemars(description = "Optional set of file paths available to the script.")]
    pub paths: Option<Vec<String>>,
    #[schemars(description = "Optional JSON arguments injected into the script as args.")]
    pub args: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PythonResponse {
    pub stdout: String,
    pub stderr: String,
    pub result: Option<Value>,
    pub exit_code: i32,
}

pub fn execute_python(command: &str, request: PythonRequest) -> Result<PythonResponse, DynError> {
    info!(
        python = command,
        has_path = request.path.is_some(),
        path_count = request.paths.as_ref().map_or(0, Vec::len),
        code_len = request.code.len(),
        code = %request.code,
        "executing python tool"
    );
    debug!(
        has_path = request.path.is_some(),
        path_count = request.paths.as_ref().map_or(0, Vec::len),
        code_len = request.code.len(),
        "python execution request"
    );

    let output = Command::new(command)
        .arg("-c")
        .arg(PYTHON_WRAPPER)
        .env("BINLEX_MCP_CODE", request.code)
        .env("BINLEX_MCP_PATH", request.path.unwrap_or_default())
        .env(
            "BINLEX_MCP_PATHS",
            serde_json::to_string(&request.paths.unwrap_or_default())?,
        )
        .env(
            "BINLEX_MCP_ARGS",
            serde_json::to_string(&request.args.unwrap_or(Value::Null))?,
        )
        .output()?;

    let stdout = String::from_utf8(output.stdout)?;
    let response: PythonResponse = serde_json::from_str(&stdout).unwrap_or(PythonResponse {
        stdout,
        stderr: String::from_utf8(output.stderr)?,
        result: None,
        exit_code: output.status.code().unwrap_or(1),
    });

    Ok(PythonResponse {
        exit_code: output.status.code().unwrap_or(1),
        ..response
    })
}

pub fn verify_python_environment(command: &str) -> Result<(), DynError> {
    let output = Command::new(command)
        .arg("-c")
        .arg("import binlex")
        .output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "unknown error".to_string()
    };

    Err(format!(
        "python environment check failed for '{}': unable to import binlex ({})",
        command, detail
    )
    .into())
}
