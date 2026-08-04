//! JSON-RPC over stdin and stdout.
//!
//! The MCP server is a thin client. It speaks the protocol to an editor and
//! forwards the actual work here, which keeps detection in one place rather than
//! reimplemented in a second language.
//!
//! One rule governs everything below: a malformed request is answered, not
//! fatal. A bridge that exits on bad input takes the editor session down with it,
//! and the user sees a dead tool rather than an error they can act on.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::scan;

/// Error codes from the JSON-RPC specification, plus one of our own.
mod code {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    /// The request was well formed but the scan could not run.
    pub const SCAN_FAILED: i32 = -32000;
}

#[derive(Debug, Deserialize)]
struct Request {
    #[serde(default)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct Response {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl Response {
    fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    fn err(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

/// Reads requests until the input ends.
///
/// One request per line. Line delimited framing is enough here because both ends
/// are ours and the payloads are small; a length prefixed frame would buy
/// nothing and cost debuggability.
pub fn serve(
    input: impl BufRead,
    mut output: impl Write,
    rules_root: PathBuf,
    tool_version: &str,
    now: impl Fn() -> String,
) -> std::io::Result<()> {
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = handle(&line, &rules_root, tool_version, &now);
        // A notification carries no id and expects no answer.
        if let Some(response) = response {
            let text = serde_json::to_string(&response)
                .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"response could not be encoded"}}"#.to_owned());
            writeln!(output, "{text}")?;
            output.flush()?;
        }
    }
    Ok(())
}

fn handle(
    line: &str,
    rules_root: &Path,
    tool_version: &str,
    now: &impl Fn() -> String,
) -> Option<Response> {
    let request: Request = match serde_json::from_str(line) {
        Ok(request) => request,
        Err(e) => {
            return Some(Response::err(
                Value::Null,
                code::PARSE_ERROR,
                format!("request is not valid JSON: {e}"),
            ))
        }
    };

    // A request without an id is a notification: the specification says nothing
    // goes back, even when the method is unknown. Returning None here is what
    // keeps the caller silent.
    let reply_id = request.id.clone()?;

    if request.jsonrpc != "2.0" {
        return Some(Response::err(
            reply_id,
            code::INVALID_REQUEST,
            "jsonrpc must be \"2.0\"",
        ));
    }

    match request.method.as_str() {
        "scan" => Some(scan_method(
            reply_id,
            &request.params,
            rules_root,
            tool_version,
            now,
        )),
        "ping" => Some(Response::ok(reply_id, json!({ "ok": true }))),
        other => Some(Response::err(
            reply_id,
            code::METHOD_NOT_FOUND,
            format!("unknown method {other:?}"),
        )),
    }
}

fn scan_method(
    id: Value,
    params: &Value,
    rules_root: &Path,
    tool_version: &str,
    now: &impl Fn() -> String,
) -> Response {
    let Some(path) = params.get("path").and_then(Value::as_str) else {
        return Response::err(id, code::INVALID_PARAMS, "params.path is required");
    };
    let project_root = PathBuf::from(path);
    if !project_root.is_dir() {
        return Response::err(id, code::SCAN_FAILED, format!("{path} is not a directory"));
    }

    let outcome = scan::run(scan::ScanRequest {
        project_root: &project_root,
        rules_root,
        tool_version,
        generated_at: now(),
    });

    match serde_json::to_value(&outcome.report) {
        Ok(report) => Response::ok(id, report),
        Err(e) => Response::err(
            id,
            code::SCAN_FAILED,
            format!("report could not be encoded: {e}"),
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn call(request: &str) -> String {
        let mut out = Vec::new();
        serve(
            Cursor::new(request),
            &mut out,
            PathBuf::from("rules"),
            "0.0.0-test",
            || "2026-08-04T09:00:00Z".to_owned(),
        )
        .unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn ping_is_answered() {
        let out = call("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
        assert!(out.contains("\"ok\":true"), "{out}");
    }

    #[test]
    fn malformed_json_gets_an_error_and_the_loop_survives() {
        // The property that matters: the process answers and keeps going, because
        // exiting here would take the editor session down with it.
        let out = call("not json\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n");
        assert!(out.contains("-32700"), "{out}");
        assert!(
            out.contains("\"ok\":true"),
            "second request went unanswered: {out}"
        );
    }

    #[test]
    fn unknown_method_is_reported_by_name() {
        let out = call("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"teleport\"}\n");
        assert!(out.contains("-32601"), "{out}");
        assert!(out.contains("teleport"), "{out}");
    }

    #[test]
    fn a_notification_receives_no_reply() {
        let out = call("{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n");
        assert!(out.is_empty(), "expected silence, got {out}");
    }

    #[test]
    fn wrong_protocol_version_is_rejected() {
        let out = call("{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"ping\"}\n");
        assert!(out.contains("-32600"), "{out}");
    }

    #[test]
    fn scan_without_a_path_says_which_parameter_is_missing() {
        let out = call("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"scan\",\"params\":{}}\n");
        assert!(out.contains("-32602"), "{out}");
        assert!(out.contains("params.path"), "{out}");
    }

    #[test]
    fn scanning_a_missing_directory_is_an_error_not_a_crash() {
        let out = call(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"scan\",\"params\":{\"path\":\"/nonexistent-xyz\"}}\n",
        );
        assert!(out.contains("-32000"), "{out}");
    }

    #[test]
    fn blank_lines_are_ignored() {
        let out = call("\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
        assert_eq!(out.lines().count(), 1, "{out}");
    }
}
