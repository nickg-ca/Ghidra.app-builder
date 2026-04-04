use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// TCP client to a running McpBridge.java instance.
pub struct Bridge {
    reader: BufReader<OwnedReadHalf>,
    writer: BufWriter<OwnedWriteHalf>,
    next_id: u64,
}

impl Bridge {
    /// Create a Bridge from an already-connected TcpStream.
    pub fn from_stream(stream: TcpStream) -> Self {
        let (read, write) = stream.into_split();
        Bridge {
            reader: BufReader::new(read),
            writer: BufWriter::new(write),
            next_id: 1,
        }
    }

    /// Connect to a bridge on localhost with retries (for waiting during Ghidra startup).
    pub async fn connect_with_retry(
        port: u16,
        timeout: Duration,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut last_err = None;

        while tokio::time::Instant::now() < deadline {
            match TcpStream::connect(("127.0.0.1", port)).await {
                Ok(stream) => {
                    let (read, write) = stream.into_split();
                    let mut bridge = Bridge {
                        reader: BufReader::new(read),
                        writer: BufWriter::new(write),
                        next_id: 1,
                    };
                    // Verify the bridge is responsive
                    match bridge.send_command("ping", serde_json::json!({})).await {
                        Ok(_) => {
                            tracing::info!("Connected to bridge on port {}", port);
                            return Ok(bridge);
                        }
                        Err(e) => {
                            tracing::debug!("Bridge ping failed: {}", e);
                            last_err = Some(e);
                        }
                    }
                }
                Err(e) => {
                    last_err = Some(Box::new(e));
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        Err(last_err.unwrap_or_else(|| "Timeout waiting for bridge".into()))
    }

    /// Send a command to the bridge and return the JSON response.
    pub async fn send_command(
        &mut self,
        cmd: &str,
        mut params: Value,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let id = self.next_id;
        self.next_id += 1;

        // Build the command object
        if let Some(obj) = params.as_object_mut() {
            obj.insert("id".to_string(), Value::Number(id.into()));
            obj.insert("cmd".to_string(), Value::String(cmd.to_string()));
        } else {
            params = serde_json::json!({
                "id": id,
                "cmd": cmd,
            });
        }

        // Write command as a single line
        let line = serde_json::to_string(&params)?;
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;

        // Read response line with timeout (longer for expensive operations)
        let timeout_secs = match cmd {
            "decompile" => 300,
            "search_memory" | "list_strings" | "list_symbols" | "list_functions" | "get_callgraph" => 120,
            _ => 60,
        };
        let mut response_line = String::new();
        let read_result = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            self.reader.read_line(&mut response_line),
        )
        .await;

        match read_result {
            Ok(Ok(0)) => Err("Bridge connection closed".into()),
            Ok(Ok(_)) => {
                let response: Value = serde_json::from_str(response_line.trim())?;
                Ok(response)
            }
            Ok(Err(e)) => Err(Box::new(e)),
            Err(_) => Err("Bridge command timed out".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
    use tokio::net::TcpListener;

    /// Helper: start a mock bridge server that accepts connections in a loop,
    /// reads one command per connection, and replies with a canned response.
    async fn mock_bridge_server(
        port: u16,
        response_fn: impl Fn(String) -> String + Send + 'static,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            // Accept multiple connections (handles test parallelism races)
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                let (read, write) = stream.into_split();
                let mut reader = TokioBufReader::new(read);
                let mut writer = tokio::io::BufWriter::new(write);

                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                    let response = response_fn(line);
                    let _ = writer.write_all(response.as_bytes()).await;
                    let _ = writer.write_all(b"\n").await;
                    let _ = writer.flush().await;
                }
            }
        });
        // Give the listener a moment to bind
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    /// Helper: start a mock that echoes back the received command with ok:true
    async fn mock_bridge_echo(port: u16) {
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, write) = stream.into_split();
            let mut reader = TokioBufReader::new(read);
            let mut writer = tokio::io::BufWriter::new(write);

            loop {
                let mut line = String::new();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let req: Value = serde_json::from_str(line.trim()).unwrap_or_default();
                        let id = req.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                        let resp = serde_json::json!({"id": id, "ok": true, "echo": req});
                        writer
                            .write_all(serde_json::to_string(&resp).unwrap().as_bytes())
                            .await
                            .unwrap();
                        writer.write_all(b"\n").await.unwrap();
                        writer.flush().await.unwrap();
                    }
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn bridge_sends_correct_json_envelope() {
        let port = crate::ghidra::find_free_port().unwrap();
        mock_bridge_echo(port).await;

        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut bridge = Bridge::from_stream(stream);

        let resp = bridge
            .send_command("test_cmd", serde_json::json!({"foo": "bar"}))
            .await
            .unwrap();

        // The echo server returns what we sent as "echo"
        let echo = &resp["echo"];
        assert_eq!(echo["cmd"], "test_cmd");
        assert_eq!(echo["id"], 1);
        assert_eq!(echo["foo"], "bar");
    }

    #[tokio::test]
    async fn bridge_id_increments() {
        let port = crate::ghidra::find_free_port().unwrap();
        mock_bridge_echo(port).await;

        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut bridge = Bridge::from_stream(stream);

        let r1 = bridge
            .send_command("cmd1", serde_json::json!({}))
            .await
            .unwrap();
        let r2 = bridge
            .send_command("cmd2", serde_json::json!({}))
            .await
            .unwrap();

        assert_eq!(r1["echo"]["id"], 1);
        assert_eq!(r2["echo"]["id"], 2);
    }

    #[tokio::test]
    async fn bridge_parses_ok_response() {
        let port = crate::ghidra::find_free_port().unwrap();
        mock_bridge_server(port, |_| {
            r#"{"id":1,"ok":true,"data":"hello"}"#.to_string()
        })
        .await;

        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut bridge = Bridge::from_stream(stream);

        let resp = bridge
            .send_command("ping", serde_json::json!({}))
            .await
            .unwrap();

        assert_eq!(resp["ok"], true);
        assert_eq!(resp["data"], "hello");
    }

    #[tokio::test]
    async fn bridge_parses_error_response() {
        let port = crate::ghidra::find_free_port().unwrap();
        mock_bridge_server(port, |_| {
            r#"{"id":1,"ok":false,"error":"something broke"}"#.to_string()
        })
        .await;

        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut bridge = Bridge::from_stream(stream);

        let resp = bridge
            .send_command("bad", serde_json::json!({}))
            .await
            .unwrap();

        assert_eq!(resp["ok"], false);
        assert_eq!(resp["error"], "something broke");
    }

    #[tokio::test]
    async fn bridge_handles_connection_closed() {
        let port = crate::ghidra::find_free_port().unwrap();

        // Server that accepts connection then immediately closes it
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream); // Close immediately
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut bridge = Bridge::from_stream(stream);

        let result = bridge.send_command("ping", serde_json::json!({})).await;
        assert!(result.is_err(), "Expected error on closed connection");
    }

    #[tokio::test]
    async fn bridge_connect_with_retry_fails_on_no_server() {
        let port = crate::ghidra::find_free_port().unwrap();
        // No server running on this port
        let result =
            Bridge::connect_with_retry(port, Duration::from_secs(3)).await;
        assert!(result.is_err(), "Expected error when no server running");
    }

    #[tokio::test]
    async fn bridge_connect_with_retry_succeeds_when_server_starts_later() {
        let port = crate::ghidra::find_free_port().unwrap();

        // Start a mock server after a short delay
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            mock_bridge_echo(port).await;
        });

        // Try to connect with retries (should succeed after ~1s)
        let result =
            Bridge::connect_with_retry(port, Duration::from_secs(10)).await;
        assert!(result.is_ok(), "Expected successful connection after retry");
    }
}
