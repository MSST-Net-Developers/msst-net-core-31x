//! Observability — Prometheus metrics, structured logging, and monitoring.
//!
//! This module provides:
//! - **Metrics registry** — atomic counters and gauges for all key subsystems
//! - **Prometheus exporter** — HTTP `/metrics` endpoint for scraping
//! - **Metrics server** — lightweight HTTP server on a dedicated port
//!
//! ## Metrics exposed
//!
//! | Metric | Type | Labels | Description |
//! |--------|------|--------|-------------|
//! | `msst_core_peers_total` | gauge | — | Number of known peers |
//! | `msst_core_room_peers_total` | gauge | — | Peers in current room |
//! | `msst_core_acl_rules_total` | gauge | — | Active ACL rules |
//! | `msst_core_packets_received_total` | counter | `type` | Inbound packets |
//! | `msst_core_packets_sent_total` | counter | `type` | Outbound packets |
//! | `msst_core_acl_decisions_total` | counter | `decision` | ACL decisions |
//! | `msst_core_wg_sessions_total` | gauge | — | Active WG sessions |
//! | `msst_core_wg_handshakes_total` | counter | `result` | WG handshake outcomes |
//! | `msst_core_path_modes` | gauge | `mode` | Peers per path mode |
//! | `msst_core_ipc_connections` | gauge | — | Active IPC clients |
//! | `msst_core_coordinator_connected` | gauge | — | 1 if WS connected |
//! | `msst_core_generation` | gauge | — | Current generation counter |
//! | `msst_core_uptime_seconds` | gauge | — | Process uptime |

pub mod metrics;

use metrics::CoreMetrics;
use prometheus::{Encoder, TextEncoder};
use std::sync::Arc;
use tracing::{error, info};

/// Start the Prometheus metrics HTTP server.
///
/// Binds to `port` and serves `/metrics` in Prometheus text format.
/// Also serves `/healthz` for liveness probes.
pub async fn start_metrics_server(metrics: Arc<CoreMetrics>, port: u16) {
    let addr = format!("127.0.0.1:{}", port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("metrics server: cannot bind {}: {}", addr, e);
            return;
        }
    };

    info!("metrics server listening on http://{}/metrics", addr);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                error!("metrics server: accept error: {}", e);
                continue;
            }
        };

        let metrics = metrics.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (reader, mut writer) = tokio::io::split(stream);
            let mut lines = BufReader::new(reader).lines();

            // Read the first line of the HTTP request.
            let first_line = match lines.next_line().await {
                Ok(Some(line)) => line,
                _ => return,
            };

            // Drain remaining headers (we don't need them).
            while let Ok(Some(line)) = lines.next_line().await {
                if line.is_empty() { break; }
            }

            let (status, body) = if first_line.starts_with("GET /metrics") {
                let encoder = TextEncoder::new();
                let metric_families = metrics.registry.gather();
                let mut buffer = Vec::new();
                encoder.encode(&metric_families, &mut buffer).unwrap();
                ("200 OK", buffer)
            } else if first_line.starts_with("GET /healthz") {
                ("200 OK", b"ok\n".to_vec())
            } else {
                ("404 Not Found", b"Not Found\n".to_vec())
            };

            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                status, body.len()
            );

            let _ = writer.write_all(response.as_bytes()).await;
            let _ = writer.write_all(&body).await;
            let _ = writer.flush().await;
        });
    }
}