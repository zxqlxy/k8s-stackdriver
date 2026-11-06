//! Lock-free Prometheus metrics registry and `:8080/metrics` HTTP server preserving GKE LOrIS SLO
//! and `prometheus-to-sd` whitelisted metric names.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// 20 exponential latency buckets (`start = 2.0`, `factor = 1.5`, `count = 20`) matching Go
/// `sd_sink`.
const LATENCY_BUCKET_COUNT: usize = 20;

fn compute_latency_bounds() -> [f64; LATENCY_BUCKET_COUNT] {
    let mut bounds = [0.0f64; LATENCY_BUCKET_COUNT];
    let mut cur = 2.0f64;
    let mut idx = 0usize;
    while idx < LATENCY_BUCKET_COUNT {
        bounds[idx] = cur;
        cur *= 1.5;
        idx += 1;
    }
    bounds
}

/// Atomic telemetry registry scraped by GKE's `prometheus-to-sd-exporter` sidecar.
pub struct MetricsRegistry {
    received_entries: AtomicU64,
    sent_entries: AtomicU64,
    podlabel_get_count: AtomicU64,
    cache_add: AtomicU64,
    cache_evict: AtomicU64,
    cache_queryhit: AtomicU64,
    cache_querymiss: AtomicU64,
    request_counts_by_code: Mutex<Vec<(String, u64)>>,
    latency_bounds: [f64; LATENCY_BUCKET_COUNT],
    latency_bucket_counts: [AtomicU64; LATENCY_BUCKET_COUNT],
    latency_inf_count: AtomicU64,
    latency_sum_micros: AtomicU64,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            received_entries: AtomicU64::new(0),
            sent_entries: AtomicU64::new(0),
            podlabel_get_count: AtomicU64::new(0),
            cache_add: AtomicU64::new(0),
            cache_evict: AtomicU64::new(0),
            cache_queryhit: AtomicU64::new(0),
            cache_querymiss: AtomicU64::new(0),
            request_counts_by_code: Mutex::new(Vec::new()),
            latency_bounds: compute_latency_bounds(),
            latency_bucket_counts: std::array::from_fn(|_| AtomicU64::new(0)),
            latency_inf_count: AtomicU64::new(0),
            latency_sum_micros: AtomicU64::new(0),
        }
    }

    pub fn add_received_entries(&self, count: u64) {
        self.received_entries.fetch_add(count, Ordering::Relaxed);
    }

    pub fn add_sent_entries(&self, count: u64) {
        self.sent_entries.fetch_add(count, Ordering::Relaxed);
    }

    pub fn inc_podlabel_get(&self) {
        self.podlabel_get_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pod_cache_op(&self, operation: &str) {
        self.add_pod_cache_op(operation, 1);
    }

    pub fn add_pod_cache_op(&self, operation: &str, delta: u64) {
        match operation {
            "add" => {
                self.cache_add.fetch_add(delta, Ordering::Relaxed);
            }
            "evict" => {
                self.cache_evict.fetch_add(delta, Ordering::Relaxed);
            }
            "queryhit" => {
                self.cache_queryhit.fetch_add(delta, Ordering::Relaxed);
            }
            "querymiss" => {
                self.cache_querymiss.fetch_add(delta, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn inc_sink_request(&self, http_equivalent_code: &str) {
        let mut guard = self
            .request_counts_by_code
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some((_, count)) = guard.iter_mut().find(|(c, _)| c == http_equivalent_code) {
            *count += 1;
            return;
        }
        guard.push((http_equivalent_code.to_string(), 1));
        guard.sort_by(|a, b| a.0.cmp(&b.0));
    }

    pub fn observe_sink_latency(&self, elapsed: Duration, entry_count: usize) {
        let secs = elapsed.as_secs_f64();
        let n = entry_count.max(1) as u64;
        for (idx, &bound) in self.latency_bounds.iter().enumerate() {
            if secs <= bound {
                self.latency_bucket_counts[idx].fetch_add(n, Ordering::Relaxed);
            }
        }
        self.latency_inf_count.fetch_add(n, Ordering::Relaxed);
        let micros = (elapsed.as_micros().min(u64::MAX as u128) as u64).saturating_mul(n);
        self.latency_sum_micros.fetch_add(micros, Ordering::Relaxed);
    }

    /// Observes end-to-end event delivery latency (`now - entry.timestamp`) on export success,
    /// matching Go `measureLatencyOnSuccess`.
    pub fn observe_entries_delivery_latency(
        &self,
        entries: &[crate::enricher::EnrichedEntry],
        now_unix_nanos: u64,
    ) {
        for entry in entries {
            if !entry.has_timestamp {
                continue;
            }
            let lag =
                Duration::from_nanos(now_unix_nanos.saturating_sub(entry.timestamp_unix_nanos));
            self.observe_sink_latency(lag, 1);
        }
    }

    /// Renders all Prometheus exposition metrics required by `event-exporter-manifest.yaml` and
    /// LOrIS.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        let _ = writeln!(
            out,
            "# HELP stackdriver_sink_received_entry_count Number of entries received by the sink.\n\
             # TYPE stackdriver_sink_received_entry_count counter\n\
             stackdriver_sink_received_entry_count {}",
            self.received_entries.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP stackdriver_sink_successfully_sent_entry_count Number of entries successfully exported.\n\
             # TYPE stackdriver_sink_successfully_sent_entry_count counter\n\
             stackdriver_sink_successfully_sent_entry_count {}",
            self.sent_entries.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP stackdriver_sink_request_count Number of export RPCs partitioned by HTTP status code.\n\
             # TYPE stackdriver_sink_request_count counter"
        );
        {
            let guard = self
                .request_counts_by_code
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if guard.is_empty() {
                let _ = writeln!(out, "stackdriver_sink_request_count{{code=\"200\"}} 0");
            } else {
                for (code, count) in guard.iter() {
                    let _ = writeln!(
                        out,
                        "stackdriver_sink_request_count{{code=\"{code}\"}} {count}"
                    );
                }
            }
        }

        let _ = writeln!(
            out,
            "# HELP stackdriver_sink_records_latency_seconds Export latency histogram in seconds.\n\
             # TYPE stackdriver_sink_records_latency_seconds histogram"
        );
        for (idx, &bound) in self.latency_bounds.iter().enumerate() {
            let count = self.latency_bucket_counts[idx].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "stackdriver_sink_records_latency_seconds_bucket{{le=\"{bound:.6}\"}} {count}"
            );
        }
        let inf_count = self.latency_inf_count.load(Ordering::Relaxed);
        let sum_secs = (self.latency_sum_micros.load(Ordering::Relaxed) as f64) / 1_000_000.0;
        let _ = writeln!(
            out,
            "stackdriver_sink_records_latency_seconds_bucket{{le=\"+Inf\"}} {inf_count}\n\
             stackdriver_sink_records_latency_seconds_sum {sum_secs:.6}\n\
             stackdriver_sink_records_latency_seconds_count {inf_count}"
        );

        let _ = writeln!(
            out,
            "# HELP podlabel_cache_ops_count Pod owner lookup table operations.\n\
             # TYPE podlabel_cache_ops_count counter\n\
             podlabel_cache_ops_count{{operation=\"add\"}} {}\n\
             podlabel_cache_ops_count{{operation=\"evict\"}} {}\n\
             podlabel_cache_ops_count{{operation=\"queryhit\"}} {}\n\
             podlabel_cache_ops_count{{operation=\"querymiss\"}} {}",
            self.cache_add.load(Ordering::Relaxed),
            self.cache_evict.load(Ordering::Relaxed),
            self.cache_queryhit.load(Ordering::Relaxed),
            self.cache_querymiss.load(Ordering::Relaxed),
        );

        let _ = writeln!(
            out,
            "# HELP podlabel_get_count Total pod owner label queries.\n\
             # TYPE podlabel_get_count counter\n\
             podlabel_get_count {}",
            self.podlabel_get_count.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP podlabel_nolabel_pod_cache_ops_count Compatibility counter for unlabelled pod cache.\n\
             # TYPE podlabel_nolabel_pod_cache_ops_count counter\n\
             podlabel_nolabel_pod_cache_ops_count{{operation=\"add\"}} 0"
        );

        out
    }
}

/// Maps gRPC status codes to their HTTP equivalents so LOrIS `query_exclude_user_errors.mash`
/// (`code="403"`, `code="429"`, `code="200"`) continues to evaluate identically under
/// `--sink=otlp`.
pub fn grpc_status_to_http_code(grpc_status: i32) -> &'static str {
    match grpc_status {
        0 => "200",
        1 => "499",
        3 | 9 | 11 => "400",
        4 => "504",
        5 => "404",
        6 => "409",
        7 => "403",
        8 => "429",
        12 => "501",
        14 => "503",
        16 => "401",
        _ => "500",
    }
}

/// Normalizes Go-style `:8080` bind addresses into Rust `SocketAddr`-compatible `0.0.0.0:8080`.
pub fn normalize_bind_addr(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    if let Some(port) = trimmed.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else {
        trimmed.to_string()
    }
}

/// Starts a lightweight `/metrics` and `/healthz` HTTP server on a background OS thread.
pub fn spawn_metrics_server(
    bind_endpoint: &str,
    registry: Arc<MetricsRegistry>,
    stop_flag: Arc<AtomicU8>,
) -> Result<(u16, JoinHandle<()>), String> {
    let addr = normalize_bind_addr(bind_endpoint);
    let listener = TcpListener::bind(&addr)
        .map_err(|e| format!("failed to bind Prometheus endpoint '{addr}': {e}"))?;
    let local_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("failed to set nonblocking metrics listener: {e}"))?;

    let handle = std::thread::Builder::new()
        .name("ee-metrics".to_string())
        .spawn(move || {
            while stop_flag.load(Ordering::Acquire) == 0 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                        let mut req_buf = [0u8; 512];
                        let n = stream.read(&mut req_buf).unwrap_or(0);
                        let req_line = String::from_utf8_lossy(&req_buf[..n]);
                        let is_health = req_line.starts_with("GET /healthz");
                        let body = if is_health {
                            "ok\n".to_string()
                        } else {
                            registry.render_prometheus()
                        };
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        })
        .map_err(|e| format!("failed to spawn metrics server thread: {e}"))?;

    Ok((local_port, handle))
}
