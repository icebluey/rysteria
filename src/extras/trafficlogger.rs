use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fmt::Write as _;
use std::io;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::net::TcpListener;

const INDEX_HTML: &str = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Hysteria Traffic Stats API Server</title><style>body{font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;padding:0;background-color:#f4f4f4}.container{padding:20px;background-color:#fff;box-shadow:0 4px 6px rgba(0,0,0,.1);border-radius:5px}</style></head><body><div class=\"container\"><p>This is a Hysteria Traffic Stats API server.</p><p>Check the documentation for usage.</p></div></body></html>";

fn unix_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

fn millis_to_system_time(ms: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms)
}

fn full_body<T: Into<Bytes>>(v: T) -> BoxBody<Bytes, Infallible> {
    Full::new(v.into()).boxed()
}

fn text_response(
    status: StatusCode,
    body: impl Into<Bytes>,
) -> Response<BoxBody<Bytes, Infallible>> {
    let mut resp = Response::new(full_body(body));
    *resp.status_mut() = status;
    resp
}

fn json_response<T: Serialize>(value: &T) -> Response<BoxBody<Bytes, Infallible>> {
    match serde_json::to_vec(value) {
        Ok(payload) => {
            let mut resp = Response::new(full_body(payload));
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/json; charset=utf-8"),
            );
            resp
        }
        Err(err) => text_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Initial,
    Hooking,
    Connecting,
    Established,
    Closed,
}

impl StreamState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "init",
            Self::Hooking => "hook",
            Self::Connecting => "connect",
            Self::Established => "estab",
            Self::Closed => "closed",
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Initial => 0,
            Self::Hooking => 1,
            Self::Connecting => 2,
            Self::Established => 3,
            Self::Closed => 4,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Hooking,
            2 => Self::Connecting,
            3 => Self::Established,
            4 => Self::Closed,
            _ => Self::Initial,
        }
    }
}

pub struct StreamStats {
    state: AtomicU8,
    pub auth_id: String,
    pub conn_id: u32,
    pub initial_time: SystemTime,
    req_addr: RwLock<String>,
    hooked_req_addr: RwLock<String>,
    pub tx: AtomicU64,
    pub rx: AtomicU64,
    last_active_time_ms: AtomicU64,
}

impl StreamStats {
    pub fn new(auth_id: String, conn_id: u32) -> Self {
        let now = unix_millis_now();
        Self {
            state: AtomicU8::new(StreamState::Initial.as_u8()),
            auth_id,
            conn_id,
            initial_time: SystemTime::now(),
            req_addr: RwLock::new(String::new()),
            hooked_req_addr: RwLock::new(String::new()),
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
            last_active_time_ms: AtomicU64::new(now),
        }
    }

    pub fn state(&self) -> StreamState {
        StreamState::from_u8(self.state.load(Ordering::Relaxed))
    }

    pub fn set_state(&self, state: StreamState) {
        self.state.store(state.as_u8(), Ordering::Relaxed);
    }

    pub fn req_addr(&self) -> String {
        self.req_addr
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn set_req_addr(&self, addr: String) {
        *self.req_addr.write().unwrap_or_else(|e| e.into_inner()) = addr;
    }

    pub fn hooked_req_addr(&self) -> String {
        self.hooked_req_addr
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn set_hooked_req_addr(&self, addr: &str) {
        let req = self.req_addr();
        if req != addr {
            *self
                .hooked_req_addr
                .write()
                .unwrap_or_else(|e| e.into_inner()) = addr.to_string();
        }
    }

    pub fn touch(&self) {
        self.last_active_time_ms
            .store(unix_millis_now(), Ordering::Relaxed);
    }

    pub fn last_active_time(&self) -> SystemTime {
        millis_to_system_time(self.last_active_time_ms.load(Ordering::Relaxed))
    }
}

pub trait TrafficLogger: Send + Sync {
    fn log_traffic(&self, id: &str, tx: u64, rx: u64) -> bool;
    fn log_online_state(&self, id: &str, online: bool);
    fn trace_stream(&self, stream_id: u64, stats: Arc<StreamStats>);
    fn untrace_stream(&self, stream_id: u64);
}

#[derive(Debug, Clone, Copy, Serialize)]
struct TrafficEntry {
    tx: u64,
    rx: u64,
}

#[derive(Default)]
struct TrafficStatsInner {
    stats_map: HashMap<String, TrafficEntry>,
    online_map: HashMap<String, i32>,
    kick_map: HashSet<String>,
    stream_map: HashMap<u64, Arc<StreamStats>>,
}

#[derive(Clone)]
pub struct TrafficStatsServer {
    inner: Arc<RwLock<TrafficStatsInner>>,
    secret: String,
}

impl TrafficStatsServer {
    pub fn new(secret: String) -> Self {
        Self {
            inner: Arc::new(RwLock::new(TrafficStatsInner::default())),
            secret,
        }
    }

    fn authorized(&self, req: &Request<Incoming>) -> bool {
        if self.secret.is_empty() {
            return true;
        }
        req.headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == self.secret)
    }

    async fn handle_http(&self, req: Request<Incoming>) -> Response<BoxBody<Bytes, Infallible>> {
        if !self.authorized(&req) {
            return text_response(StatusCode::UNAUTHORIZED, "unauthorized\n");
        }

        let path = req.uri().path();
        match (req.method(), path) {
            (&Method::GET, "/") => {
                let mut resp = Response::new(full_body(INDEX_HTML));
                resp.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                );
                resp
            }
            (&Method::GET, "/traffic") => self.get_traffic(req.uri().query()),
            (&Method::GET, "/online") => self.get_online(),
            (&Method::POST, "/kick") => self.kick(req).await,
            (&Method::GET, "/dump/streams") => self.get_dump_streams(req.headers().get(ACCEPT)),
            _ => text_response(StatusCode::NOT_FOUND, "404 page not found\n"),
        }
    }

    fn get_traffic(&self, query: Option<&str>) -> Response<BoxBody<Bytes, Infallible>> {
        let clear = query
            .and_then(|q| {
                q.split('&').find_map(|kv| {
                    let (k, v) = kv.split_once('=')?;
                    if k == "clear" {
                        Some(v.eq_ignore_ascii_case("true") || v == "1")
                    } else {
                        None
                    }
                })
            })
            .unwrap_or(false);

        if clear {
            let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
            let snapshot = guard.stats_map.clone();
            guard.stats_map.clear();
            json_response(&snapshot)
        } else {
            let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
            json_response(&guard.stats_map)
        }
    }

    fn get_online(&self) -> Response<BoxBody<Bytes, Infallible>> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        json_response(&guard.online_map)
    }

    async fn kick(&self, req: Request<Incoming>) -> Response<BoxBody<Bytes, Infallible>> {
        let body_bytes = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => return text_response(StatusCode::BAD_REQUEST, err.to_string()),
        };

        let ids: Vec<String> = match serde_json::from_slice(&body_bytes) {
            Ok(v) => v,
            Err(err) => return text_response(StatusCode::BAD_REQUEST, err.to_string()),
        };

        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        for id in ids {
            guard.kick_map.insert(id);
        }

        text_response(StatusCode::OK, Bytes::new())
    }

    fn get_dump_streams(
        &self,
        accept: Option<&HeaderValue>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        #[derive(Serialize)]
        struct DumpEntry {
            state: String,
            auth: String,
            connection: String,
            stream: u64,
            req_addr: String,
            hooked_req_addr: String,
            tx: u64,
            rx: u64,
            initial_at: String,
            last_active_at: String,
        }

        let mut entries = {
            let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
            guard
                .stream_map
                .iter()
                .map(|(stream_id, stats)| DumpEntry {
                    state: stats.state().as_str().to_string(),
                    auth: stats.auth_id.clone(),
                    connection: format!("{:08X}", stats.conn_id),
                    stream: *stream_id,
                    req_addr: stats.req_addr(),
                    hooked_req_addr: stats.hooked_req_addr(),
                    tx: stats.tx.load(Ordering::Relaxed),
                    rx: stats.rx.load(Ordering::Relaxed),
                    initial_at: humantime_timestamp(stats.initial_time),
                    last_active_at: humantime_timestamp(stats.last_active_time()),
                })
                .collect::<Vec<_>>()
        };

        entries.sort_by(|lhs, rhs| {
            lhs.auth
                .cmp(&rhs.auth)
                .then_with(|| lhs.connection.cmp(&rhs.connection))
                .then_with(|| lhs.stream.cmp(&rhs.stream))
        });

        let wants_text = accept
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("text/plain"));

        if wants_text {
            let mut out = String::new();
            let _ = writeln!(
                out,
                "{:<8} {:<12} {:>12} {:>8} {:>12} {:>12} {:>12} {:>12} {:<16} {}",
                "State",
                "Auth",
                "Connection",
                "Stream",
                "TX-Bytes",
                "RX-Bytes",
                "Req-Addr",
                "Hooked-Req",
                "Initial-At",
                "Last-Active"
            );
            for e in entries {
                let _ = writeln!(
                    out,
                    "{:<8} {:<12} {:>12} {:>8} {:>12} {:>12} {:>12} {:>12} {:<16} {}",
                    e.state.to_uppercase(),
                    e.auth,
                    e.connection,
                    e.stream,
                    e.tx,
                    e.rx,
                    if e.req_addr.is_empty() {
                        "-"
                    } else {
                        &e.req_addr
                    },
                    if e.hooked_req_addr.is_empty() {
                        "-"
                    } else {
                        &e.hooked_req_addr
                    },
                    e.initial_at,
                    e.last_active_at
                );
            }
            let mut resp = Response::new(full_body(out));
            resp.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            return resp;
        }

        #[derive(Serialize)]
        struct DumpWrapper {
            streams: Vec<DumpEntry>,
        }

        json_response(&DumpWrapper { streams: entries })
    }
}

impl TrafficLogger for TrafficStatsServer {
    fn log_traffic(&self, id: &str, tx: u64, rx: u64) -> bool {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if guard.kick_map.remove(id) {
            return false;
        }

        let entry = guard
            .stats_map
            .entry(id.to_string())
            .or_insert(TrafficEntry { tx: 0, rx: 0 });
        entry.tx = entry.tx.saturating_add(tx);
        entry.rx = entry.rx.saturating_add(rx);
        true
    }

    fn log_online_state(&self, id: &str, online: bool) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if online {
            let current = guard.online_map.get(id).copied().unwrap_or(0);
            guard.online_map.insert(id.to_string(), current + 1);
        } else {
            let current = guard.online_map.get(id).copied().unwrap_or(0) - 1;
            if current <= 0 {
                guard.online_map.remove(id);
            } else {
                guard.online_map.insert(id.to_string(), current);
            }
        }
    }

    fn trace_stream(&self, stream_id: u64, stats: Arc<StreamStats>) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        guard.stream_map.insert(stream_id, stats);
    }

    fn untrace_stream(&self, stream_id: u64) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        guard.stream_map.remove(&stream_id);
    }
}

pub async fn run_traffic_stats_server(
    listen: &str,
    server: Arc<TrafficStatsServer>,
) -> io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let server = Arc::clone(&server);
                async move { Ok::<_, Infallible>(server.handle_http(req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}

fn humantime_timestamp(ts: SystemTime) -> String {
    let dt: OffsetDateTime = ts.into();
    dt.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::{StreamState, StreamStats, TrafficLogger, TrafficStatsServer};
    use std::sync::Arc;

    #[test]
    fn stream_state_roundtrip() {
        let stats = StreamStats::new("u".to_string(), 1);
        stats.set_state(StreamState::Hooking);
        assert_eq!(stats.state(), StreamState::Hooking);
    }

    #[test]
    fn kick_marks_disconnect() {
        let server = TrafficStatsServer::new(String::new());
        assert!(server.log_traffic("a", 1, 2));
        server.log_online_state("a", true);
        let stats = Arc::new(StreamStats::new("a".to_string(), 1));
        server.trace_stream(10, stats);
        server.untrace_stream(10);
    }
}
