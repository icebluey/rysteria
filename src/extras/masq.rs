use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::header::{ALT_SVC, CONTENT_TYPE, HOST, LOCATION};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Body as HyperBody;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tower_http::services::ServeDir;

use crate::extras::correctnet::correct_tcp_listener;
use crate::unmap_ipv4;

const ALT_SVC_MAX_AGE: u32 = 2_592_000;
const H1_MAX_HEADERS: usize = 4_096;
const H1_MAX_BUF_SIZE: usize = 1_048_576;
const H2_MAX_HEADER_LIST_SIZE: u32 = 1_048_576 + 10 * 32;

type RespBody = BoxBody<Bytes, Infallible>;

fn full_body<T: Into<Bytes>>(body: T) -> RespBody {
    Full::new(body.into()).boxed()
}

fn empty_body() -> RespBody {
    Full::new(Bytes::new()).boxed()
}

#[async_trait]
pub trait MasqHandler: Send + Sync {
    async fn serve(&self, req: Request<()>, remote_addr: SocketAddr) -> Response<RespBody>;

    async fn serve_http(
        &self,
        req: Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> Response<RespBody> {
        let (parts, _body) = req.into_parts();
        self.serve(Request::from_parts(parts, ()), remote_addr)
            .await
    }
}

pub struct NotFoundHandler;

#[async_trait]
impl MasqHandler for NotFoundHandler {
    async fn serve(&self, _req: Request<()>, _remote_addr: SocketAddr) -> Response<RespBody> {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(full_body("404 page not found\n"))
            .unwrap_or_else(|_| Response::new(full_body("404 page not found\n")))
    }
}

pub struct StringHandler {
    pub content: String,
    pub headers: HashMap<String, String>,
    pub status_code: u16,
}

#[async_trait]
impl MasqHandler for StringHandler {
    async fn serve(&self, _req: Request<()>, _remote_addr: SocketAddr) -> Response<RespBody> {
        let status = if self.status_code == 0 {
            StatusCode::OK
        } else {
            StatusCode::from_u16(self.status_code).unwrap_or(StatusCode::OK)
        };
        let mut builder = Response::builder().status(status);
        for (k, v) in &self.headers {
            builder = builder.header(k, v);
        }
        builder
            .body(full_body(self.content.clone()))
            .unwrap_or_else(|_| Response::new(full_body(self.content.clone())))
    }
}

pub struct FileHandler {
    pub dir: PathBuf,
}

impl FileHandler {
    async fn serve_fs<B>(&self, req: Request<B>) -> Response<RespBody>
    where
        B: HyperBody<Data = Bytes> + Send + 'static,
        B::Error: Send + Sync + 'static,
    {
        let service = ServeDir::new(self.dir.clone());
        match service.oneshot(req).await {
            Ok(resp) => {
                let (parts, body) = resp.into_parts();
                let body_bytes = body
                    .collect()
                    .await
                    .map(|collected| collected.to_bytes())
                    .unwrap_or_default();

                let mut builder = Response::builder().status(parts.status);
                for (name, value) in &parts.headers {
                    builder = builder.header(name, value);
                }
                builder
                    .body(full_body(body_bytes))
                    .unwrap_or_else(|_| Response::new(empty_body()))
            }
            Err(_) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(empty_body())
                .unwrap_or_else(|_| Response::new(empty_body())),
        }
    }
}

#[async_trait]
impl MasqHandler for FileHandler {
    async fn serve(&self, req: Request<()>, _remote_addr: SocketAddr) -> Response<RespBody> {
        let (parts, _body) = req.into_parts();
        let req = Request::from_parts(parts, Empty::<Bytes>::new());
        self.serve_fs(req).await
    }

    async fn serve_http(
        &self,
        req: Request<Incoming>,
        _remote_addr: SocketAddr,
    ) -> Response<RespBody> {
        self.serve_fs(req).await
    }
}

pub struct ProxyHandler {
    pub upstream: Uri,
    pub rewrite_host: bool,
    pub client: reqwest::Client,
}

impl ProxyHandler {
    fn rewrite_uri(&self, req_uri: &Uri) -> Option<String> {
        let scheme = self.upstream.scheme_str()?;
        let authority = self.upstream.authority()?.as_str();

        let upstream_path = self.upstream.path();
        let req_path = req_uri.path();
        let joined_path = match (upstream_path.ends_with('/'), req_path.starts_with('/')) {
            (true, true) => format!("{}{}", upstream_path, req_path.trim_start_matches('/')),
            (false, false) => format!("{upstream_path}/{req_path}"),
            _ => format!("{upstream_path}{req_path}"),
        };

        let mut target = format!("{scheme}://{authority}{joined_path}");
        if let Some(query) = req_uri.query() {
            target.push('?');
            target.push_str(query);
        }
        Some(target)
    }

    fn filtered_headers(&self, src: &HeaderMap<HeaderValue>) -> reqwest::header::HeaderMap {
        let mut out = reqwest::header::HeaderMap::new();
        for (k, v) in src {
            if *k == HOST {
                continue;
            }
            let name = match reqwest::header::HeaderName::from_bytes(k.as_str().as_bytes()) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let value = match reqwest::header::HeaderValue::from_bytes(v.as_bytes()) {
                Ok(v) => v,
                Err(_) => continue,
            };
            out.insert(name, value);
        }
        out
    }

    async fn forward_request(
        &self,
        method: http::Method,
        uri: Uri,
        headers: HeaderMap<HeaderValue>,
        body: Bytes,
    ) -> Response<RespBody> {
        let target = match self.rewrite_uri(&uri) {
            Some(v) => v,
            None => {
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(empty_body())
                    .unwrap_or_else(|_| Response::new(empty_body()));
            }
        };

        let mut builder = self
            .client
            .request(
                reqwest::Method::from_bytes(method.as_str().as_bytes())
                    .unwrap_or(reqwest::Method::GET),
                target,
            )
            .headers(self.filtered_headers(&headers))
            .body(body);

        if self.rewrite_host {
            if let Some(authority) = self.upstream.authority() {
                builder = builder.header(HOST.as_str(), authority.as_str());
            }
        } else if let Some(host) = headers.get(HOST).and_then(|v| v.to_str().ok()) {
            builder = builder.header(HOST.as_str(), host);
        }

        match builder.send().await {
            Ok(upstream_resp) => {
                let status = upstream_resp.status();
                let headers = upstream_resp.headers().clone();
                match upstream_resp.bytes().await {
                    Ok(body) => {
                        let mut resp = Response::builder().status(status.as_u16());
                        for (name, value) in &headers {
                            resp = resp.header(name.as_str(), value.as_bytes());
                        }
                        resp.body(full_body(body))
                            .unwrap_or_else(|_| Response::new(empty_body()))
                    }
                    Err(err) => {
                        tracing::error!(error = ?err, "HTTP reverse proxy error");
                        Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(empty_body())
                            .unwrap_or_else(|_| Response::new(empty_body()))
                    }
                }
            }
            Err(err) => {
                tracing::error!(error = ?err, "HTTP reverse proxy error");
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(empty_body())
                    .unwrap_or_else(|_| Response::new(empty_body()))
            }
        }
    }
}

#[async_trait]
impl MasqHandler for ProxyHandler {
    async fn serve(&self, req: Request<()>, _remote_addr: SocketAddr) -> Response<RespBody> {
        let (parts, _body) = req.into_parts();
        self.forward_request(parts.method, parts.uri, parts.headers, Bytes::new())
            .await
    }

    async fn serve_http(
        &self,
        req: Request<Incoming>,
        _remote_addr: SocketAddr,
    ) -> Response<RespBody> {
        let (parts, body) = req.into_parts();
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                tracing::error!(error = ?err, "HTTP reverse proxy error");
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(empty_body())
                    .unwrap_or_else(|_| Response::new(empty_body()));
            }
        };
        self.forward_request(parts.method, parts.uri, parts.headers, body_bytes)
            .await
    }
}

pub struct MasqHandlerLogWrapper {
    pub handler: Arc<dyn MasqHandler + Send + Sync>,
    pub quic: bool,
}

#[async_trait]
impl MasqHandler for MasqHandlerLogWrapper {
    async fn serve(&self, req: Request<()>, remote_addr: SocketAddr) -> Response<RespBody> {
        tracing::debug!(
            addr = %remote_addr,
            method = %req.method(),
            host = req.headers().get(HOST).and_then(|v| v.to_str().ok()).unwrap_or(""),
            url = %req.uri(),
            quic = self.quic,
            "masquerade request"
        );
        self.handler.serve(req, remote_addr).await
    }

    async fn serve_http(
        &self,
        req: Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> Response<RespBody> {
        tracing::debug!(
            addr = %remote_addr,
            method = %req.method(),
            host = req.headers().get(HOST).and_then(|v| v.to_str().ok()).unwrap_or(""),
            url = %req.uri(),
            quic = self.quic,
            "masquerade request"
        );
        self.handler.serve_http(req, remote_addr).await
    }
}

fn inject_alt_svc(mut resp: Response<RespBody>, quic_port: u16) -> Response<RespBody> {
    let value = format!("h3=\":{}\"; ma={}", quic_port, ALT_SVC_MAX_AGE);
    if let Ok(v) = HeaderValue::from_str(&value) {
        resp.headers_mut().insert(ALT_SVC, v);
    }
    resp
}

pub struct MasqTCPServer {
    pub quic_port: u16,
    pub https_port: u16,
    pub handler: Arc<dyn MasqHandler + Send + Sync>,
    pub tls_config: Arc<rustls::ServerConfig>,
    pub force_https: bool,
}

impl MasqTCPServer {
    pub async fn listen_and_serve_http(&self, addr: &str) -> io::Result<()> {
        let listener = correct_tcp_listener(addr).await?;
        loop {
            let (stream, remote_addr) = listener.accept().await?;
            let remote_addr = unmap_ipv4(remote_addr);
            let handler = Arc::clone(&self.handler);
            let quic_port = self.quic_port;
            let https_port = self.https_port;
            let force_https = self.force_https;
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let handler = Arc::clone(&handler);
                    async move {
                        let host = req
                            .headers()
                            .get(HOST)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let path_q = req
                            .uri()
                            .path_and_query()
                            .map(|v| v.as_str())
                            .unwrap_or("/")
                            .to_string();

                        if force_https {
                            let location = if https_port == 0 || https_port == 443 {
                                format!("https://{}{}", host, path_q)
                            } else {
                                format!("https://{}:{}{}", host, https_port, path_q)
                            };
                            let mut resp = Response::new(empty_body());
                            *resp.status_mut() = StatusCode::MOVED_PERMANENTLY;
                            if let Ok(v) = HeaderValue::from_str(&location) {
                                resp.headers_mut().insert(LOCATION, v);
                            }
                            return Ok::<_, Infallible>(resp);
                        }

                        let resp = handler.serve_http(req, remote_addr).await;
                        Ok::<_, Infallible>(inject_alt_svc(resp, quic_port))
                    }
                });

                let mut h1 = hyper::server::conn::http1::Builder::new();
                h1.max_headers(H1_MAX_HEADERS);
                h1.max_buf_size(H1_MAX_BUF_SIZE);
                let _ = h1
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    }

    pub async fn listen_and_serve_https(&self, addr: &str) -> io::Result<()> {
        let listener = correct_tcp_listener(addr).await?;
        let acceptor = TlsAcceptor::from(Arc::clone(&self.tls_config));

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            let remote_addr = unmap_ipv4(remote_addr);
            let acceptor = acceptor.clone();
            let handler = Arc::clone(&self.handler);
            let quic_port = self.quic_port;

            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(v) => v,
                    Err(err) => {
                        tracing::warn!(addr = %remote_addr, error = %err, "TLS error");
                        return;
                    }
                };

                let alpn = tls_stream
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|v| v.to_vec())
                    .unwrap_or_default();

                let service = service_fn(move |req: Request<Incoming>| {
                    let handler = Arc::clone(&handler);
                    async move {
                        let resp = handler.serve_http(req, remote_addr).await;
                        Ok::<_, Infallible>(inject_alt_svc(resp, quic_port))
                    }
                });

                let io = TokioIo::new(tls_stream);
                if alpn.as_slice() == b"h2" {
                    let mut h2 = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                    h2.max_header_list_size(H2_MAX_HEADER_LIST_SIZE);
                    let _ = h2.serve_connection(io, service).await;
                } else {
                    let mut h1 = hyper::server::conn::http1::Builder::new();
                    h1.max_headers(H1_MAX_HEADERS);
                    h1.max_buf_size(H1_MAX_BUF_SIZE);
                    let _ = h1.serve_connection(io, service).with_upgrades().await;
                }
            });
        }
    }
}

pub async fn run_masq_tcp_server(
    server: Arc<MasqTCPServer>,
    http_addr: Option<String>,
    https_addr: Option<String>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<io::Result<()>>(2);

    if let Some(addr) = http_addr {
        let server = Arc::clone(&server);
        let tx = tx.clone();
        tokio::spawn(async move {
            tracing::info!(listen = %addr, "masquerade HTTP server up and running");
            let _ = tx.send(server.listen_and_serve_http(&addr).await).await;
        });
    }

    if let Some(addr) = https_addr {
        let server = Arc::clone(&server);
        let tx = tx.clone();
        tokio::spawn(async move {
            tracing::info!(listen = %addr, "masquerade HTTPS server up and running");
            let _ = tx.send(server.listen_and_serve_https(&addr).await).await;
        });
    }

    if let Some(Err(err)) = rx.recv().await {
        tracing::error!(error = ?err, "failed to serve masquerade HTTP(S)");
        std::process::exit(1);
    }
}
