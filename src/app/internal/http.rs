use std::convert::Infallible;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use bytes::Bytes;
use http::header::{CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

use crate::app::internal::utils::copy_two_way;
use crate::core::client::ReconnectableClient;
use crate::unmap_ipv4;

type ProxyBody = BoxBody<Bytes, hyper::Error>;

const HTTP_CLIENT_TIMEOUT_SECS: u64 = 10;

pub trait EventLogger: Send + Sync {
    fn connect_request(&self, addr: SocketAddr, req_addr: &str);
    fn connect_error(
        &self,
        addr: SocketAddr,
        req_addr: &str,
        err: Option<&(dyn Error + Send + Sync)>,
    );
    fn http_request(&self, addr: SocketAddr, req_url: &str);
    fn http_error(&self, addr: SocketAddr, req_url: &str, err: Option<&(dyn Error + Send + Sync)>);
}

pub struct Server {
    pub hy_client: Arc<ReconnectableClient>,
    pub auth_func: Option<Arc<dyn Fn(&str, &str) -> bool + Send + Sync>>,
    pub auth_realm: String,
    pub event_logger: Option<Arc<dyn EventLogger>>,
}

impl Server {
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        loop {
            let (stream, remote_addr) = listener.accept().await?;
            let remote_addr = unmap_ipv4(remote_addr);
            let server = Arc::clone(&self);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let server = Arc::clone(&server);
                    async move { server.handle_request(remote_addr, req).await }
                });
                let _ = Http1Builder::new()
                    .keep_alive(true)
                    .timer(hyper_util::rt::TokioTimer::new())
                    .serve_connection(io, svc)
                    .with_upgrades()
                    .await;
            });
        }
    }

    pub async fn dispatch(self: Arc<Self>, stream: TcpStream) {
        let remote_addr = unmap_ipv4(
            stream
                .peer_addr()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
        );

        let io = TokioIo::new(stream);
        let svc = service_fn(move |req| {
            let server = Arc::clone(&self);
            async move { server.handle_request(remote_addr, req).await }
        });
        let _ = Http1Builder::new()
            .keep_alive(true)
            .timer(hyper_util::rt::TokioTimer::new())
            .serve_connection(io, svc)
            .with_upgrades()
            .await;
    }

    async fn handle_request(
        self: Arc<Self>,
        remote_addr: SocketAddr,
        req: Request<Incoming>,
    ) -> Result<Response<ProxyBody>, Infallible> {
        if !self.check_auth(&req) {
            return Ok(proxy_auth_required(self.realm()));
        }

        if req.method() == Method::CONNECT {
            return Ok(self.handle_connect(remote_addr, req).await);
        }

        let req_url = req.uri().to_string();
        if let Some(logger) = &self.event_logger {
            logger.http_request(remote_addr, &req_url);
        }

        let mut close_error: Option<Box<dyn Error + Send + Sync>> = None;
        let response = match self.forward_http_request(req).await {
            Ok(resp) => resp,
            Err(err) => {
                close_error = Some(Box::new(err));
                simple_response(StatusCode::BAD_GATEWAY)
            }
        };

        if let Some(logger) = &self.event_logger {
            logger.http_error(remote_addr, &req_url, close_error.as_deref());
        }
        Ok(response)
    }

    fn check_auth(&self, req: &Request<Incoming>) -> bool {
        let Some(auth_func) = &self.auth_func else {
            return true;
        };
        let Some(header) = req.headers().get(PROXY_AUTHORIZATION) else {
            return false;
        };
        let Ok(value) = header.to_str() else {
            return false;
        };
        let Some(raw) = value.strip_prefix("Basic ") else {
            return false;
        };

        let decoded = STANDARD.decode(raw).or_else(|_| URL_SAFE.decode(raw)).ok();
        let Some(decoded) = decoded else {
            return false;
        };
        let text = String::from_utf8_lossy(&decoded);
        let Some((user, pass)) = text.split_once(':') else {
            return false;
        };
        auth_func(user, pass)
    }

    fn realm(&self) -> &str {
        if self.auth_realm.is_empty() {
            "Hysteria"
        } else {
            &self.auth_realm
        }
    }

    async fn handle_connect(
        self: Arc<Self>,
        remote_addr: SocketAddr,
        req: Request<Incoming>,
    ) -> Response<ProxyBody> {
        let Some(authority) = req.uri().authority().map(|a| a.as_str().to_string()) else {
            return simple_response(StatusCode::BAD_REQUEST);
        };

        if let Some(logger) = &self.event_logger {
            logger.connect_request(remote_addr, &authority);
        }

        let hy_conn = match self.hy_client.tcp(&authority).await {
            Ok(c) => c,
            Err(err) => {
                if let Some(logger) = &self.event_logger {
                    logger.connect_error(remote_addr, &authority, Some(err.as_ref()));
                }
                return simple_response(StatusCode::BAD_GATEWAY);
            }
        };

        let on_upgrade = hyper::upgrade::on(req);
        let logger = self.event_logger.as_ref().map(Arc::clone);
        tokio::spawn(async move {
            let mut close_error: Option<Box<dyn Error + Send + Sync>> = None;
            let upgraded = match on_upgrade.await {
                Ok(u) => u,
                Err(err) => {
                    close_error = Some(Box::new(err));
                    if let Some(logger) = &logger {
                        logger.connect_error(remote_addr, &authority, close_error.as_deref());
                    }
                    return;
                }
            };

            let local = TokioIo::new(upgraded);
            if let Err(err) = copy_two_way(local, hy_conn).await {
                close_error = Some(Box::new(err));
            }

            if let Some(logger) = &logger {
                logger.connect_error(remote_addr, &authority, close_error.as_deref());
            }
        });

        simple_response(StatusCode::OK)
    }

    async fn forward_http_request(
        &self,
        mut req: Request<Incoming>,
    ) -> io::Result<Response<ProxyBody>> {
        let target_addr = resolve_target_addr(req.uri(), req.headers())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid target URL"))?;

        remove_hop_by_hop_headers(req.headers_mut());
        req.headers_mut().remove(PROXY_AUTHORIZATION);

        let path = req
            .uri()
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or("/");
        *req.uri_mut() = Uri::from_str(path)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;

        if let Some(host_header) = normalize_host_header(req.uri(), &target_addr) {
            req.headers_mut().insert(HOST, host_header);
        }

        let hy_conn = self
            .hy_client
            .tcp(&target_addr)
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;

        let io = TokioIo::new(hy_conn);
        let (mut sender, connection) = http1::handshake(io)
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;

        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(HTTP_CLIENT_TIMEOUT_SECS), connection)
                .await;
        });

        let mut response = sender
            .send_request(req)
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;

        remove_hop_by_hop_headers(response.headers_mut());

        Ok(response.map(|body| body.boxed()))
    }
}

fn resolve_target_addr(uri: &Uri, headers: &http::HeaderMap) -> Option<String> {
    if let Some(authority) = uri.authority() {
        return Some(with_default_port(authority.as_str(), uri.scheme_str()));
    }

    let host = headers.get(HOST)?.to_str().ok()?;
    Some(with_default_port(host, uri.scheme_str()))
}

fn with_default_port(authority: &str, scheme: Option<&str>) -> String {
    if authority.rfind(':').is_some() {
        authority.to_string()
    } else {
        let port = match scheme.unwrap_or("http") {
            "https" => 443,
            _ => 80,
        };
        format!("{authority}:{port}")
    }
}

fn normalize_host_header(uri: &Uri, target_addr: &str) -> Option<http::HeaderValue> {
    let host = uri.host().unwrap_or(target_addr);
    http::HeaderValue::from_str(host).ok()
}

fn remove_hop_by_hop_headers(headers: &mut http::HeaderMap) {
    headers.remove("proxy-connection");
    headers.remove(CONNECTION);
    headers.remove("keep-alive");
    headers.remove("proxy-authenticate");
    headers.remove("te");
    headers.remove("trailers");
    headers.remove("transfer-encoding");
    headers.remove("upgrade");
}

fn simple_response(status: StatusCode) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(empty_body())
        .unwrap_or_else(|_| Response::new(empty_body()))
}

fn proxy_auth_required(realm: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(PROXY_AUTHENTICATE, format!("Basic realm=\"{realm}\""))
        .body(full_body("Proxy Authentication Required"))
        .unwrap_or_else(|_| simple_response(StatusCode::PROXY_AUTHENTICATION_REQUIRED))
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body(content: impl Into<Bytes>) -> ProxyBody {
    Full::new(content.into())
        .map_err(|never| match never {})
        .boxed()
}
