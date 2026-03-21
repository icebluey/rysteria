use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, ResolverConfig as HickoryResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol as DnsProtocol;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use tracing::info;

use crate::app::cmd::{BoxError, parse_bandwidth_bps, parse_config, read_config_file, resolve_config_path};
use crate::core::internal::pmtud::DISABLE_PATH_MTU_DISCOVERY;
use crate::core::internal::protocol::{DEFAULT_CONN_RECEIVE_WINDOW, DEFAULT_STREAM_RECEIVE_WINDOW};
use crate::core::server::{EventLogger, RequestHook, Server, ServerConfig, TransportConfigBuilder};
use crate::extras::auth::{
    Authenticator, CommandAuthenticator, HttpAuthenticator, PasswordAuthenticator,
    UserPassAuthenticator,
};
use crate::extras::masq::{
    FileHandler, MasqHandler, MasqHandlerLogWrapper, MasqTCPServer, NotFoundHandler, ProxyHandler,
    StringHandler, run_masq_tcp_server,
};
use crate::extras::obfs::SalamanderObfuscator;
use crate::extras::outbounds::utils::{
    DirectOutbound, DirectOutboundMode, DirectOutboundOptions, HostResolveResult, HostResolver,
    PluggableOutbound, SystemResolver,
};
use crate::extras::outbounds::{
    HttpOutbound, OutboundEntry, Socks5Outbound, http_proxy_auth_header,
    new_acl_engine_from_string_with_resolver_and_geo,
};
use crate::extras::sniff::{PortUnion, Sniffer};
use crate::extras::tls::{GuardedCertResolver, SniGuardMode};
use crate::extras::trafficlogger::{TrafficLogger, TrafficStatsServer, run_traffic_stats_server};

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerConfigFile {
    listen: String,
    obfs: ServerObfsConfig,
    tls: ServerTlsConfig,
    quic: ServerQuicConfig,
    auth: ServerAuthConfig,
    bandwidth: ServerBandwidthConfig,
    #[serde(rename = "ignoreClientBandwidth")]
    ignore_client_bandwidth: bool,
    #[serde(rename = "speedTest")]
    speed_test: bool,
    #[serde(rename = "disableUDP")]
    disable_udp: bool,
    #[serde(rename = "udpIdleTimeout")]
    udp_idle_timeout: String,
    #[serde(rename = "trafficStats")]
    traffic_stats: TrafficStatsConfig,
    masquerade: MasqueradeConfig,
    sniff: SniffConfig,
    resolver: ServerResolverConfig,
    acl: ServerAclConfig,
    outbounds: Vec<ServerOutboundConfig>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerObfsConfig {
    #[serde(rename = "type")]
    obfs_type: String,
    salamander: ServerObfsSalamanderConfig,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerObfsSalamanderConfig {
    password: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerTlsConfig {
    cert: String,
    key: String,
    #[serde(rename = "sniGuard")]
    sni_guard: String,
    #[serde(rename = "clientCA")]
    client_ca: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerBandwidthConfig {
    up: String,
    down: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct ServerQuicConfig {
    #[serde(rename = "initStreamReceiveWindow")]
    init_stream_receive_window: u64,
    #[serde(rename = "maxStreamReceiveWindow")]
    max_stream_receive_window: u64,
    #[serde(rename = "initConnReceiveWindow")]
    init_conn_receive_window: u64,
    #[serde(rename = "maxConnReceiveWindow")]
    max_conn_receive_window: u64,
    #[serde(rename = "maxIdleTimeout")]
    max_idle_timeout: String,
    #[serde(rename = "maxIncomingStreams")]
    max_incoming_streams: u64,
    #[serde(rename = "disablePathMTUDiscovery")]
    disable_path_mtu_discovery: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerAuthHttpConfig {
    url: String,
    insecure: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerAuthConfig {
    #[serde(rename = "type")]
    auth_type: String,
    password: String,
    userpass: HashMap<String, String>,
    http: ServerAuthHttpConfig,
    command: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct TrafficStatsConfig {
    listen: String,
    secret: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct SniffConfig {
    enable: bool,
    timeout: String,
    #[serde(rename = "rewriteDomain")]
    rewrite_domain: bool,
    #[serde(rename = "tcpPorts")]
    tcp_ports: String,
    #[serde(rename = "udpPorts")]
    udp_ports: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct MasqueradeConfig {
    #[serde(rename = "type")]
    masq_type: String,
    proxy: MasqueradeProxyConfig,
    string: MasqueradeStringConfig,
    file: MasqueradeFileConfig,
    #[serde(rename = "listenHTTP")]
    listen_http: String,
    #[serde(rename = "listenHTTPS")]
    listen_https: String,
    #[serde(rename = "forceHTTPS")]
    force_https: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct MasqueradeProxyConfig {
    url: String,
    #[serde(rename = "rewriteHost")]
    rewrite_host: bool,
    insecure: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct MasqueradeStringConfig {
    content: String,
    headers: HashMap<String, String>,
    #[serde(rename = "statusCode")]
    status_code: u16,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct MasqueradeFileConfig {
    dir: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerResolverConfig {
    #[serde(rename = "type")]
    resolver_type: String,
    udp: ServerResolverStandardConfig,
    tcp: ServerResolverStandardConfig,
    tls: ServerResolverTlsConfig,
    https: ServerResolverHttpsConfig,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerResolverStandardConfig {
    addr: String,
    timeout: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerResolverTlsConfig {
    addr: String,
    timeout: String,
    sni: String,
    insecure: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerResolverHttpsConfig {
    addr: String,
    timeout: String,
    sni: String,
    insecure: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerAclConfig {
    file: String,
    inline: Vec<String>,
    geoip: String,
    geosite: String,
    #[serde(rename = "geoUpdateInterval")]
    geo_update_interval: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerOutboundConfig {
    name: String,
    #[serde(rename = "type")]
    outbound_type: String,
    direct: ServerOutboundDirectConfig,
    socks5: ServerOutboundSocks5Config,
    http: ServerOutboundHttpConfig,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerOutboundDirectConfig {
    mode: String,
    #[serde(rename = "bindIPv4")]
    bind_ipv4: String,
    #[serde(rename = "bindIPv6")]
    bind_ipv6: String,
    #[serde(rename = "bindDevice")]
    bind_device: String,
    #[serde(rename = "fastOpen")]
    fast_open: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerOutboundSocks5Config {
    addr: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ServerOutboundHttpConfig {
    url: String,
    insecure: bool,
    username: String,
    password: String,
}

struct ServerEventLogger;

impl EventLogger for ServerEventLogger {
    fn connect(&self, addr: &SocketAddr, id: &str, tx: u64) {
        tracing::info!(addr = %addr, id = %id, tx, "client connected");
    }

    fn disconnect(
        &self,
        addr: &SocketAddr,
        id: &str,
        err: Option<&(dyn std::error::Error + Send + Sync)>,
    ) {
        tracing::info!(addr = %addr, id = %id, error = ?err, "client disconnected");
    }

    fn tcp_request(&self, addr: &SocketAddr, id: &str, req_addr: &str) {
        tracing::debug!(addr = %addr, id = %id, reqAddr = %req_addr, "TCP request");
    }

    fn tcp_error(
        &self,
        addr: &SocketAddr,
        id: &str,
        req_addr: &str,
        err: Option<&(dyn std::error::Error + Send + Sync)>,
    ) {
        if let Some(err) = err {
            tracing::warn!(addr = %addr, id = %id, reqAddr = %req_addr, error = %err, "TCP error");
        } else {
            tracing::debug!(addr = %addr, id = %id, reqAddr = %req_addr, "TCP closed");
        }
    }

    fn udp_request(&self, addr: &SocketAddr, id: &str, session_id: u32, req_addr: &str) {
        tracing::debug!(addr = %addr, id = %id, sessionID = session_id, reqAddr = %req_addr, "UDP request");
    }

    fn udp_error(
        &self,
        addr: &SocketAddr,
        id: &str,
        session_id: u32,
        err: Option<&(dyn std::error::Error + Send + Sync)>,
    ) {
        if let Some(err) = err {
            tracing::warn!(addr = %addr, id = %id, sessionID = session_id, error = %err, "UDP error");
        } else {
            tracing::debug!(addr = %addr, id = %id, sessionID = session_id, "UDP closed");
        }
    }
}

#[derive(Clone)]
struct HickoryHostResolver {
    resolver: TokioResolver,
}

#[async_trait::async_trait]
impl HostResolver for HickoryHostResolver {
    async fn resolve(&self, host: &str) -> io::Result<HostResolveResult> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(match ip {
                IpAddr::V4(v4) => HostResolveResult {
                    ipv4: Some(v4),
                    ipv6: None,
                },
                IpAddr::V6(v6) => HostResolveResult {
                    ipv4: None,
                    ipv6: Some(v6),
                },
            });
        }
        let lookup = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(|err| io::Error::other(format!("dns resolve failed: {err}")))?;
        let mut resolved = HostResolveResult::default();
        for ip in lookup.iter() {
            match ip {
                IpAddr::V4(v4) if resolved.ipv4.is_none() => resolved.ipv4 = Some(v4),
                IpAddr::V6(v6) if resolved.ipv6.is_none() => resolved.ipv6 = Some(v6),
                _ => {}
            }
            if resolved.ipv4.is_some() && resolved.ipv6.is_some() {
                break;
            }
        }
        Ok(resolved)
    }
}

#[derive(Debug)]
struct HickoryNoVerifier;

impl rustls::client::danger::ServerCertVerifier for HickoryNoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

pub async fn run_server(config_path: Option<PathBuf>) -> Result<(), BoxError> {
    info!("server mode");

    let path = resolve_config_path(config_path)?;
    let raw = read_config_file(&path)?;
    let file_cfg: ServerConfigFile = parse_config(&path, &raw)?;

    let listen = if file_cfg.listen.trim().is_empty() {
        ":443"
    } else {
        file_cfg.listen.trim()
    };

    let addr = normalize_listen_addr(listen)?;
    let (tls_cert, tls_key) = load_tls_material(&file_cfg.tls.cert, &file_cfg.tls.key)?;
    let sni_guard = parse_sni_guard(&file_cfg.tls.sni_guard)?;
    let tls_client_ca = build_tls_client_ca(&file_cfg.tls.client_ca)?;
    validate_resolver(&file_cfg.resolver)?;
    let outbound_resolver = build_outbound_resolver(&file_cfg.resolver)?;
    let outbound = build_server_outbound(&file_cfg.outbounds, &file_cfg.acl, outbound_resolver)?;

    let speed_bps = parse_server_bandwidth(&file_cfg.bandwidth.up, "bandwidth.up")?;
    let speed_rx_bps = parse_server_bandwidth(&file_cfg.bandwidth.down, "bandwidth.down")?;
    let obfs_salamander_password = build_server_obfs_password(&file_cfg.obfs)?;
    let udp_idle_timeout = build_udp_idle_timeout(&file_cfg.udp_idle_timeout)?;
    let transport_builder = build_server_transport_builder(&file_cfg.quic)?;

    let authenticator = build_authenticator(&file_cfg.auth)?;

    let event_logger: Arc<dyn EventLogger> = Arc::new(ServerEventLogger);

    let traffic_logger_server = if file_cfg.traffic_stats.listen.trim().is_empty() {
        None
    } else {
        Some(Arc::new(TrafficStatsServer::new(
            file_cfg.traffic_stats.secret.clone(),
        )))
    };

    // Service runtimes: each dedicated single-thread runtime lives until
    // run_server() returns (after server.serve().await? completes).
    let mut service_runtimes: Vec<crate::core::internal::runtime::RyRuntime> = Vec::new();

    if let Some(ts) = &traffic_logger_server {
        let listen = file_cfg.traffic_stats.listen.clone();
        let ts_clone = Arc::clone(ts);
        let rt = crate::core::internal::runtime::RyRuntime::new_no_steal(
            "rysteria-traffic-stats",
        )?;
        rt.handle().spawn(async move {
            tracing::info!(listen = %listen, "traffic stats server up and running");
            let _ = run_traffic_stats_server(&listen, ts_clone).await;
        });
        service_runtimes.push(rt);
    }

    let request_hook = build_sniffer(&file_cfg.sniff)?;

    let base_masq_handler = build_masq_handler(&file_cfg.masquerade)?;
    let quic_masq_handler = base_masq_handler.as_ref().map(|h| {
        Arc::new(MasqHandlerLogWrapper {
            handler: Arc::clone(h),
            quic: true,
        }) as Arc<dyn MasqHandler + Send + Sync>
    });

    if !file_cfg.masquerade.listen_http.trim().is_empty()
        && file_cfg.masquerade.listen_https.trim().is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "having only HTTP server without HTTPS is not supported",
        )
        .into());
    }

    let masq_tls_cert = tls_cert.clone();
    let masq_tls_key = tls_key.clone_key();

    let server = Server::new(ServerConfig {
        authenticator,
        tls_cert,
        tls_key,
        tls_sni_guard: sni_guard,
        addr,
        transport: None,
        transport_builder: Some(transport_builder),
        speed_bps,
        speed_rx_bps,
        ignore_client_bandwidth: file_cfg.ignore_client_bandwidth,
        event_logger: Some(event_logger),
        traffic_logger: traffic_logger_server
            .as_ref()
            .map(|v| Arc::clone(v) as Arc<dyn TrafficLogger>),
        request_hook,
        outbound: Some(outbound),
        masq_handler: quic_masq_handler,
        disable_udp: file_cfg.disable_udp,
        speed_test: file_cfg.speed_test,
        udp_idle_timeout,
        obfs_salamander_password,
        tls_client_ca,
        shard_threads: None,
    })?;

    if let Some(base) = base_masq_handler {
        let http_addr = if file_cfg.masquerade.listen_http.trim().is_empty() {
            None
        } else {
            Some(file_cfg.masquerade.listen_http.clone())
        };
        let https_addr = if file_cfg.masquerade.listen_https.trim().is_empty() {
            None
        } else {
            Some(file_cfg.masquerade.listen_https.clone())
        };

        if http_addr.is_some() || https_addr.is_some() {
            let builder = rustls::ServerConfig::builder();
            let crypto_provider = Arc::clone(builder.crypto_provider());
            let cert_resolver = Arc::new(GuardedCertResolver::new(
                masq_tls_cert,
                masq_tls_key,
                sni_guard,
                &crypto_provider,
            )?);
            let mut tls = builder
                .with_no_client_auth()
                .with_cert_resolver(cert_resolver);
            tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let https_port = https_addr
                .as_deref()
                .map(extract_listen_port)
                .transpose()?
                .unwrap_or(0);

            let tcp_handler: Arc<dyn MasqHandler + Send + Sync> = Arc::new(MasqHandlerLogWrapper {
                handler: Arc::clone(&base),
                quic: false,
            });

            let tcp_server = Arc::new(MasqTCPServer {
                quic_port: server.local_addr().port(),
                https_port,
                handler: tcp_handler,
                tls_config: Arc::new(tls),
                force_https: file_cfg.masquerade.force_https,
            });

            let masq_rt = crate::core::internal::runtime::RyRuntime::new_no_steal(
                "rysteria-masq-tcp",
            )?;
            masq_rt.handle().spawn(async move {
                run_masq_tcp_server(tcp_server, http_addr, https_addr).await;
            });
            service_runtimes.push(masq_rt);
        }
    }

    info!(listen = %server.local_addr(), "server up and running");

    // Run the QUIC accept loop on a dedicated no-steal runtime so that
    // the connection accept path is pinned to a fixed OS thread, consistent
    // with the shard-pinned connection pipeline.
    let quic_rt = crate::core::internal::runtime::RyRuntime::new_no_steal("rysteria-quic-accept")?;
    let (serve_tx, serve_rx) = tokio::sync::oneshot::channel::<Result<(), BoxError>>();
    quic_rt.handle().spawn(async move {
        let _ = serve_tx.send(server.serve().await);
    });
    let result = serve_rx
        .await
        .unwrap_or_else(|_| Err("QUIC accept runtime exited unexpectedly".into()));
    drop(service_runtimes);
    drop(quic_rt);
    result
}

fn normalize_listen_addr(listen: &str) -> Result<std::net::SocketAddr, io::Error> {
    if let Some(port) = listen.strip_prefix(':') {
        let port = port
            .parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid listen port"))?;
        Ok(std::net::SocketAddr::from(([0, 0, 0, 0], port)))
    } else {
        listen.parse::<std::net::SocketAddr>().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid listen address: {e}"),
            )
        })
    }
}

fn extract_listen_port(listen: &str) -> Result<u16, io::Error> {
    if let Some(port) = listen.strip_prefix(':') {
        return port
            .parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid port"));
    }
    let addr = listen
        .parse::<SocketAddr>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid address"))?;
    Ok(addr.port())
}

fn load_tls_material(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    if cert_path.trim().is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "tls.cert is empty").into());
    }
    if key_path.trim().is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "tls.key is empty").into());
    }

    let mut cert_reader = BufReader::new(File::open(Path::new(cert_path))?);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .collect::<Vec<_>>();
    if certs.is_empty() {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "no certificate in tls.cert").into(),
        );
    }

    let mut key_reader = BufReader::new(File::open(Path::new(key_path))?);
    let mut key: Option<PrivateKeyDer<'static>> = None;
    for item in rustls_pemfile::read_all(&mut key_reader) {
        match item? {
            rustls_pemfile::Item::Pkcs1Key(k) => {
                key = Some(PrivateKeyDer::Pkcs1(k));
                break;
            }
            rustls_pemfile::Item::Pkcs8Key(k) => {
                key = Some(PrivateKeyDer::Pkcs8(k));
                break;
            }
            rustls_pemfile::Item::Sec1Key(k) => {
                key = Some(PrivateKeyDer::Sec1(k));
                break;
            }
            _ => {}
        }
    }

    let key = key
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no private key in tls.key"))?;

    Ok((certs, key))
}

fn parse_sni_guard(raw: &str) -> Result<SniGuardMode, BoxError> {
    Ok(SniGuardMode::parse(raw)?)
}

fn build_tls_client_ca(raw: &str) -> Result<Option<rustls::RootCertStore>, BoxError> {
    let path = raw.trim();
    if path.is_empty() {
        return Ok(None);
    }
    let mut reader = BufReader::new(File::open(Path::new(path))?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no certificate in tls.clientCA",
        )
        .into());
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid certificate in tls.clientCA: {err}"),
            )
        })?;
    }
    Ok(Some(roots))
}

fn validate_resolver(cfg: &ServerResolverConfig) -> Result<(), BoxError> {
    let resolver_type = if cfg.resolver_type.trim().is_empty() {
        "system"
    } else {
        cfg.resolver_type.trim()
    };
    match resolver_type.to_ascii_lowercase().as_str() {
        "system" => Ok(()),
        "udp" => validate_resolver_standard("resolver.udp", &cfg.udp),
        "tcp" => validate_resolver_standard("resolver.tcp", &cfg.tcp),
        "tls" | "tcp-tls" => validate_resolver_tls("resolver.tls", &cfg.tls),
        "https" | "http" => validate_resolver_https("resolver.https", &cfg.https),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolver.type must be one of: system, udp, tcp, tls, tcp-tls, https, http",
        )
        .into()),
    }
}

fn build_outbound_resolver(
    cfg: &ServerResolverConfig,
) -> Result<Option<Arc<dyn HostResolver>>, BoxError> {
    fn parse_resolver_timeout(raw: &str) -> Result<Duration, BoxError> {
        if raw.trim().is_empty() {
            Ok(Duration::from_secs(5))
        } else {
            Ok(parse_duration_like(raw.trim())?)
        }
    }

    fn parse_socket_addr_with_default(
        raw: &str,
        default_port: u16,
    ) -> Result<SocketAddr, BoxError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "resolver addr is empty").into(),
            );
        }
        let normalized = if trimmed.parse::<SocketAddr>().is_ok() {
            trimmed.to_string()
        } else if let Some((_, port)) = trimmed.rsplit_once(':') {
            if port.parse::<u16>().is_ok() {
                trimmed.to_string()
            } else if trimmed.contains(':') {
                format!("[{trimmed}]:{default_port}")
            } else {
                format!("{trimmed}:{default_port}")
            }
        } else if trimmed.contains(':') {
            format!("[{trimmed}]:{default_port}")
        } else {
            format!("{trimmed}:{default_port}")
        };
        normalized.to_socket_addrs()?.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "resolver addr unresolved").into()
        })
    }

    fn build_hickory_resolver(
        socket_addr: SocketAddr,
        protocol: DnsProtocol,
        timeout: Duration,
        tls_dns_name: Option<String>,
        http_endpoint: Option<String>,
        insecure: bool,
    ) -> Arc<dyn HostResolver> {
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        if insecure && protocol.is_encrypted() {
            opts.tls_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(HickoryNoVerifier))
                .with_no_client_auth();
        }

        let mut ns = NameServerConfig::new(socket_addr, protocol);
        ns.trust_negative_responses = true;
        ns.tls_dns_name = tls_dns_name;
        ns.http_endpoint = http_endpoint;

        let mut group = NameServerConfigGroup::new();
        group.push(ns);

        let config = HickoryResolverConfig::from_parts(None, vec![], group);
        Arc::new(HickoryHostResolver {
            resolver: TokioResolver::builder_with_config(
                config,
                TokioConnectionProvider::default(),
            )
            .with_options(opts)
            .build(),
        })
    }

    let resolver_type = if cfg.resolver_type.trim().is_empty() {
        "system"
    } else {
        cfg.resolver_type.trim()
    };
    match resolver_type.to_ascii_lowercase().as_str() {
        "system" => Ok(Some(Arc::new(SystemResolver))),
        "udp" => {
            let timeout = parse_resolver_timeout(&cfg.udp.timeout)?;
            let socket_addr = parse_socket_addr_with_default(&cfg.udp.addr, 53)?;
            Ok(Some(build_hickory_resolver(
                socket_addr,
                DnsProtocol::Udp,
                timeout,
                None,
                None,
                false,
            )))
        }
        "tcp" => {
            let timeout = parse_resolver_timeout(&cfg.tcp.timeout)?;
            let socket_addr = parse_socket_addr_with_default(&cfg.tcp.addr, 53)?;
            Ok(Some(build_hickory_resolver(
                socket_addr,
                DnsProtocol::Tcp,
                timeout,
                None,
                None,
                false,
            )))
        }
        "tls" | "tcp-tls" => {
            let timeout = parse_resolver_timeout(&cfg.tls.timeout)?;
            let socket_addr = parse_socket_addr_with_default(&cfg.tls.addr, 853)?;
            let sni = if cfg.tls.sni.trim().is_empty() {
                None
            } else {
                Some(cfg.tls.sni.trim().to_string())
            };
            Ok(Some(build_hickory_resolver(
                socket_addr,
                DnsProtocol::Tls,
                timeout,
                sni,
                None,
                cfg.tls.insecure,
            )))
        }
        "https" | "http" => {
            let timeout = parse_resolver_timeout(&cfg.https.timeout)?;
            let addr = cfg.https.addr.trim();
            let parsed = if addr.starts_with("https://") || addr.starts_with("http://") {
                url::Url::parse(addr).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid resolver.https.addr: {err}"),
                    )
                })?
            } else {
                url::Url::parse(&format!("https://{addr}/dns-query")).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid resolver.https.addr: {err}"),
                    )
                })?
            };
            let host = parsed.host_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "resolver.https.addr has no host",
                )
            })?;
            let port = parsed.port_or_known_default().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "resolver.https.addr has no port",
                )
            })?;
            let socket_addr = parse_socket_addr_with_default(host, port)?;
            let sni = if cfg.https.sni.trim().is_empty() {
                Some(host.to_string())
            } else {
                Some(cfg.https.sni.trim().to_string())
            };
            let endpoint = {
                let path = parsed.path();
                if path.is_empty() || path == "/" {
                    None
                } else {
                    Some(path.to_string())
                }
            };
            Ok(Some(build_hickory_resolver(
                socket_addr,
                DnsProtocol::Https,
                timeout,
                sni,
                endpoint,
                cfg.https.insecure,
            )))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolver.type must be one of: system, udp, tcp, tls, tcp-tls, https, http",
        )
        .into()),
    }
}

fn validate_resolver_standard(
    field: &str,
    cfg: &ServerResolverStandardConfig,
) -> Result<(), BoxError> {
    if cfg.addr.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field}.addr is empty"),
        )
        .into());
    }
    if !cfg.timeout.trim().is_empty() {
        parse_duration_like(cfg.timeout.trim())?;
    }
    Ok(())
}

fn validate_resolver_tls(field: &str, cfg: &ServerResolverTlsConfig) -> Result<(), BoxError> {
    if cfg.addr.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field}.addr is empty"),
        )
        .into());
    }
    if !cfg.timeout.trim().is_empty() {
        parse_duration_like(cfg.timeout.trim())?;
    }
    Ok(())
}

fn validate_resolver_https(field: &str, cfg: &ServerResolverHttpsConfig) -> Result<(), BoxError> {
    if cfg.addr.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field}.addr is empty"),
        )
        .into());
    }
    if !cfg.timeout.trim().is_empty() {
        parse_duration_like(cfg.timeout.trim())?;
    }
    let _ = cfg.sni.as_str();
    let _ = cfg.insecure;
    Ok(())
}

fn build_server_outbound(
    outbounds: &[ServerOutboundConfig],
    acl: &ServerAclConfig,
    resolver: Option<Arc<dyn HostResolver>>,
) -> Result<Arc<dyn PluggableOutbound>, BoxError> {
    if !acl.file.trim().is_empty() && !acl.inline.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "acl.file and acl.inline cannot both be set",
        )
        .into());
    }

    let mut entries = Vec::new();
    for ob in outbounds {
        let name = ob.name.trim();
        if name.is_empty() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "outbounds[].name is empty").into(),
            );
        }
        let outbound = match ob.outbound_type.trim().to_ascii_lowercase().as_str() {
            "" | "direct" => Arc::new(server_config_outbound_direct_to_outbound(
                &ob.direct,
                resolver.clone(),
            )?) as Arc<dyn PluggableOutbound>,
            "socks5" => {
                if ob.socks5.addr.trim().is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("outbound {} socks5.addr is empty", ob.name),
                    )
                    .into());
                }
                Arc::new(Socks5Outbound {
                    addr: ob.socks5.addr.trim().to_string(),
                    username: ob.socks5.username.clone(),
                    password: ob.socks5.password.clone(),
                }) as Arc<dyn PluggableOutbound>
            }
            "http" => {
                if ob.http.url.trim().is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("outbound {} http.url is empty", ob.name),
                    )
                    .into());
                }
                let parsed = url::Url::parse(ob.http.url.trim()).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid outbound {} http.url: {err}", ob.name),
                    )
                })?;
                let scheme = parsed.scheme().to_ascii_lowercase();
                if scheme != "http" && scheme != "https" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "invalid outbound {} http.url scheme: {}",
                            ob.name,
                            parsed.scheme()
                        ),
                    )
                    .into());
                }
                if parsed.host_str().is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("outbound {} http.url has no host", ob.name),
                    )
                    .into());
                }
                let port = parsed.port_or_known_default().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid proxy port")
                })?;
                let proxy_url = if parsed.port().is_none() {
                    let mut fixed = parsed.clone();
                    let _ = fixed.set_port(Some(port));
                    fixed
                } else {
                    parsed.clone()
                };
                let auth_header = if !ob.http.username.is_empty() || !ob.http.password.is_empty() {
                    http_proxy_auth_header(&ob.http.username, &ob.http.password)
                } else if !parsed.username().is_empty() || parsed.password().is_some() {
                    http_proxy_auth_header(parsed.username(), parsed.password().unwrap_or(""))
                } else {
                    None
                };
                Arc::new(HttpOutbound {
                    proxy_url,
                    auth_header,
                    insecure: ob.http.insecure,
                }) as Arc<dyn PluggableOutbound>
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported outbound type: {}", ob.outbound_type),
                )
                .into());
            }
        };
        entries.push(OutboundEntry {
            name: name.to_string(),
            outbound,
        });
    }

    let acl_rules = if !acl.file.trim().is_empty() {
        std::fs::read_to_string(acl.file.trim())?
    } else if !acl.inline.is_empty() {
        acl.inline.join("\n")
    } else {
        String::new()
    };

    if acl_rules.trim().is_empty() {
        if let Some(first) = entries.first() {
            return Ok(Arc::clone(&first.outbound));
        }
        return Ok(Arc::new(DirectOutbound::default().with_resolver(resolver)));
    }

    let geoip_path = if acl.geoip.trim().is_empty() {
        None
    } else {
        Some(acl.geoip.trim())
    };
    let geosite_path = if acl.geosite.trim().is_empty() {
        None
    } else {
        Some(acl.geosite.trim())
    };

    Ok(new_acl_engine_from_string_with_resolver_and_geo(
        &acl_rules,
        entries,
        resolver,
        geoip_path,
        geosite_path,
    )?)
}

fn server_config_outbound_direct_to_outbound(
    cfg: &ServerOutboundDirectConfig,
    resolver: Option<Arc<dyn HostResolver>>,
) -> Result<DirectOutbound, BoxError> {
    let mode = match cfg.mode.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => DirectOutboundMode::Auto,
        "64" => DirectOutboundMode::PreferIpv6,
        "46" => DirectOutboundMode::PreferIpv4,
        "6" => DirectOutboundMode::Ipv6Only,
        "4" => DirectOutboundMode::Ipv4Only,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "outbounds.direct.mode is unsupported",
            )
            .into());
        }
    };
    let bind_has_ip = !cfg.bind_ipv4.trim().is_empty() || !cfg.bind_ipv6.trim().is_empty();
    let bind_has_device = !cfg.bind_device.trim().is_empty();
    if bind_has_ip && bind_has_device {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "outbounds.direct cannot bind both IP and device",
        )
        .into());
    }

    let bind_ipv4 = if cfg.bind_ipv4.trim().is_empty() {
        None
    } else {
        Some(
            cfg.bind_ipv4
                .trim()
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "outbounds.direct.bindIPv4 is invalid",
                    )
                })?,
        )
    };
    let bind_ipv6 = if cfg.bind_ipv6.trim().is_empty() {
        None
    } else {
        Some(
            cfg.bind_ipv6
                .trim()
                .parse::<std::net::Ipv6Addr>()
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "outbounds.direct.bindIPv6 is invalid",
                    )
                })?,
        )
    };

    Ok(DirectOutbound::new(DirectOutboundOptions {
        mode,
        bind_ipv4,
        bind_ipv6,
        bind_device: if cfg.bind_device.trim().is_empty() {
            None
        } else {
            Some(cfg.bind_device.trim().to_string())
        },
        fast_open: cfg.fast_open,
    })
    .with_resolver(resolver))
}

fn build_authenticator(auth_cfg: &ServerAuthConfig) -> Result<Arc<dyn Authenticator>, BoxError> {
    match auth_cfg.auth_type.to_ascii_lowercase().as_str() {
        "password" => {
            if auth_cfg.password.is_empty() {
                return Err(
                    io::Error::new(io::ErrorKind::InvalidInput, "auth.password is empty").into(),
                );
            }
            Ok(Arc::new(PasswordAuthenticator {
                password: auth_cfg.password.clone(),
            }))
        }
        "userpass" => {
            if auth_cfg.userpass.is_empty() {
                return Err(
                    io::Error::new(io::ErrorKind::InvalidInput, "auth.userpass is empty").into(),
                );
            }
            Ok(Arc::new(UserPassAuthenticator::new(
                auth_cfg.userpass.clone(),
            )))
        }
        "http" | "https" => {
            if auth_cfg.http.url.is_empty() {
                return Err(
                    io::Error::new(io::ErrorKind::InvalidInput, "auth.http.url is empty").into(),
                );
            }
            if auth_cfg.http.insecure {
                Ok(Arc::new(HttpAuthenticator::new_insecure(
                    auth_cfg.http.url.clone(),
                )))
            } else {
                Ok(Arc::new(HttpAuthenticator::new(auth_cfg.http.url.clone())))
            }
        }
        "command" | "cmd" => {
            if auth_cfg.command.is_empty() {
                return Err(
                    io::Error::new(io::ErrorKind::InvalidInput, "auth.command is empty").into(),
                );
            }
            Ok(Arc::new(CommandAuthenticator {
                cmd: auth_cfg.command.clone(),
            }))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported auth.type (supported: password, userpass, http, https, command, cmd)",
        )
        .into()),
    }
}

fn build_sniffer(cfg: &SniffConfig) -> Result<Option<Arc<dyn RequestHook>>, BoxError> {
    if !cfg.enable {
        return Ok(None);
    }

    let timeout = if cfg.timeout.trim().is_empty() {
        Duration::from_secs(4)
    } else {
        parse_duration_like(cfg.timeout.trim())?
    };

    let tcp_ports = if cfg.tcp_ports.trim().is_empty() {
        None
    } else {
        Some(PortUnion::parse(cfg.tcp_ports.trim())?)
    };

    let udp_ports = if cfg.udp_ports.trim().is_empty() {
        None
    } else {
        Some(PortUnion::parse(cfg.udp_ports.trim())?)
    };

    Ok(Some(Arc::new(Sniffer {
        timeout,
        rewrite_domain: cfg.rewrite_domain,
        tcp_ports,
        udp_ports,
    })))
}

fn build_server_obfs_password(cfg: &ServerObfsConfig) -> Result<Option<String>, BoxError> {
    let obfs_type = cfg.obfs_type.trim();
    if obfs_type.is_empty() || obfs_type.eq_ignore_ascii_case("plain") {
        return Ok(None);
    }
    if !obfs_type.eq_ignore_ascii_case("salamander") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported obfs.type: {}", cfg.obfs_type),
        )
        .into());
    }
    let password = cfg.salamander.password.trim();
    if password.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "obfs.salamander.password is empty",
        )
        .into());
    }
    SalamanderObfuscator::new(password.as_bytes().to_vec()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid obfs.salamander.password: {e}"),
        )
    })?;
    Ok(Some(cfg.salamander.password.clone()))
}

fn build_masq_handler(
    cfg: &MasqueradeConfig,
) -> Result<Option<Arc<dyn MasqHandler + Send + Sync>>, BoxError> {
    let masq_type = cfg.masq_type.trim().to_ascii_lowercase();

    let base: Arc<dyn MasqHandler + Send + Sync> = match masq_type.as_str() {
        "" | "404" => Arc::new(NotFoundHandler),
        "file" => {
            if cfg.file.dir.trim().is_empty() {
                return Err(
                    io::Error::new(io::ErrorKind::InvalidInput, "empty file directory").into(),
                );
            }
            Arc::new(FileHandler {
                dir: PathBuf::from(cfg.file.dir.clone()),
            })
        }
        "proxy" => {
            if cfg.proxy.url.trim().is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty proxy url").into());
            }
            let uri = http::Uri::from_str(cfg.proxy.url.trim()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid proxy url: {e}"),
                )
            })?;
            let scheme = uri.scheme_str().unwrap_or("");
            if scheme != "http" && scheme != "https" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported protocol scheme \"{scheme}\""),
                )
                .into());
            }
            let mut client_builder = reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(30))
                .timeout(Duration::from_secs(30))
                .tcp_keepalive(Duration::from_secs(30))
                .pool_max_idle_per_host(100)
                .pool_idle_timeout(Duration::from_secs(90))
                .http2_adaptive_window(true);
            if cfg.proxy.insecure {
                client_builder = client_builder.danger_accept_invalid_certs(true);
            }
            let client = client_builder.build()?;
            Arc::new(ProxyHandler {
                upstream: uri,
                rewrite_host: cfg.proxy.rewrite_host,
                client,
            })
        }
        "string" => {
            if cfg.string.content.is_empty() {
                return Err(
                    io::Error::new(io::ErrorKind::InvalidInput, "empty string content").into(),
                );
            }
            if cfg.string.status_code != 0
                && (!(200..=599).contains(&cfg.string.status_code) || cfg.string.status_code == 233)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid status code (must be 200-599, except 233)",
                )
                .into());
            }
            Arc::new(StringHandler {
                content: cfg.string.content.clone(),
                headers: cfg.string.headers.clone(),
                status_code: cfg.string.status_code,
            })
        }
        _ => {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "unsupported masquerade type").into(),
            );
        }
    };

    Ok(Some(base))
}

fn parse_duration_like(raw: &str) -> Result<Duration, BoxError> {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty duration").into());
    }

    let (num, unit) = if let Some(v) = s.strip_suffix("ms") {
        (v, "ms")
    } else if let Some(v) = s.strip_suffix('s') {
        (v, "s")
    } else if let Some(v) = s.strip_suffix('m') {
        (v, "m")
    } else if let Some(v) = s.strip_suffix('h') {
        (v, "h")
    } else {
        (s.as_str(), "s")
    };

    let value = num.trim().parse::<u64>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid duration: {raw}"),
        )
    })?;

    let d = match unit {
        "ms" => Duration::from_millis(value),
        "s" => Duration::from_secs(value),
        "m" => Duration::from_secs(value * 60),
        "h" => Duration::from_secs(value * 3600),
        _ => Duration::from_secs(value),
    };
    Ok(d)
}

/// Parses a bandwidth string and validates the minimum (64KB/s = 65536 bytes/sec).
/// Empty string → 0 (unlimited). Non-zero values below 65536 are rejected.
/// Go: core/server/config.go:84-88
fn parse_server_bandwidth(raw: &str, field: &str) -> Result<u64, BoxError> {
    if raw.trim().is_empty() {
        return Ok(0);
    }
    let bps = parse_bandwidth_bps(raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if bps != 0 && bps < 65_536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must be at least 65536"),
        )
        .into());
    }
    Ok(bps)
}

fn build_udp_idle_timeout(raw: &str) -> Result<Duration, BoxError> {
    let timeout = if raw.trim().is_empty() {
        Duration::from_secs(60)
    } else {
        parse_duration_like(raw)?
    };
    if !(Duration::from_secs(2)..=Duration::from_secs(600)).contains(&timeout) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "udpIdleTimeout must be between 2s and 600s",
        )
        .into());
    }
    Ok(timeout)
}

fn build_server_transport_builder(
    cfg: &ServerQuicConfig,
) -> Result<TransportConfigBuilder, BoxError> {
    let stream_window = resolve_quic_window(
        cfg.init_stream_receive_window,
        cfg.max_stream_receive_window,
        DEFAULT_STREAM_RECEIVE_WINDOW,
        "quic.initStreamReceiveWindow",
        "quic.maxStreamReceiveWindow",
    )?;
    let conn_window = resolve_quic_window(
        cfg.init_conn_receive_window,
        cfg.max_conn_receive_window,
        DEFAULT_CONN_RECEIVE_WINDOW,
        "quic.initConnReceiveWindow",
        "quic.maxConnReceiveWindow",
    )?;
    let max_idle_timeout = if cfg.max_idle_timeout.trim().is_empty() {
        Duration::from_secs(30)
    } else {
        parse_duration_like(&cfg.max_idle_timeout)?
    };
    if !(Duration::from_secs(4)..=Duration::from_secs(120)).contains(&max_idle_timeout) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "quic.maxIdleTimeout must be between 4s and 120s",
        )
        .into());
    }
    let max_incoming_streams = if cfg.max_incoming_streams == 0 {
        1024
    } else {
        cfg.max_incoming_streams
    };
    if max_incoming_streams < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "quic.maxIncomingStreams must be at least 8",
        )
        .into());
    }
    let disable_pmtud = cfg.disable_path_mtu_discovery || DISABLE_PATH_MTU_DISCOVERY;

    Ok(Arc::new(move || {
        let mut transport = quinn::TransportConfig::default();
        transport.initial_mtu(1200);
        // Datagram buffer sizes: use Quinn defaults (approx 1.2 MiB receive, 1 MiB send).
        // Setting these to MAX_DATAGRAM_FRAME_SIZE (1200) confuses per-packet MTU
        // with transport buffer capacity, silently dropping fragmented UDP messages.
        if disable_pmtud {
            transport.mtu_discovery_config(None);
        }
        if let Ok(v) = quinn::VarInt::from_u64(stream_window) {
            transport.stream_receive_window(v);
        }
        if let Ok(v) = quinn::VarInt::from_u64(conn_window) {
            transport.receive_window(v);
        }
        if let Ok(v) = quinn::VarInt::from_u64(max_incoming_streams) {
            transport.max_concurrent_bidi_streams(v);
        }
        if let Ok(timeout) = max_idle_timeout.try_into() {
            transport.max_idle_timeout(Some(timeout));
        }
        transport
    }))
}

fn resolve_quic_window(
    init: u64,
    max: u64,
    default: u64,
    init_field: &str,
    max_field: &str,
) -> Result<u64, BoxError> {
    if init != 0 && init < 16_384 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{init_field} must be at least 16384"),
        )
        .into());
    }
    if max != 0 && max < 16_384 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{max_field} must be at least 16384"),
        )
        .into());
    }
    if init != 0 && max != 0 && init > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{init_field} must not exceed {max_field}"),
        )
        .into());
    }
    if max != 0 {
        Ok(max)
    } else if init != 0 {
        Ok(init)
    } else {
        Ok(default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_idle_timeout_defaults_to_60s() {
        let timeout = build_udp_idle_timeout("").unwrap();
        assert_eq!(timeout, Duration::from_secs(60));
    }

    #[test]
    fn udp_idle_timeout_range_validation() {
        assert!(build_udp_idle_timeout("1s").is_err());
        assert!(build_udp_idle_timeout("601s").is_err());
        assert!(build_udp_idle_timeout("60s").is_ok());
    }

    #[test]
    fn server_bandwidth_min_validation() {
        // empty → 0 (unlimited), always OK
        assert_eq!(parse_server_bandwidth("", "bandwidth.up").unwrap(), 0);
        // 512kbps = 64000 bytes/sec < 65536 → error
        assert!(parse_server_bandwidth("512kbps", "bandwidth.up").is_err());
        // 1mbps = 125000 bytes/sec >= 65536 → OK
        assert!(parse_server_bandwidth("1mbps", "bandwidth.up").is_ok());
        // 100mbps → well above minimum → OK
        assert!(parse_server_bandwidth("100mbps", "bandwidth.down").is_ok());
        // error message includes the field name
        let err = parse_server_bandwidth("512kbps", "bandwidth.down").unwrap_err();
        assert!(err.to_string().contains("bandwidth.down"));
    }

    #[test]
    fn server_quic_max_incoming_validation() {
        let cfg = ServerQuicConfig {
            max_incoming_streams: 4,
            ..ServerQuicConfig::default()
        };
        assert!(build_server_transport_builder(&cfg).is_err());
    }

    #[test]
    fn toml_server_minimal_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[tls]
cert = "/path/cert.pem"
key = "/path/key.pem"

[auth]
type = "password"
password = "secret"
"#;
        let path = std::path::Path::new("server.toml");
        let cfg: ServerConfigFile = crate::app::cmd::parse_config(path, toml).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:443");
        assert_eq!(cfg.tls.cert, "/path/cert.pem");
        assert_eq!(cfg.tls.key, "/path/key.pem");
        assert_eq!(cfg.auth.auth_type, "password");
        assert_eq!(cfg.auth.password, "secret");
    }

    #[test]
    fn toml_server_outbounds_array_of_tables() {
        let toml = r#"
listen = ":443"

[[outbounds]]
name = "direct-1"
type = "direct"

[outbounds.direct]
mode = "auto"

[[outbounds]]
name = "socks-proxy"
type = "socks5"

[outbounds.socks5]
addr = "127.0.0.1:1080"
username = "user"
password = "pass"
"#;
        let path = std::path::Path::new("server.toml");
        let cfg: ServerConfigFile = crate::app::cmd::parse_config(path, toml).unwrap();
        assert_eq!(cfg.outbounds.len(), 2);
        assert_eq!(cfg.outbounds[0].name, "direct-1");
        assert_eq!(cfg.outbounds[0].outbound_type, "direct");
        assert_eq!(cfg.outbounds[0].direct.mode, "auto");
        assert_eq!(cfg.outbounds[1].name, "socks-proxy");
        assert_eq!(cfg.outbounds[1].socks5.addr, "127.0.0.1:1080");
    }

    #[test]
    fn toml_server_auth_userpass_hashmap() {
        let toml = r#"
[auth]
type = "userpass"

[auth.userpass]
alice = "pass1"
bob = "pass2"
"#;
        let path = std::path::Path::new("server.toml");
        let cfg: ServerConfigFile = crate::app::cmd::parse_config(path, toml).unwrap();
        assert_eq!(cfg.auth.auth_type, "userpass");
        assert_eq!(cfg.auth.userpass.get("alice").unwrap(), "pass1");
        assert_eq!(cfg.auth.userpass.get("bob").unwrap(), "pass2");
    }

    #[test]
    fn toml_server_masquerade_string_headers() {
        let toml = r#"
[masquerade]
type = "string"

[masquerade.string]
content = "hello"
statusCode = 200

[masquerade.string.headers]
content-type = "text/plain"
x-custom = "value"
"#;
        let path = std::path::Path::new("server.toml");
        let cfg: ServerConfigFile = crate::app::cmd::parse_config(path, toml).unwrap();
        assert_eq!(cfg.masquerade.masq_type, "string");
        assert_eq!(cfg.masquerade.string.content, "hello");
        assert_eq!(cfg.masquerade.string.status_code, 200);
        assert_eq!(
            cfg.masquerade.string.headers.get("content-type").unwrap(),
            "text/plain"
        );
    }
}
