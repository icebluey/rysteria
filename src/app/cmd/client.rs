use std::error::Error;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::app::cmd::{BoxError, parse_bandwidth_bps, read_config_file, resolve_config_path};
use crate::app::internal::forwarding::{TCPTunnel, UDPTunnel};
use crate::app::internal::proxymux;
use crate::app::internal::sockopts::{SocketOptions, UnsupportedError};
use crate::app::internal::socks5;
use crate::app::internal::{forwarding, http, redirect, tproxy, tun};
use crate::core::client::{
    Client, ClientConfig, ClientIdentity, ClientObfsConfig, ClientPacketTransport, ClientTlsConfig,
    HandshakeInfo, ReconnectableClient, UdpSocketFactory,
};
use crate::core::internal::pmtud::DISABLE_PATH_MTU_DISCOVERY;
use crate::core::internal::protocol::{
    DEFAULT_CONN_RECEIVE_WINDOW, DEFAULT_STREAM_RECEIVE_WINDOW, MAX_DATAGRAM_FRAME_SIZE,
};
use crate::extras::transport::udphop::{
    DEFAULT_HOP_INTERVAL, MIN_HOP_INTERVAL, resolve_udp_hop_addrs,
};

const SPEEDTEST_DEST: &str = "@speedtest:0";
const SPEEDTEST_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct SpeedtestArgs {
    pub skip_download: bool,
    pub skip_upload: bool,
    /// Duration for each direction in time-based mode.
    pub duration: Duration,
    /// None = time-based mode; Some(n) = size-based mode with exactly n bytes.
    pub data_size: Option<u32>,
    pub use_bytes: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct ClientConfigFile {
    server: String,
    auth: String,
    transport: ClientTransportConfig,
    obfs: ClientObfsConfigFile,
    tls: ClientTlsConfigFile,
    quic: ClientQuicConfig,
    bandwidth: ClientBandwidthConfig,
    #[serde(rename = "fastOpen")]
    fast_open: bool,
    lazy: bool,
    socks5: Option<Socks5Config>,
    http: Option<HttpConfig>,
    #[serde(rename = "tcpForwarding")]
    tcp_forwarding: Vec<TcpForwardingEntry>,
    #[serde(rename = "udpForwarding")]
    udp_forwarding: Vec<UdpForwardingEntry>,
    #[serde(rename = "tcpTProxy")]
    tcp_tproxy: Option<TcpTProxyConfig>,
    #[serde(rename = "udpTProxy")]
    udp_tproxy: Option<UdpTProxyConfig>,
    #[serde(rename = "tcpRedirect")]
    tcp_redirect: Option<TcpRedirectConfig>,
    tun: Option<TunModeConfig>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct ClientTransportConfig {
    #[serde(rename = "type")]
    transport_type: String,
    udp: ClientTransportUdpConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct ClientTransportUdpConfig {
    #[serde(
        rename = "hopInterval",
        default,
        deserialize_with = "deserialize_opt_duration"
    )]
    hop_interval: Option<Duration>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct ClientObfsConfigFile {
    #[serde(rename = "type")]
    obfs_type: String,
    salamander: ClientObfsSalamanderConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct ClientObfsSalamanderConfig {
    password: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct ClientTlsConfigFile {
    sni: String,
    insecure: bool,
    #[serde(rename = "pinSHA256")]
    pin_sha256: String,
    ca: String,
    #[serde(rename = "clientCertificate")]
    client_certificate: String,
    #[serde(rename = "clientKey")]
    client_key: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct ClientBandwidthConfig {
    up: String,
    down: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct ClientQuicConfig {
    #[serde(rename = "initStreamReceiveWindow")]
    init_stream_receive_window: u64,
    #[serde(rename = "maxStreamReceiveWindow")]
    max_stream_receive_window: u64,
    #[serde(rename = "initConnReceiveWindow")]
    init_conn_receive_window: u64,
    #[serde(rename = "maxConnReceiveWindow")]
    max_conn_receive_window: u64,
    #[serde(
        rename = "maxIdleTimeout",
        default,
        deserialize_with = "deserialize_opt_duration"
    )]
    max_idle_timeout: Option<Duration>,
    #[serde(
        rename = "keepAlivePeriod",
        default,
        deserialize_with = "deserialize_opt_duration"
    )]
    keep_alive_period: Option<Duration>,
    #[serde(rename = "disablePathMTUDiscovery")]
    disable_path_mtu_discovery: bool,
    sockopts: ClientQuicSockoptsConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct ClientQuicSockoptsConfig {
    #[serde(rename = "bindInterface")]
    bind_interface: Option<String>,
    fwmark: Option<u32>,
    #[serde(rename = "fdControlUnixSocket")]
    fd_control_unix_socket: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct Socks5Config {
    listen: String,
    username: String,
    password: String,
    #[serde(rename = "disableUDP")]
    disable_udp: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct HttpConfig {
    listen: String,
    username: String,
    password: String,
    realm: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct TcpForwardingEntry {
    listen: String,
    remote: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct UdpForwardingEntry {
    listen: String,
    remote: String,
    #[serde(default, deserialize_with = "deserialize_opt_duration")]
    timeout: Option<Duration>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct TcpTProxyConfig {
    listen: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct UdpTProxyConfig {
    listen: String,
    #[serde(default, deserialize_with = "deserialize_opt_duration")]
    timeout: Option<Duration>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct TcpRedirectConfig {
    listen: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct TunModeConfig {
    name: String,
    mtu: u32,
    #[serde(default, deserialize_with = "deserialize_opt_duration")]
    timeout: Option<Duration>,
    address: Option<TunAddressConfig>,
    route: Option<TunRouteConfig>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct TunAddressConfig {
    ipv4: String,
    ipv6: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
struct TunRouteConfig {
    strict: bool,
    ipv4: Vec<String>,
    ipv6: Vec<String>,
    #[serde(rename = "ipv4Exclude")]
    ipv4_exclude: Vec<String>,
    #[serde(rename = "ipv6Exclude")]
    ipv6_exclude: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DurationRepr {
    Number(u64),
    Text(String),
}

fn parse_duration_text(s: &str) -> Result<Duration, String> {
    let v = s.trim();
    if v.is_empty() {
        return Err("empty duration".to_string());
    }
    if let Ok(sec) = v.parse::<u64>() {
        return Ok(Duration::from_secs(sec));
    }
    let (num, unit) = if let Some(x) = v.strip_suffix("ms") {
        (x.trim(), "ms")
    } else if let Some(x) = v.strip_suffix('s') {
        (x.trim(), "s")
    } else if let Some(x) = v.strip_suffix('m') {
        (x.trim(), "m")
    } else if let Some(x) = v.strip_suffix('h') {
        (x.trim(), "h")
    } else {
        return Err(format!("unsupported duration unit: {v}"));
    };
    let n = num
        .parse::<u64>()
        .map_err(|_| format!("invalid duration value: {v}"))?;
    let d = match unit {
        "ms" => Duration::from_millis(n),
        "s" => Duration::from_secs(n),
        "m" => Duration::from_secs(n.saturating_mul(60)),
        "h" => Duration::from_secs(n.saturating_mul(3600)),
        _ => return Err(format!("unsupported duration unit: {v}")),
    };
    Ok(d)
}

fn deserialize_opt_duration<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<DurationRepr>::deserialize(deserializer)?;
    match raw {
        None => Ok(None),
        Some(DurationRepr::Number(n)) => Ok(Some(Duration::from_secs(n))),
        Some(DurationRepr::Text(s)) => parse_duration_text(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

pub async fn run_client(config_path: Option<PathBuf>) -> Result<(), BoxError> {
    info!("client mode");

    let path = resolve_config_path(config_path)?;
    let raw = read_config_file(&path)?;
    let cfg: ClientConfigFile = serde_saphyr::from_str(&raw)?;

    let shared_cfg = Arc::new(cfg.clone());
    let config_func_cfg = Arc::clone(&shared_cfg);
    let client = Arc::new(
        ReconnectableClient::new(
            move || build_client_config(&config_func_cfg),
            Some(|_client, info: &HandshakeInfo, count| {
                info!(
                    udpEnabled = info.udp_enabled,
                    tx = info.tx,
                    count,
                    "connected to server"
                );
            }),
            cfg.lazy,
        )
        .await?,
    );

    let mut modes = Vec::<(String, tokio::task::JoinHandle<Result<(), BoxError>>)>::new();

    if let (Some(socks_cfg), Some(http_cfg)) = (&cfg.socks5, &cfg.http) {
        if socks_cfg.listen == http_cfg.listen && !socks_cfg.listen.is_empty() {
            let c = Arc::clone(&client);
            let socks_cfg = socks_cfg.clone();
            let http_cfg = http_cfg.clone();
            modes.push((
                "Proxy mux".to_string(),
                tokio::spawn(async move { run_mux_mode(socks_cfg, http_cfg, c).await }),
            ));
        } else {
            let c = Arc::clone(&client);
            let s = socks_cfg.clone();
            modes.push((
                "SOCKS5 server".to_string(),
                tokio::spawn(async move { run_socks5(s, c).await }),
            ));

            let c = Arc::clone(&client);
            let h = http_cfg.clone();
            modes.push((
                "HTTP proxy server".to_string(),
                tokio::spawn(async move { run_http(h, c).await }),
            ));
        }
    } else {
        if let Some(socks_cfg) = cfg.socks5.clone() {
            let c = Arc::clone(&client);
            modes.push((
                "SOCKS5 server".to_string(),
                tokio::spawn(async move { run_socks5(socks_cfg, c).await }),
            ));
        }
        if let Some(http_cfg) = cfg.http.clone() {
            let c = Arc::clone(&client);
            modes.push((
                "HTTP proxy server".to_string(),
                tokio::spawn(async move { run_http(http_cfg, c).await }),
            ));
        }
    }

    if !cfg.tcp_forwarding.is_empty() {
        let c = Arc::clone(&client);
        let entries = cfg.tcp_forwarding.clone();
        modes.push((
            "TCP forwarding".to_string(),
            tokio::spawn(async move { run_tcp_forwarding(entries, c).await }),
        ));
    }

    if !cfg.udp_forwarding.is_empty() {
        let c = Arc::clone(&client);
        let entries = cfg.udp_forwarding.clone();
        modes.push((
            "UDP forwarding".to_string(),
            tokio::spawn(async move { run_udp_forwarding(entries, c).await }),
        ));
    }

    if let Some(tp) = cfg.tcp_tproxy.clone() {
        if tp.listen.trim().is_empty() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "tcpTProxy.listen is empty").into(),
            );
        }
        let c = Arc::clone(&client);
        modes.push((
            "TCP transparent proxy".to_string(),
            tokio::spawn(async move { run_tcp_tproxy(tp, c).await }),
        ));
    }

    if let Some(up) = cfg.udp_tproxy.clone() {
        if up.listen.trim().is_empty() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "udpTProxy.listen is empty").into(),
            );
        }
        let c = Arc::clone(&client);
        modes.push((
            "UDP transparent proxy".to_string(),
            tokio::spawn(async move { run_udp_tproxy(up, c).await }),
        ));
    }

    if let Some(rd) = cfg.tcp_redirect.clone() {
        if rd.listen.trim().is_empty() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "tcpRedirect.listen is empty").into(),
            );
        }
        let c = Arc::clone(&client);
        modes.push((
            "TCP redirect".to_string(),
            tokio::spawn(async move { run_tcp_redirect(rd, c).await }),
        ));
    }

    if let Some(tun_cfg) = cfg.tun.clone() {
        if tun_cfg.name.trim().is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "tun.name is empty").into());
        }
        let c = Arc::clone(&client);
        modes.push((
            "TUN".to_string(),
            tokio::spawn(async move { run_tun(tun_cfg, c).await }),
        ));
    }

    if modes.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no mode specified").into());
    }

    let (tx, mut rx) = mpsc::channel::<(String, Result<(), BoxError>)>(modes.len());
    for (name, handle) in modes {
        let tx = tx.clone();
        tokio::spawn(async move {
            let result = match handle.await {
                Ok(r) => r,
                Err(err) => Err(Box::new(io::Error::other(err.to_string())) as BoxError),
            };
            let _ = tx.send((name, result)).await;
        });
    }
    drop(tx);

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("received signal, shutting down gracefully");
            let _ = client.close().await;
            Ok(())
        }
        msg = rx.recv() => {
            let _ = client.close().await;
            match msg {
                Some((name, Ok(()))) => {
                    info!(mode = %name, "mode exited");
                    Ok(())
                }
                Some((name, Err(err))) => {
                    Err(io::Error::other(format!("failed to run {name}: {err}")).into())
                }
                None => Ok(()),
            }
        }
    }
}

pub async fn run_ping(config_path: Option<PathBuf>, addr: String) -> Result<(), BoxError> {
    info!("ping mode");

    let path = resolve_config_path(config_path)?;
    let raw = read_config_file(&path)?;
    let cfg: ClientConfigFile = serde_saphyr::from_str(&raw)?;
    let core_cfg = build_client_config(&Arc::new(cfg))?;

    let (client, info0) = Client::connect(core_cfg).await?;
    info!(
        udpEnabled = info0.udp_enabled,
        tx = info0.tx,
        "connected to server"
    );

    info!(addr = %addr, "connecting");
    let start = tokio::time::Instant::now();
    let _conn = client.tcp(&addr).await?;
    info!(time = %format!("{:?}", start.elapsed()), "connected");

    client.close();
    Ok(())
}

pub async fn run_speedtest(
    config_path: Option<PathBuf>,
    args: SpeedtestArgs,
) -> Result<(), BoxError> {
    info!("speed test mode");

    let path = resolve_config_path(config_path)?;
    let raw = read_config_file(&path)?;
    let cfg: ClientConfigFile = serde_saphyr::from_str(&raw)?;
    let core_cfg = build_client_config(&Arc::new(cfg))?;

    let (client, info0) = Client::connect(core_cfg).await?;
    info!(
        udpEnabled = info0.udp_enabled,
        tx = info0.tx,
        "connected to server"
    );

    let run = async {
        if !args.skip_download {
            run_download_test(&client, args.data_size, args.duration, args.use_bytes).await?;
            info!("download test complete");
        }
        if !args.skip_upload {
            run_upload_test(&client, args.data_size, args.duration, args.use_bytes).await?;
            info!("upload test complete");
        }
        Ok::<(), BoxError>(())
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("received signal, shutting down gracefully");
        }
        res = run => {
            res?;
            info!("speed test complete");
        }
    }

    client.close();
    Ok(())
}

fn build_client_config(cfg: &Arc<ClientConfigFile>) -> Result<ClientConfig, BoxError> {
    let mut effective = (**cfg).clone();
    apply_hysteria2_uri_overrides(&mut effective)?;

    let resolved_server = resolve_server_endpoint(&effective.server, &effective.transport)?;
    let bandwidth_tx = if effective.bandwidth.up.trim().is_empty() {
        0
    } else {
        parse_bandwidth_bps(&effective.bandwidth.up)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
    };
    let bandwidth_rx = if effective.bandwidth.down.trim().is_empty() {
        0
    } else {
        parse_bandwidth_bps(&effective.bandwidth.down)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
    };

    let tls = build_tls_config(&effective.tls)?;
    let obfs = build_client_obfs(&effective.obfs)?;
    let transport = build_client_transport_config(&effective.quic)?;
    let udp_socket_factory = build_udp_socket_factory(&effective.quic.sockopts)?;

    Ok(ClientConfig {
        auth: effective.auth.clone(),
        server_addr: resolved_server.server_addr,
        server_name: if effective.tls.sni.is_empty() {
            resolved_server.server_name
        } else {
            effective.tls.sni.clone()
        },
        tls,
        bandwidth_tx,
        bandwidth_rx,
        transport: Some(transport),
        udp_socket_factory,
        packet_transport: resolved_server.packet_transport,
        obfs,
        fast_open: effective.fast_open,
        persistent_tunnel: true,
        tunnel_keepalive_secs: 25,
        conn_send_budget: None,
    })
}

fn build_client_transport_config(
    cfg: &ClientQuicConfig,
) -> Result<quinn::TransportConfig, BoxError> {
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
    let max_idle_timeout = cfg.max_idle_timeout.unwrap_or(Duration::from_secs(30));
    if !(Duration::from_secs(4)..=Duration::from_secs(120)).contains(&max_idle_timeout) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "quic.maxIdleTimeout must be between 4s and 120s",
        )
        .into());
    }
    let keep_alive_period = cfg.keep_alive_period.unwrap_or(Duration::from_secs(10));
    if !(Duration::from_secs(2)..=Duration::from_secs(60)).contains(&keep_alive_period) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "quic.keepAlivePeriod must be between 2s and 60s",
        )
        .into());
    }

    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1200);
    transport.datagram_receive_buffer_size(Some(MAX_DATAGRAM_FRAME_SIZE as usize));
    transport.datagram_send_buffer_size(MAX_DATAGRAM_FRAME_SIZE as usize);
    if cfg.disable_path_mtu_discovery || DISABLE_PATH_MTU_DISCOVERY {
        transport.mtu_discovery_config(None);
    }
    if let Ok(v) = quinn::VarInt::from_u64(stream_window) {
        transport.stream_receive_window(v);
    }
    if let Ok(v) = quinn::VarInt::from_u64(conn_window) {
        transport.receive_window(v);
    }
    if let Ok(timeout) = max_idle_timeout.try_into() {
        transport.max_idle_timeout(Some(timeout));
    }
    transport.keep_alive_interval(Some(keep_alive_period));
    Ok(transport)
}

fn build_udp_socket_factory(
    cfg: &ClientQuicSockoptsConfig,
) -> Result<Option<UdpSocketFactory>, BoxError> {
    let options = SocketOptions {
        bind_interface: cfg.bind_interface.clone(),
        fwmark: cfg.fwmark,
        fd_control_unix_socket: cfg.fd_control_unix_socket.clone(),
    };
    options.check_supported().map_err(|err| {
        let field = match err {
            UnsupportedError {
                field: "bindInterface",
            } => "quic.sockopts.bindInterface",
            UnsupportedError { field: "fwmark" } => "quic.sockopts.fwmark",
            UnsupportedError {
                field: "fdControlUnixSocket",
            } => "quic.sockopts.fdControlUnixSocket",
            UnsupportedError { field } => field,
        };
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} is unsupported on this platform"),
        )
    })?;
    if options.bind_interface.is_none()
        && options.fwmark.is_none()
        && options.fd_control_unix_socket.is_none()
    {
        return Ok(None);
    }
    let options = Arc::new(options);
    let factory: UdpSocketFactory = Arc::new(move |prefer_ipv6: bool| {
        let bind_addr = if prefer_ipv6 {
            std::net::SocketAddr::from(([0u16; 8], 0))
        } else {
            std::net::SocketAddr::from(([0, 0, 0, 0], 0))
        };
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        options.apply_to_udp_socket(&socket)?;
        Ok(socket)
    });
    Ok(Some(factory))
}

#[derive(Debug, Default)]
struct ParsedHy2Uri {
    server: String,
    auth: Option<String>,
    obfs: Option<String>,
    obfs_password: Option<String>,
    sni: Option<String>,
    insecure: Option<bool>,
    pin_sha256: Option<String>,
}

fn apply_hysteria2_uri_overrides(cfg: &mut ClientConfigFile) -> Result<(), BoxError> {
    let Some(uri) = parse_hysteria2_uri(&cfg.server)? else {
        return Ok(());
    };
    cfg.server = uri.server;
    if let Some(auth) = uri.auth {
        cfg.auth = auth;
    }
    if let Some(obfs) = uri.obfs {
        cfg.obfs.obfs_type = obfs.clone();
        if obfs.eq_ignore_ascii_case("salamander") {
            cfg.obfs.salamander.password = uri.obfs_password.unwrap_or_default();
        }
    }
    if let Some(sni) = uri.sni {
        cfg.tls.sni = sni;
    }
    if let Some(insecure) = uri.insecure {
        cfg.tls.insecure = insecure;
    }
    if let Some(pin) = uri.pin_sha256 {
        cfg.tls.pin_sha256 = pin;
    }
    Ok(())
}

fn parse_hysteria2_uri(raw: &str) -> Result<Option<ParsedHy2Uri>, BoxError> {
    let trimmed = raw.trim();
    let rest = if let Some(v) = trimmed.strip_prefix("hysteria2://") {
        v
    } else if let Some(v) = trimmed.strip_prefix("hy2://") {
        v
    } else {
        return Ok(None);
    };
    let rest = rest.split('#').next().unwrap_or(rest);
    let (authority_and_path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let authority = authority_and_path
        .split_once('/')
        .map(|(a, _)| a)
        .unwrap_or(authority_and_path);
    if authority.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid hysteria2 URI: empty authority",
        )
        .into());
    }

    let (auth, host_port_raw) = if let Some((userinfo, host_port)) = authority.rsplit_once('@') {
        if userinfo.is_empty() {
            (None, host_port)
        } else if let Some((user, pass)) = userinfo.split_once(':') {
            (Some(format!("{user}:{pass}")), host_port)
        } else {
            (Some(userinfo.to_string()), host_port)
        }
    } else {
        (None, authority)
    };
    if host_port_raw.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid hysteria2 URI: empty host",
        )
        .into());
    }
    let server = if has_port_spec(host_port_raw) {
        host_port_raw.to_string()
    } else if host_port_raw.starts_with('[') && host_port_raw.ends_with(']') {
        format!("{host_port_raw}:443")
    } else if host_port_raw.contains(':') {
        format!("[{host_port_raw}]:443")
    } else {
        format!("{host_port_raw}:443")
    };

    let mut result = ParsedHy2Uri {
        server,
        auth,
        ..ParsedHy2Uri::default()
    };
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "obfs" => result.obfs = Some(value.to_string()),
            "obfs-password" => result.obfs_password = Some(value.to_string()),
            "sni" => result.sni = Some(value.to_string()),
            "pinSHA256" => result.pin_sha256 = Some(value.to_string()),
            "insecure" => {
                let v = parse_bool_like(value.as_ref()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid hysteria2 URI query: insecure must be a boolean",
                    )
                })?;
                result.insecure = Some(v);
            }
            _ => {}
        }
    }
    Ok(Some(result))
}

fn has_port_spec(host_port: &str) -> bool {
    if let Some(rest) = host_port.strip_prefix('[') {
        if let Some(idx) = rest.find(']') {
            return rest[idx + 1..].starts_with(':');
        }
        return false;
    }
    host_port.rsplit_once(':').is_some()
}

fn parse_bool_like(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "t" | "true" | "y" | "yes" => Some(true),
        "0" | "f" | "false" | "n" | "no" => Some(false),
        _ => None,
    }
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

fn build_tls_config(cfg: &ClientTlsConfigFile) -> Result<ClientTlsConfig, BoxError> {
    let client_identity = load_client_identity(&cfg.client_certificate, &cfg.client_key)?;
    if cfg.insecure {
        return Ok(ClientTlsConfig::InsecureSkipVerify { client_identity });
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if !cfg.ca.trim().is_empty() {
        let mut ca_reader = io::BufReader::new(std::fs::File::open(&cfg.ca)?);
        let certs = rustls_pemfile::certs(&mut ca_reader).collect::<Result<Vec<_>, _>>()?;
        let (valid, _invalid) = roots.add_parsable_certificates(certs);
        if valid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "failed to parse CA certificate",
            )
            .into());
        }
    }

    Ok(ClientTlsConfig::RootCerts {
        roots,
        pin_sha256: parse_cert_pin(&cfg.pin_sha256)?,
        client_identity,
    })
}

fn parse_cert_pin(value: &str) -> Result<Option<[u8; 32]>, BoxError> {
    let normalized: String = value
        .chars()
        .filter(|c| *c != ':' && *c != '-' && !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if normalized.is_empty() {
        return Ok(None);
    }
    if normalized.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls.pinSHA256 must be 64 hex characters",
        )
        .into());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in normalized.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls.pinSHA256"))?;
        out[i] = u8::from_str_radix(hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls.pinSHA256"))?;
    }
    Ok(Some(out))
}

fn load_client_identity(
    cert_path: &str,
    key_path: &str,
) -> Result<Option<ClientIdentity>, BoxError> {
    let has_cert = !cert_path.trim().is_empty();
    let has_key = !key_path.trim().is_empty();
    if !has_cert && !has_key {
        return Ok(None);
    }
    if !has_cert || !has_key {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls.clientCertificate and tls.clientKey must be set together",
        )
        .into());
    }

    let mut cert_reader = io::BufReader::new(std::fs::File::open(cert_path)?);
    let cert_chain = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    if cert_chain.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no certificate in tls.clientCertificate",
        )
        .into());
    }

    let mut key_reader = io::BufReader::new(std::fs::File::open(key_path)?);
    let mut key = None;
    for item in rustls_pemfile::read_all(&mut key_reader) {
        match item? {
            rustls_pemfile::Item::Pkcs1Key(k) => {
                key = Some(rustls::pki_types::PrivateKeyDer::Pkcs1(k));
                break;
            }
            rustls_pemfile::Item::Pkcs8Key(k) => {
                key = Some(rustls::pki_types::PrivateKeyDer::Pkcs8(k));
                break;
            }
            rustls_pemfile::Item::Sec1Key(k) => {
                key = Some(rustls::pki_types::PrivateKeyDer::Sec1(k));
                break;
            }
            _ => {}
        }
    }
    let key = key.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "no private key in tls.clientKey",
        )
    })?;

    Ok(Some(ClientIdentity { cert_chain, key }))
}

/// Spawns a ticker task that logs interval throughput every second.
///
/// Returns (byte_counter, task_handle). The I/O loop increments byte_counter
/// via fetch_add; the ticker swaps it atomically, computes progress%, and logs.
/// Call task_handle.abort() when I/O is complete.
///
/// total_size: Some(n) = size-based (progress by bytes); None = time-based.
/// total_dur:  Some(d) = time-based (progress by elapsed); None = size-based.
fn start_progress_reporter(
    use_bytes: bool,
    total_size: Option<u64>,
    total_dur: Option<Duration>,
    label: &'static str,
) -> (Arc<AtomicU64>, tokio::task::JoinHandle<()>) {
    let counter = Arc::new(AtomicU64::new(0));
    let c = counter.clone();
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut cumulative: u64 = 0;
        let test_start = Instant::now();
        let mut last_tick = Instant::now();
        loop {
            ticker.tick().await;
            let now = Instant::now();
            let interval_dur = now.duration_since(last_tick);
            last_tick = now;
            let bytes = c.swap(0, Ordering::Relaxed);
            cumulative += bytes;
            let progress = match (total_size, total_dur) {
                (Some(sz), _) if sz > 0 => cumulative as f64 / sz as f64 * 100.0,
                (_, Some(dur)) => {
                    test_start.elapsed().as_secs_f64() / dur.as_secs_f64() * 100.0
                }
                _ => 0.0,
            };
            info!(
                bytes,
                progress = %format!("{progress:.1}%"),
                speed = %format_speed(bytes, interval_dur, use_bytes),
                "{label}",
            );
        }
    });
    (counter, handle)
}

async fn run_download_test(
    client: &Client,
    data_size: Option<u32>,
    duration: Duration,
    use_bytes: bool,
) -> Result<(), BoxError> {
    let is_time_based = data_size.is_none();
    let req_size = if is_time_based { u32::MAX } else { data_size.unwrap() };

    info!(
        mode = if is_time_based { "time-based" } else { "size-based" },
        "performing download test"
    );

    let mut conn = client.tcp(SPEEDTEST_DEST).await.map_err(|err| {
        io::Error::other(format!(
            "failed to connect (server may not support speed test): {err}"
        ))
    })?;

    write_download_request(&mut conn, req_size).await?;
    let (ok, msg) = read_status_message(&mut conn).await?;
    if !ok {
        return Err(io::Error::other(format!("server rejected download request: {msg}")).into());
    }

    let (counter, progress_handle) = start_progress_reporter(
        use_bytes,
        data_size.map(|s| s as u64),
        if is_time_based { Some(duration) } else { None },
        "downloading",
    );

    let mut buf = vec![0u8; SPEEDTEST_CHUNK_SIZE];
    let total_start = Instant::now();
    let mut total_bytes: u64 = 0;

    // Two modes share the same handle; only one branch runs per invocation.
    // The async block borrows conn/buf/counter directly — no intermediate allocation.
    let io_result: io::Result<()> = if is_time_based {
        // Time-based: stream until deadline fires (or server closes early).
        match tokio::time::timeout(duration, async {
            loop {
                let n = conn.read(&mut buf).await?;
                if n == 0 {
                    break; // server closed stream early — treat as normal completion
                }
                total_bytes += n as u64;
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            io::Result::Ok(())
        })
        .await
        {
            Ok(Err(e)) => Err(e), // genuine I/O error during the read loop
            _ => Ok(()),          // timeout expired or server-initiated close — both OK
        }
    } else {
        // Size-based: read exactly req_size bytes.
        let mut remaining = req_size;
        loop {
            let chunk = remaining.min(SPEEDTEST_CHUNK_SIZE as u32) as usize;
            let n = conn.read(&mut buf[..chunk]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "download stream closed before all bytes received",
                )
                .into());
            }
            total_bytes += n as u64;
            counter.fetch_add(n as u64, Ordering::Relaxed);
            remaining -= n as u32;
            if remaining == 0 {
                break;
            }
        }
        Ok(())
    };

    progress_handle.abort();
    io_result?;

    info!(
        bytes = total_bytes,
        speed = %format_speed(total_bytes, total_start.elapsed(), use_bytes),
        "download complete"
    );
    Ok(())
}

async fn run_upload_test(
    client: &Client,
    data_size: Option<u32>,
    duration: Duration,
    use_bytes: bool,
) -> Result<(), BoxError> {
    let is_time_based = data_size.is_none();
    let req_size = if is_time_based { u32::MAX } else { data_size.unwrap() };

    info!(
        mode = if is_time_based { "time-based" } else { "size-based" },
        "performing upload test"
    );

    let mut conn = client.tcp(SPEEDTEST_DEST).await.map_err(|err| {
        io::Error::other(format!(
            "failed to connect (server may not support speed test): {err}"
        ))
    })?;

    write_upload_request(&mut conn, req_size).await?;
    let (ok, msg) = read_status_message(&mut conn).await?;
    if !ok {
        return Err(io::Error::other(format!("server rejected upload request: {msg}")).into());
    }

    let (counter, progress_handle) = start_progress_reporter(
        use_bytes,
        data_size.map(|s| s as u64),
        if is_time_based { Some(duration) } else { None },
        "uploading",
    );

    let buf = vec![0u8; SPEEDTEST_CHUNK_SIZE];
    let total_start = Instant::now();
    let mut total_bytes: u64 = 0;

    if is_time_based {
        // Time-based: write until deadline fires.
        match tokio::time::timeout(duration, async {
            loop {
                conn.write_all(&buf).await?;
                total_bytes += buf.len() as u64;
                counter.fetch_add(buf.len() as u64, Ordering::Relaxed);
            }
            #[allow(unreachable_code)]
            io::Result::Ok(())
        })
        .await
        {
            Ok(Err(e)) => {
                progress_handle.abort();
                return Err(e.into()); // genuine write error
            }
            _ => {} // timeout or server-side close — normal
        }
        progress_handle.abort();
        // Time-based: use locally measured elapsed and byte count.
        info!(
            bytes = total_bytes,
            speed = %format_speed(total_bytes, total_start.elapsed(), use_bytes),
            "upload complete"
        );
    } else {
        // Size-based: write exactly req_size bytes, then read server UploadSummary.
        let mut remaining = req_size;
        loop {
            let chunk = remaining.min(SPEEDTEST_CHUNK_SIZE as u32) as usize;
            conn.write_all(&buf[..chunk]).await?;
            counter.fetch_add(chunk as u64, Ordering::Relaxed);
            remaining -= chunk as u32;
            if remaining == 0 {
                break;
            }
        }
        progress_handle.abort();
        // Size-based: server-reported elapsed and byte count are authoritative.
        let (server_elapsed, server_received) = read_upload_summary(&mut conn).await?;
        info!(
            bytes = server_received,
            speed = %format_speed(server_received as u64, server_elapsed, use_bytes),
            "upload complete"
        );
    }

    Ok(())
}

async fn write_download_request(conn: &mut (impl AsyncWrite + Unpin), size: u32) -> io::Result<()> {
    let mut req = [0u8; 5];
    req[0] = 0x01;
    req[1..].copy_from_slice(&size.to_be_bytes());
    conn.write_all(&req).await
}

async fn write_upload_request(conn: &mut (impl AsyncWrite + Unpin), size: u32) -> io::Result<()> {
    let mut req = [0u8; 5];
    req[0] = 0x02;
    req[1..].copy_from_slice(&size.to_be_bytes());
    conn.write_all(&req).await
}

async fn read_status_message(conn: &mut (impl AsyncRead + Unpin)) -> io::Result<(bool, String)> {
    let mut status = [0u8; 1];
    conn.read_exact(&mut status).await?;
    let mut len = [0u8; 2];
    conn.read_exact(&mut len).await?;
    let msg_len = u16::from_be_bytes(len) as usize;
    let mut msg = vec![0u8; msg_len];
    conn.read_exact(&mut msg).await?;
    Ok((status[0] == 0, String::from_utf8_lossy(&msg).into_owned()))
}

async fn read_upload_summary(conn: &mut (impl AsyncRead + Unpin)) -> io::Result<(Duration, u32)> {
    let mut buf = [0u8; 8];
    conn.read_exact(&mut buf).await?;
    let duration_ms = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
    let received = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    Ok((Duration::from_millis(duration_ms), received))
}

fn format_speed(bytes: u64, duration: Duration, use_bytes: bool) -> String {
    let secs = duration.as_secs_f64().max(1e-6);
    let mut speed = bytes as f64 / secs;
    let units = if use_bytes {
        ["B/s", "KB/s", "MB/s", "GB/s"]
    } else {
        speed *= 8.0;
        ["bps", "Kbps", "Mbps", "Gbps"]
    };
    let mut unit_index = 0usize;
    while speed > 1000.0 && unit_index < units.len() - 1 {
        speed /= 1000.0;
        unit_index += 1;
    }
    format!("{speed:.2} {}", units[unit_index])
}

struct ResolvedServerEndpoint {
    server_name: String,
    server_addr: SocketAddr,
    packet_transport: ClientPacketTransport,
}

fn resolve_server_endpoint(
    server: &str,
    transport_cfg: &ClientTransportConfig,
) -> Result<ResolvedServerEndpoint, BoxError> {
    if server.trim().is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "server is empty").into());
    }

    let (host, port, host_port) = parse_server_addr_string(server);

    let transport_type = if transport_cfg.transport_type.trim().is_empty() {
        "udp"
    } else {
        transport_cfg.transport_type.trim()
    };
    if !transport_type.eq_ignore_ascii_case("udp") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "unsupported transport.type: {}",
                transport_cfg.transport_type
            ),
        )
        .into());
    }

    if let Some(interval) = transport_cfg.udp.hop_interval
        && interval < MIN_HOP_INTERVAL
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transport.udp.hopInterval must be at least 5s",
        )
        .into());
    }

    if is_port_hopping_port(&port) {
        let addrs = resolve_udp_hop_addrs(&host_port).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid port-hopping server address: {err}"),
            )
        })?;
        let hop_interval = transport_cfg
            .udp
            .hop_interval
            .unwrap_or(DEFAULT_HOP_INTERVAL);
        return Ok(ResolvedServerEndpoint {
            server_name: host,
            server_addr: addrs[0],
            packet_transport: ClientPacketTransport::UdpHop {
                addrs,
                hop_interval,
            },
        });
    }

    let mut addrs = host_port
        .to_socket_addrs()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let addr = addrs.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "server resolves to no address")
    })?;

    Ok(ResolvedServerEndpoint {
        server_name: host,
        server_addr: addr,
        packet_transport: ClientPacketTransport::Udp,
    })
}

fn parse_server_addr_string(addr: &str) -> (String, String, String) {
    if let Some((host, port)) = split_host_port(addr) {
        return (host, port, addr.to_string());
    }
    let host = addr
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = "443".to_string();
    let host_port = join_host_port(&host, &port);
    (host, port, host_port)
}

fn split_host_port(addr: &str) -> Option<(String, String)> {
    if let Some(rest) = addr.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = rest[..close].to_string();
        let remain = &rest[close + 1..];
        let port = remain.strip_prefix(':')?;
        if port.is_empty() {
            return None;
        }
        return Some((host, port.to_string()));
    }
    let (host, port) = addr.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() {
        return None;
    }
    if host.contains(':') {
        return None;
    }
    Some((host.to_string(), port.to_string()))
}

fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn is_port_hopping_port(port: &str) -> bool {
    port.contains('-') || port.contains(',')
}

fn build_client_obfs(cfg: &ClientObfsConfigFile) -> Result<Option<ClientObfsConfig>, BoxError> {
    let obfs_type = cfg.obfs_type.trim();
    if obfs_type.is_empty() {
        return Ok(None);
    }
    if !obfs_type.eq_ignore_ascii_case("salamander") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported obfs.type: {}", cfg.obfs_type),
        )
        .into());
    }
    if cfg.salamander.password.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "obfs.salamander.password is empty",
        )
        .into());
    }
    Ok(Some(ClientObfsConfig {
        salamander_password: cfg.salamander.password.clone(),
    }))
}

async fn run_mux_mode(
    socks_cfg: Socks5Config,
    http_cfg: HttpConfig,
    client: Arc<ReconnectableClient>,
) -> Result<(), BoxError> {
    if socks_cfg.listen.trim().is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "socks5.listen is empty").into());
    }

    let listener = TcpListener::bind(normalize_listen_addr(&socks_cfg.listen)?).await?;

    let socks_server = Arc::new(socks5::Server {
        hy_client: Arc::clone(&client),
        auth_func: auth_func(&socks_cfg.username, &socks_cfg.password),
        disable_udp: socks_cfg.disable_udp,
        event_logger: Some(Arc::new(Socks5Logger)),
    });

    let http_server = Arc::new(http::Server {
        hy_client: Arc::clone(&client),
        auth_func: auth_func(&http_cfg.username, &http_cfg.password),
        auth_realm: if http_cfg.realm.is_empty() {
            "Hysteria".to_string()
        } else {
            http_cfg.realm
        },
        event_logger: Some(Arc::new(HttpLogger)),
    });

    info!(addr = %socks_cfg.listen, "SOCKS5 server listening");
    info!(addr = %socks_cfg.listen, "HTTP proxy server listening");

    let socks_handler: proxymux::DispatchHandler = Arc::new(move |stream| {
        let server = Arc::clone(&socks_server);
        Box::pin(async move {
            server.dispatch(stream).await;
        })
    });

    let http_handler: proxymux::DispatchHandler = Arc::new(move |stream| {
        let server = Arc::clone(&http_server);
        Box::pin(async move {
            server.dispatch(stream).await;
        })
    });

    proxymux::serve(listener, socks_handler, http_handler).await?;
    Ok(())
}

async fn run_socks5(
    config: Socks5Config,
    client: Arc<ReconnectableClient>,
) -> Result<(), BoxError> {
    if config.listen.trim().is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "socks5.listen is empty").into());
    }

    let listener = TcpListener::bind(normalize_listen_addr(&config.listen)?).await?;
    let server = Arc::new(socks5::Server {
        hy_client: client,
        auth_func: auth_func(&config.username, &config.password),
        disable_udp: config.disable_udp,
        event_logger: Some(Arc::new(Socks5Logger)),
    });

    info!(addr = %config.listen, "SOCKS5 server listening");
    server.serve(listener).await?;
    Ok(())
}

async fn run_http(config: HttpConfig, client: Arc<ReconnectableClient>) -> Result<(), BoxError> {
    if config.listen.trim().is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "http.listen is empty").into());
    }

    let listener = TcpListener::bind(normalize_listen_addr(&config.listen)?).await?;
    let server = Arc::new(http::Server {
        hy_client: client,
        auth_func: auth_func(&config.username, &config.password),
        auth_realm: if config.realm.is_empty() {
            "Hysteria".to_string()
        } else {
            config.realm
        },
        event_logger: Some(Arc::new(HttpLogger)),
    });

    info!(addr = %config.listen, "HTTP proxy server listening");
    server.serve(listener).await?;
    Ok(())
}

async fn run_tcp_forwarding(
    entries: Vec<TcpForwardingEntry>,
    client: Arc<ReconnectableClient>,
) -> Result<(), BoxError> {
    let (tx, mut rx) = mpsc::channel::<Result<(), BoxError>>(entries.len());

    for entry in entries {
        if entry.listen.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcpForwarding.listen is empty",
            )
            .into());
        }
        if entry.remote.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcpForwarding.remote is empty",
            )
            .into());
        }

        let listener = TcpListener::bind(normalize_listen_addr(&entry.listen)?).await?;
        info!(addr = %entry.listen, remote = %entry.remote, "TCP forwarding listening");

        let tunnel = Arc::new(TCPTunnel {
            hy_client: Arc::clone(&client),
            remote: entry.remote.clone(),
            event_logger: Some(Arc::new(TcpForwardLogger)),
        });

        let tx = tx.clone();
        tokio::spawn(async move {
            let result = tunnel
                .serve(listener)
                .await
                .map_err(|err| Box::new(err) as BoxError);
            let _ = tx.send(result).await;
        });
    }

    drop(tx);
    rx.recv().await.unwrap_or_else(|| Ok(()))
}

async fn run_udp_forwarding(
    entries: Vec<UdpForwardingEntry>,
    client: Arc<ReconnectableClient>,
) -> Result<(), BoxError> {
    let (tx, mut rx) = mpsc::channel::<Result<(), BoxError>>(entries.len());

    for entry in entries {
        if entry.listen.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "udpForwarding.listen is empty",
            )
            .into());
        }
        if entry.remote.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "udpForwarding.remote is empty",
            )
            .into());
        }

        let socket = UdpSocket::bind(normalize_listen_addr(&entry.listen)?).await?;
        info!(addr = %entry.listen, remote = %entry.remote, "UDP forwarding listening");

        let tunnel = Arc::new(UDPTunnel::new(
            Arc::clone(&client),
            entry.remote.clone(),
            entry.timeout.unwrap_or(Duration::from_secs(60)),
            Some(Arc::new(UdpForwardLogger)),
        ));

        let tx = tx.clone();
        tokio::spawn(async move {
            let result = tunnel
                .serve(socket)
                .await
                .map_err(|err| Box::new(err) as BoxError);
            let _ = tx.send(result).await;
        });
    }

    drop(tx);
    rx.recv().await.unwrap_or_else(|| Ok(()))
}

async fn run_tcp_tproxy(
    config: TcpTProxyConfig,
    client: Arc<ReconnectableClient>,
) -> Result<(), BoxError> {
    if !cfg!(target_os = "linux") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP transparent proxy is only supported on Linux",
        )
        .into());
    }
    let listener = TcpListener::bind(normalize_listen_addr(&config.listen)?).await?;
    let proxy = Arc::new(tproxy::TCPTProxy {
        hy_client: client,
        event_logger: Some(Arc::new(TcpTProxyLogger)),
    });
    info!(addr = %config.listen, "TCP transparent proxy listening");
    proxy.listen_and_serve(listener).await?;
    Ok(())
}

async fn run_udp_tproxy(
    config: UdpTProxyConfig,
    client: Arc<ReconnectableClient>,
) -> Result<(), BoxError> {
    if !cfg!(target_os = "linux") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP transparent proxy is only supported on Linux",
        )
        .into());
    }
    let socket = UdpSocket::bind(normalize_listen_addr(&config.listen)?).await?;
    let proxy = Arc::new(tproxy::UDPTProxy::new(
        client,
        config.timeout.unwrap_or(Duration::from_secs(60)),
        Some(Arc::new(UdpTProxyLogger)),
    ));
    info!(addr = %config.listen, "UDP transparent proxy listening");
    proxy.listen_and_serve(socket).await?;
    Ok(())
}

async fn run_tcp_redirect(
    config: TcpRedirectConfig,
    client: Arc<ReconnectableClient>,
) -> Result<(), BoxError> {
    if !cfg!(target_os = "linux") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP redirect is only supported on Linux",
        )
        .into());
    }
    let listener = TcpListener::bind(normalize_listen_addr(&config.listen)?).await?;
    let server = Arc::new(redirect::TCPRedirect {
        hy_client: client,
        event_logger: Some(Arc::new(TcpRedirectLogger)),
    });
    info!(addr = %config.listen, "TCP redirect listening");
    server.listen_and_serve(listener).await?;
    Ok(())
}

async fn run_tun(config: TunModeConfig, client: Arc<ReconnectableClient>) -> Result<(), BoxError> {
    let mut server_cfg = tun::TunConfig {
        name: if config.name.trim().is_empty() {
            "hytun".to_string()
        } else {
            config.name
        },
        mtu: if config.mtu == 0 { 1500 } else { config.mtu },
        timeout: config.timeout.unwrap_or(Duration::from_secs(300)),
        ..tun::TunConfig::default()
    };
    if let Some(addr) = config.address {
        if !addr.ipv4.trim().is_empty() {
            server_cfg.inet4_address.push(addr.ipv4);
        } else {
            server_cfg
                .inet4_address
                .push("100.100.100.101/30".to_string());
        }
        if !addr.ipv6.trim().is_empty() {
            server_cfg.inet6_address.push(addr.ipv6);
        } else {
            server_cfg
                .inet6_address
                .push("2001::ffff:ffff:ffff:fff1/126".to_string());
        }
    } else {
        server_cfg
            .inet4_address
            .push("100.100.100.101/30".to_string());
        server_cfg
            .inet6_address
            .push("2001::ffff:ffff:ffff:fff1/126".to_string());
    }
    if let Some(route) = config.route {
        server_cfg.auto_route = true;
        server_cfg.strict_route = route.strict;
        server_cfg.inet4_route_address = route.ipv4;
        server_cfg.inet6_route_address = route.ipv6;
        server_cfg.inet4_route_exclude_address = route.ipv4_exclude;
        server_cfg.inet6_route_exclude_address = route.ipv6_exclude;
    }
    let server = tun::build_default_tun_server(client, server_cfg, Some(Arc::new(TunLogger)));
    server.validate()?;
    info!(interface = %server.config.name, "TUN listening");
    server.serve().await?;
    Ok(())
}

fn normalize_listen_addr(listen: &str) -> Result<SocketAddr, io::Error> {
    if let Some(port) = listen.strip_prefix(':') {
        let port = port
            .parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid listen port"))?;
        Ok(SocketAddr::from(([0, 0, 0, 0], port)))
    } else {
        listen.parse::<SocketAddr>().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid listen address: {e}"),
            )
        })
    }
}

fn auth_func(
    username: &str,
    password: &str,
) -> Option<Arc<dyn Fn(&str, &str) -> bool + Send + Sync>> {
    if username.is_empty() || password.is_empty() {
        return None;
    }
    let username = username.to_string();
    let password = password.to_string();
    Some(Arc::new(move |u, p| u == username && p == password))
}

struct Socks5Logger;

impl socks5::EventLogger for Socks5Logger {
    fn tcp_request(&self, addr: SocketAddr, req_addr: &str) {
        debug!(addr = %addr, reqAddr = %req_addr, "SOCKS5 TCP request");
    }

    fn tcp_error(&self, addr: SocketAddr, req_addr: &str, err: Option<&(dyn Error + Send + Sync)>) {
        if let Some(err) = err {
            warn!(addr = %addr, reqAddr = %req_addr, error = %err, "SOCKS5 TCP error");
        } else {
            debug!(addr = %addr, reqAddr = %req_addr, "SOCKS5 TCP closed");
        }
    }

    fn udp_request(&self, addr: SocketAddr) {
        debug!(addr = %addr, "SOCKS5 UDP request");
    }

    fn udp_error(&self, addr: SocketAddr, err: Option<&(dyn Error + Send + Sync)>) {
        if let Some(err) = err {
            warn!(addr = %addr, error = %err, "SOCKS5 UDP error");
        } else {
            debug!(addr = %addr, "SOCKS5 UDP closed");
        }
    }
}

struct HttpLogger;

impl http::EventLogger for HttpLogger {
    fn connect_request(&self, addr: SocketAddr, req_addr: &str) {
        debug!(addr = %addr, reqAddr = %req_addr, "HTTP CONNECT request");
    }

    fn connect_error(
        &self,
        addr: SocketAddr,
        req_addr: &str,
        err: Option<&(dyn Error + Send + Sync)>,
    ) {
        if let Some(err) = err {
            warn!(addr = %addr, reqAddr = %req_addr, error = %err, "HTTP CONNECT error");
        } else {
            debug!(addr = %addr, reqAddr = %req_addr, "HTTP CONNECT closed");
        }
    }

    fn http_request(&self, addr: SocketAddr, req_url: &str) {
        debug!(addr = %addr, reqURL = %req_url, "HTTP request");
    }

    fn http_error(&self, addr: SocketAddr, req_url: &str, err: Option<&(dyn Error + Send + Sync)>) {
        if let Some(err) = err {
            warn!(addr = %addr, reqURL = %req_url, error = %err, "HTTP error");
        } else {
            debug!(addr = %addr, reqURL = %req_url, "HTTP closed");
        }
    }
}

struct TcpForwardLogger;

impl forwarding::TCPEventLogger for TcpForwardLogger {
    fn connect(&self, addr: SocketAddr) {
        debug!(addr = %addr, "TCP forwarding connect");
    }

    fn error(&self, addr: SocketAddr, err: Option<&(dyn Error + Send + Sync)>) {
        if let Some(err) = err {
            warn!(addr = %addr, error = %err, "TCP forwarding error");
        } else {
            debug!(addr = %addr, "TCP forwarding closed");
        }
    }
}

struct UdpForwardLogger;

impl forwarding::UDPEventLogger for UdpForwardLogger {
    fn connect(&self, addr: SocketAddr) {
        debug!(addr = %addr, "UDP forwarding connect");
    }

    fn error(&self, addr: SocketAddr, err: Option<&(dyn Error + Send + Sync)>) {
        if let Some(err) = err {
            warn!(addr = %addr, error = %err, "UDP forwarding error");
        } else {
            debug!(addr = %addr, "UDP forwarding closed");
        }
    }
}

struct TcpTProxyLogger;

impl tproxy::TCPEventLogger for TcpTProxyLogger {
    fn connect(&self, addr: SocketAddr, req_addr: SocketAddr) {
        debug!(addr = %addr, reqAddr = %req_addr, "TCP transparent proxy connect");
    }

    fn error(
        &self,
        addr: SocketAddr,
        req_addr: SocketAddr,
        err: Option<&(dyn Error + Send + Sync)>,
    ) {
        if let Some(err) = err {
            warn!(addr = %addr, reqAddr = %req_addr, error = %err, "TCP transparent proxy error");
        } else {
            debug!(addr = %addr, reqAddr = %req_addr, "TCP transparent proxy closed");
        }
    }
}

struct UdpTProxyLogger;

impl tproxy::UDPEventLogger for UdpTProxyLogger {
    fn connect(&self, addr: SocketAddr, req_addr: SocketAddr) {
        debug!(addr = %addr, reqAddr = %req_addr, "UDP transparent proxy connect");
    }

    fn error(
        &self,
        addr: SocketAddr,
        req_addr: SocketAddr,
        err: Option<&(dyn Error + Send + Sync)>,
    ) {
        if let Some(err) = err {
            warn!(addr = %addr, reqAddr = %req_addr, error = %err, "UDP transparent proxy error");
        } else {
            debug!(addr = %addr, reqAddr = %req_addr, "UDP transparent proxy closed");
        }
    }
}

struct TcpRedirectLogger;

impl redirect::TCPEventLogger for TcpRedirectLogger {
    fn connect(&self, addr: SocketAddr, req_addr: SocketAddr) {
        debug!(addr = %addr, reqAddr = %req_addr, "TCP redirect connect");
    }

    fn error(
        &self,
        addr: SocketAddr,
        req_addr: SocketAddr,
        err: Option<&(dyn Error + Send + Sync)>,
    ) {
        if let Some(err) = err {
            warn!(addr = %addr, reqAddr = %req_addr, error = %err, "TCP redirect error");
        } else {
            debug!(addr = %addr, reqAddr = %req_addr, "TCP redirect closed");
        }
    }
}

struct TunLogger;

impl tun::EventLogger for TunLogger {
    fn tcp_request(&self, addr: &str, req_addr: &str) {
        debug!(addr = %addr, reqAddr = %req_addr, "TUN TCP request");
    }

    fn tcp_error(&self, addr: &str, req_addr: &str, err: Option<&(dyn Error + Send + Sync)>) {
        if let Some(err) = err {
            warn!(addr = %addr, reqAddr = %req_addr, error = %err, "TUN TCP error");
        } else {
            debug!(addr = %addr, reqAddr = %req_addr, "TUN TCP closed");
        }
    }

    fn udp_request(&self, addr: &str) {
        debug!(addr = %addr, "TUN UDP request");
    }

    fn udp_error(&self, addr: &str, err: Option<&(dyn Error + Send + Sync)>) {
        if let Some(err) = err {
            warn!(addr = %addr, error = %err, "TUN UDP error");
        } else {
            debug!(addr = %addr, "TUN UDP closed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hy2_uri_overrides_auth_tls_obfs() {
        let mut cfg = ClientConfigFile {
            server: "hysteria2://user:pass@example.com:8443?sni=edge.example.com&insecure=1&obfs=salamander&obfs-password=secret&pinSHA256=abcd".to_string(),
            ..ClientConfigFile::default()
        };
        apply_hysteria2_uri_overrides(&mut cfg).unwrap();
        assert_eq!(cfg.server, "example.com:8443");
        assert_eq!(cfg.auth, "user:pass");
        assert_eq!(cfg.tls.sni, "edge.example.com");
        assert!(cfg.tls.insecure);
        assert_eq!(cfg.tls.pin_sha256, "abcd");
        assert_eq!(cfg.obfs.obfs_type, "salamander");
        assert_eq!(cfg.obfs.salamander.password, "secret");
    }

    #[test]
    fn hy2_uri_non_uri_server_unchanged() {
        let mut cfg = ClientConfigFile {
            server: "example.com:443".to_string(),
            auth: "token".to_string(),
            ..ClientConfigFile::default()
        };
        apply_hysteria2_uri_overrides(&mut cfg).unwrap();
        assert_eq!(cfg.server, "example.com:443");
        assert_eq!(cfg.auth, "token");
    }

    #[test]
    fn hy2_uri_keeps_port_hopping_server() {
        let mut cfg = ClientConfigFile {
            server: "hysteria2://user:pass@example.com:2000-2003,2008?insecure=1".to_string(),
            ..ClientConfigFile::default()
        };
        apply_hysteria2_uri_overrides(&mut cfg).unwrap();
        assert_eq!(cfg.server, "example.com:2000-2003,2008");
        assert_eq!(cfg.auth, "user:pass");
        assert!(cfg.tls.insecure);
    }

    #[test]
    fn hy2_uri_default_port_for_ipv6() {
        let mut cfg = ClientConfigFile {
            server: "hy2://[2001:db8::1]?obfs=salamander".to_string(),
            ..ClientConfigFile::default()
        };
        apply_hysteria2_uri_overrides(&mut cfg).unwrap();
        assert_eq!(cfg.server, "[2001:db8::1]:443");
        assert_eq!(cfg.obfs.obfs_type, "salamander");
    }

    #[test]
    fn client_quic_keepalive_validation() {
        let cfg = ClientQuicConfig {
            keep_alive_period: Some(Duration::from_secs(1)),
            ..ClientQuicConfig::default()
        };
        assert!(build_client_transport_config(&cfg).is_err());
    }
}
