/// Integration tests: real client ↔ server over loopback QUIC/H3.
///
/// Each test spins up a local Hysteria server and a matching client, then
/// exercises the auth handshake and (where applicable) the TCP proxy tunnel
/// or UDP relay.
use std::sync::Arc;
use std::time::Duration;

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use rysteria::core::client::{Client, ClientConfig, ClientPacketTransport, ClientTlsConfig};
use rysteria::core::server::{Server, ServerConfig};
use rysteria::extras::auth::PasswordAuthenticator;
use rysteria::extras::tls::SniGuardMode;
use rysteria::extras::transport::udphop::resolve_udp_hop_addrs;

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Generate a self-signed TLS certificate for `localhost`.
fn make_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    (vec![cert_der], key_der)
}

/// Build and bind a `Server`, spawn it in the background, return the bound address.
async fn spawn_server(password: &str) -> std::net::SocketAddr {
    let (tls_cert, tls_key) = make_cert();
    let server = Server::new(ServerConfig {
        authenticator: Arc::new(PasswordAuthenticator {
            password: password.to_string(),
        }),
        tls_cert,
        tls_key,
        tls_client_ca: None,
        tls_sni_guard: SniGuardMode::Disable,
        addr: "127.0.0.1:0".parse().unwrap(),
        transport: None,
        transport_builder: None,
        speed_bps: 0, // 0 = no limit (use BBR)
        speed_rx_bps: 0,
        ignore_client_bandwidth: false,
        event_logger: None,
        traffic_logger: None,
        request_hook: None,
        outbound: None,
        masq_handler: None,
        disable_udp: false,
        speed_test: false,
        udp_idle_timeout: Duration::from_secs(60),
        obfs_salamander_password: None,
        shard_threads: Some(1),
    })
    .unwrap();
    let addr = server.local_addr();
    tokio::spawn(async move {
        let _ = server.serve().await;
    });
    addr
}

/// Build a `ClientConfig` pointing at `server_addr` with password auth,
/// using `InsecureSkipVerify` (no CA needed for loopback tests).
fn client_cfg(password: &str, server_addr: std::net::SocketAddr) -> ClientConfig {
    ClientConfig {
        auth: password.to_string(),
        server_addr,
        server_name: "localhost".to_string(),
        tls: ClientTlsConfig::InsecureSkipVerify {
            client_identity: None,
        },
        bandwidth_tx: 0,
        bandwidth_rx: 0,
        transport: None,
        udp_socket_factory: None,
        packet_transport: ClientPacketTransport::Udp,
        obfs: None,
        fast_open: false,
        persistent_tunnel: true,
        tunnel_keepalive_secs: 25,
        conn_send_budget: None,
        socket_wrapper: None,
        hop_generation: None,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

/// A client with the correct password successfully completes the H3 auth
/// handshake and receives a valid `HandshakeInfo`.
#[tokio::test]
async fn handshake_correct_password() {
    let server_addr = spawn_server("secret").await;

    let (client, info) = tokio::time::timeout(
        Duration::from_secs(5),
        Client::connect(client_cfg("secret", server_addr)),
    )
    .await
    .expect("timed out")
    .expect("connect failed");

    // server reports UDP enabled.
    assert!(info.udp_enabled);

    client.close();
}

/// A client that sends the wrong password must receive an error (auth rejected).
#[tokio::test]
async fn handshake_wrong_password_rejected() {
    let server_addr = spawn_server("correct").await;

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        Client::connect(client_cfg("wrong", server_addr)),
    )
    .await
    .expect("timed out");

    assert!(result.is_err(), "wrong password should be rejected");
}

/// After auth, the client can open a TCP proxy stream to a local echo server
/// and data round-trips correctly through the QUIC tunnel.
#[tokio::test]
async fn tcp_proxy_echo_roundtrip() {
    // ── Start a trivial TCP echo server ──────────────────────────────────────
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = stream.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });

    // ── Start Hysteria server ─────────────────────────────────────────────────
    let server_addr = spawn_server("pass").await;

    // ── Connect Hysteria client ───────────────────────────────────────────────
    let (client, _) = tokio::time::timeout(
        Duration::from_secs(5),
        Client::connect(client_cfg("pass", server_addr)),
    )
    .await
    .expect("timed out")
    .expect("connect failed");

    // ── Open a TCP proxy stream to the echo server ────────────────────────────
    let mut proxy =
        tokio::time::timeout(Duration::from_secs(5), client.tcp(&echo_addr.to_string()))
            .await
            .expect("tcp() timed out")
            .expect("tcp() failed");

    // ── Write data; read it back ──────────────────────────────────────────────
    let payload = b"hello rysteria";
    proxy.write_all(payload).await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), proxy.read_exact(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();

    assert_eq!(&buf, payload);

    client.close();
}

/// Multiple TCP proxy connections can be opened concurrently over the same
/// QUIC connection.
#[tokio::test]
async fn tcp_proxy_multiple_streams() {
    // ── Echo server ───────────────────────────────────────────────────────────
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = stream.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });

    // ── Server + client ───────────────────────────────────────────────────────
    let server_addr = spawn_server("pass").await;
    let (client, _) = tokio::time::timeout(
        Duration::from_secs(5),
        Client::connect(client_cfg("pass", server_addr)),
    )
    .await
    .expect("timed out")
    .expect("connect failed");

    let client = Arc::new(client);

    // ── Open 4 streams concurrently ───────────────────────────────────────────
    let handles: Vec<_> = (0u8..4)
        .map(|i| {
            let client = client.clone();
            let echo_addr = echo_addr.to_string();
            tokio::spawn(async move {
                let mut proxy = client.tcp(&echo_addr).await.unwrap();
                let msg = vec![i; 32];
                proxy.write_all(&msg).await.unwrap();
                let mut buf = vec![0u8; 32];
                proxy.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, msg);
            })
        })
        .collect();

    for h in handles {
        tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .expect("stream task timed out")
            .unwrap();
    }

    client.close();
}

// ──────────────────────────────────────────────────────────────────────────────
// UDP relay tests
// ──────────────────────────────────────────────────────────────────────────────

/// A client can open a UDP relay session and exchange datagrams with a remote
/// UDP echo server via the Hysteria server.
#[tokio::test]
async fn udp_relay_echo_roundtrip() {
    // ── Start a trivial UDP echo server ──────────────────────────────────────
    let echo_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, src)) = echo_sock.recv_from(&mut buf).await else {
                break;
            };
            let _ = echo_sock.send_to(&buf[..n], src).await;
        }
    });

    // ── Start Hysteria server ─────────────────────────────────────────────────
    let server_addr = spawn_server("pass").await;

    // ── Connect Hysteria client ───────────────────────────────────────────────
    let (client, info) = tokio::time::timeout(
        Duration::from_secs(5),
        Client::connect(client_cfg("pass", server_addr)),
    )
    .await
    .expect("timed out")
    .expect("connect failed");

    assert!(info.udp_enabled, "server must advertise UDP enabled");

    // ── Open a UDP relay session ──────────────────────────────────────────────
    let udp = tokio::time::timeout(Duration::from_secs(5), client.udp())
        .await
        .expect("udp() timed out")
        .expect("udp() failed");

    // ── Send data; receive echoed data ────────────────────────────────────────
    let payload = b"hello udp relay";
    tokio::time::timeout(
        Duration::from_secs(5),
        udp.send(payload, &echo_addr.to_string()),
    )
    .await
    .expect("send timed out")
    .expect("send failed");

    let (recv_data, recv_addr) = tokio::time::timeout(Duration::from_secs(5), udp.receive())
        .await
        .expect("receive timed out")
        .expect("receive failed");

    assert_eq!(recv_data, payload);
    // The returned addr is the echo server's address as reported by the server.
    assert_eq!(recv_addr, echo_addr.to_string());

    udp.close();
    client.close();
}

/// Multiple UDP relay sessions can be open concurrently over the same QUIC
/// connection.
#[tokio::test]
async fn udp_relay_multiple_sessions() {
    // ── UDP echo server ───────────────────────────────────────────────────────
    let echo_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let echo_addr = echo_sock.local_addr().unwrap();
    {
        let echo_sock = Arc::clone(&echo_sock);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, src)) = echo_sock.recv_from(&mut buf).await else {
                    break;
                };
                let _ = echo_sock.send_to(&buf[..n], src).await;
            }
        });
    }

    // ── Server + client ───────────────────────────────────────────────────────
    let server_addr = spawn_server("pass").await;
    let (client, _) = tokio::time::timeout(
        Duration::from_secs(5),
        Client::connect(client_cfg("pass", server_addr)),
    )
    .await
    .expect("timed out")
    .expect("connect failed");

    let client = Arc::new(client);

    // ── Open 3 UDP sessions concurrently ─────────────────────────────────────
    let handles: Vec<_> = (0u8..3)
        .map(|i| {
            let client = Arc::clone(&client);
            let echo_addr = echo_addr.to_string();
            tokio::spawn(async move {
                let udp = client.udp().await.unwrap();
                let msg = vec![i; 16];
                udp.send(&msg, &echo_addr).await.unwrap();
                let (recv, _) = tokio::time::timeout(Duration::from_secs(5), udp.receive())
                    .await
                    .expect("receive timed out")
                    .unwrap();
                assert_eq!(recv, msg);
                udp.close();
            })
        })
        .collect();

    for h in handles {
        tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .expect("udp session task timed out")
            .unwrap();
    }

    client.close();
}

/// A large UDP payload that exceeds `MAX_DATAGRAM_FRAME_SIZE` (1200 bytes) is
/// automatically fragmented by the client and reassembled by the server before
/// being forwarded upstream.  The echo response is similarly handled in reverse.
#[tokio::test]
async fn udp_relay_large_payload_auto_fragmented() {
    // ── UDP echo server ───────────────────────────────────────────────────────
    let echo_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, src)) = echo_sock.recv_from(&mut buf).await else {
                break;
            };
            let _ = echo_sock.send_to(&buf[..n], src).await;
        }
    });

    // ── Server + client ───────────────────────────────────────────────────────
    let server_addr = spawn_server("pass").await;
    let (client, _) = tokio::time::timeout(
        Duration::from_secs(5),
        Client::connect(client_cfg("pass", server_addr)),
    )
    .await
    .expect("timed out")
    .expect("connect failed");

    let udp = client.udp().await.expect("udp() failed");

    // 2 KB payload — larger than MAX_DATAGRAM_FRAME_SIZE (1200 bytes).
    // The client should auto-fragment and the server should reassemble.
    let payload: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
    tokio::time::timeout(
        Duration::from_secs(5),
        udp.send(&payload, &echo_addr.to_string()),
    )
    .await
    .expect("send timed out")
    .expect("send failed");

    let (recv_data, _) = tokio::time::timeout(Duration::from_secs(5), udp.receive())
        .await
        .expect("receive timed out")
        .expect("receive failed");

    assert_eq!(recv_data, payload);

    udp.close();
    client.close();
}

// ──────────────────────────────────────────────────────────────────────────────
// UDP hop address parsing tests
// ──────────────────────────────────────────────────────────────────────────────

/// `resolve_udp_hop_addrs` correctly parses a single-port hop address.
#[test]
fn udphop_resolve_single_port() {
    let addrs = resolve_udp_hop_addrs("127.0.0.1:443").unwrap();
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].port(), 443);
}

/// `resolve_udp_hop_addrs` correctly expands a port range.
#[test]
fn udphop_resolve_port_range() {
    let addrs = resolve_udp_hop_addrs("127.0.0.1:8000-8004").unwrap();
    assert_eq!(addrs.len(), 5);
    let ports: Vec<u16> = addrs.iter().map(|a| a.port()).collect();
    assert_eq!(ports, vec![8000, 8001, 8002, 8003, 8004]);
}

/// `resolve_udp_hop_addrs` correctly expands a comma-separated port union.
#[test]
fn udphop_resolve_port_union() {
    let mut addrs = resolve_udp_hop_addrs("127.0.0.1:9000,9001,9002").unwrap();
    addrs.sort_by_key(|a| a.port());
    assert_eq!(addrs.len(), 3);
    assert_eq!(addrs[0].port(), 9000);
    assert_eq!(addrs[2].port(), 9002);
}

// ──────────────────────────────────────────────────────────────────────────────
// Optimization validation tests
// ──────────────────────────────────────────────────────────────────────────────

/// Multiple concurrent TCP proxy streams receive fair throughput.
///
/// Opens N streams to an echo server concurrently, sends data, reads it
/// back, and verifies all streams complete without starvation. This
/// exercises the DRR scheduler and per-flow permit allocation in the
/// ConnectionActor path.
#[tokio::test]
async fn tcp_proxy_multi_flow_fairness() {
    const NUM_STREAMS: usize = 4;
    const PAYLOAD_SIZE: usize = 4096;

    // Start a TCP echo server.
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = echo.accept().await else { break };
            tokio::spawn(async move {
                let (mut rd, mut wr) = stream.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });

    let server_addr = spawn_server("fairness").await;
    let (client, _) = tokio::time::timeout(
        Duration::from_secs(5),
        Client::connect(client_cfg("fairness", server_addr)),
    )
    .await
    .expect("timed out")
    .expect("connect failed");
    let client = Arc::new(client);

    // Spawn N concurrent streams, each sending and receiving PAYLOAD_SIZE bytes.
    let mut handles = Vec::new();
    for i in 0..NUM_STREAMS {
        let c = Arc::clone(&client);
        let addr = echo_addr.to_string();
        handles.push(tokio::spawn(async move {
            let mut proxy = tokio::time::timeout(Duration::from_secs(5), c.tcp(&addr))
                .await
                .expect("tcp() timed out")
                .expect("tcp() failed");

            // Use a unique fill byte per stream for verification.
            let fill = (i as u8).wrapping_add(0xA0);
            let data = vec![fill; PAYLOAD_SIZE];
            proxy.write_all(&data).await.expect("write failed");

            // Read back the echoed data.
            let mut buf = vec![0u8; PAYLOAD_SIZE];
            tokio::time::timeout(Duration::from_secs(5), proxy.read_exact(&mut buf))
                .await
                .expect("read timed out")
                .expect("read failed");

            assert_eq!(buf, data, "echo mismatch on stream {i}");
            true
        }));
    }

    let mut all_ok = true;
    for h in handles {
        if !h.await.expect("task panicked") {
            all_ok = false;
        }
    }

    assert!(all_ok, "all streams should complete with correct echo data");
    client.close();
}

/// Bulk TCP traffic should not prevent UDP datagrams from being relayed
/// promptly. This verifies that the scheduler's Realtime class (used for
/// UDP) takes priority over Bulk class (used for TCP streams).
#[tokio::test]
async fn udp_relay_unblocked_by_tcp_bulk() {
    // Start a TCP sink that just drains data (no echo, just consume).
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = sink.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = sink.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                while stream.read(&mut buf).await.unwrap_or(0) > 0 {}
            });
        }
    });

    // Start a UDP echo server.
    let udp_echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_echo_addr = udp_echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            let (n, from) = match udp_echo.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => break,
            };
            let _ = udp_echo.send_to(&buf[..n], from).await;
        }
    });

    let server_addr = spawn_server("udpiso").await;
    let (client, _) = tokio::time::timeout(
        Duration::from_secs(5),
        Client::connect(client_cfg("udpiso", server_addr)),
    )
    .await
    .expect("timed out")
    .expect("connect failed");
    let client = Arc::new(client);

    // Start a bulk TCP stream to saturate the connection.
    let bulk_client = Arc::clone(&client);
    let bulk_addr = sink_addr.to_string();
    let bulk_handle = tokio::spawn(async move {
        if let Ok(mut proxy) = bulk_client.tcp(&bulk_addr).await {
            let data = vec![0xFFu8; 64 * 1024];
            for _ in 0..16 {
                if proxy.write_all(&data).await.is_err() {
                    break;
                }
            }
            let _ = proxy.shutdown().await;
        }
    });

    // Give the bulk stream a head start.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send a UDP datagram and verify it arrives back promptly.
    let udp_conn = tokio::time::timeout(Duration::from_secs(5), client.udp())
        .await
        .expect("udp() timed out")
        .expect("udp() failed");

    let payload = b"ping";
    udp_conn
        .send(payload, &udp_echo_addr.to_string())
        .await
        .expect("udp send failed");

    // UDP should come back within a reasonable time even under TCP load.
    let result: Result<Result<(Vec<u8>, String), _>, _> =
        tokio::time::timeout(Duration::from_secs(3), udp_conn.receive()).await;

    assert!(
        result.is_ok(),
        "UDP datagram should arrive within 3s even during bulk TCP transfer"
    );

    // Clean up.
    let _ = bulk_handle.await;
    client.close();
}
