/// Regression proof tests: validates that all historical failure modes are fixed.
///
/// Each test directly corresponds to a numbered regression in the
/// "Historical Failure Regression Matrix" from optimization-gpt5.4x.md
/// (section "Validation and Regression Proof").
///
/// R14 is automated via generation-aware FaultInjectionSocket:
///   - r14_port_hop_recovers_without_tunnel_rebuild: proves UdpHopSocket
///     absorbs tuple-specific impairment (generation-targeted drop), traffic
///     recovers after hop, and connect_count stays at 1 (no tunnel rebuild).
///
/// R15 is automated via socket-wide FaultInjectionSocket with two tests:
///   - r15_brief_interruption_recovery: proves QUIC+Brutal self-heals after
///     a 2-second total outage (connection survives, no reconnect needed).
///   - r15_forced_tunnel_rebuild_after_prolonged_outage: proves TunnelManager
///     detects connection death and rebuilds the tunnel (short idle timeout +
///     prolonged outage + connect_count assertion).
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use rysteria::core::client::{Client, ClientConfig, ClientPacketTransport, ClientTlsConfig};
use rysteria::core::server::{Server, ServerConfig};
use rysteria::extras::auth::PasswordAuthenticator;
use rysteria::extras::tls::SniGuardMode;

// ─────────────────────────────────────────────────────────────────────────────
// Shared loopback fixtures
// ─────────────────────────────────────────────────────────────────────────────

fn make_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    (vec![cert_der], key_der)
}

/// Spawn a Hysteria server with no rate limit (BBR congestion control).
async fn spawn_server(password: &str) -> std::net::SocketAddr {
    spawn_server_inner(password, 0).await
}

/// Spawn a Hysteria server with Brutal congestion control at `speed_bps`.
async fn spawn_server_with_bps(password: &str, speed_bps: u64) -> std::net::SocketAddr {
    spawn_server_inner(password, speed_bps).await
}

async fn spawn_server_inner(password: &str, speed_bps: u64) -> std::net::SocketAddr {
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
        speed_bps,
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

fn client_cfg(password: &str, server_addr: std::net::SocketAddr) -> ClientConfig {
    ClientConfig {
        auth: password.to_string(),
        server_addr,
        server_name: "localhost".to_string(),
        tls: ClientTlsConfig::InsecureSkipVerify { client_identity: None },
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

/// Connect a client; panics on timeout or error.
async fn connect(password: &str, server_addr: std::net::SocketAddr) -> Client {
    tokio::time::timeout(
        Duration::from_secs(5),
        Client::connect(client_cfg(password, server_addr)),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed")
    .0
}

/// Bind a TCP echo server (reads all data and writes it back).
async fn spawn_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let (mut rd, mut wr) = stream.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    addr
}

/// Bind a TCP sink (drains all incoming data without echoing).
async fn spawn_sink_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                while stream.read(&mut buf).await.unwrap_or(0) > 0 {}
            });
        }
    });
    addr
}

/// Bind a UDP echo socket (echoes every datagram back to sender).
async fn spawn_udp_echo() -> std::net::SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, src)) = sock.recv_from(&mut buf).await else { break };
            let _ = sock.send_to(&buf[..n], src).await;
        }
    });
    addr
}

// ─────────────────────────────────────────────────────────────────────────────
// R01 — Double-buffering data stall
// ─────────────────────────────────────────────────────────────────────────────

/// R01: A single byte written to the TCP proxy must echo back promptly.
///
/// Proof: if a BufWriter or nested buffer existed on the relay path, the small
/// write would never be flushed and the echo would never arrive. This catches
/// any re-introduction of double-buffering on the hot relay path (Rule 1).
#[tokio::test]
async fn r01_single_byte_echo_no_buffer_stall() {
    let echo_addr = spawn_echo_server().await;
    let server_addr = spawn_server("r01").await;
    let client = connect("r01", server_addr).await;

    let mut proxy = tokio::time::timeout(
        Duration::from_secs(5),
        client.tcp(&echo_addr.to_string()),
    )
    .await
    .expect("tcp() timed out")
    .expect("tcp() failed");

    proxy.write_all(b"X").await.expect("write failed");

    let mut buf = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(3), proxy.read_exact(&mut buf))
        .await
        .expect("single-byte echo timed out — double-buffering stall? (R01)")
        .expect("read failed");

    assert_eq!(&buf, b"X");
    client.close();
}

// ─────────────────────────────────────────────────────────────────────────────
// R02 — Permit exhaustion after sustained traffic
// ─────────────────────────────────────────────────────────────────────────────

/// R02: Permit budget must remain available across many sequential TCP flows.
///
/// Proof: runs 20 sequential round-trips over the same QUIC connection. If
/// permits are "burned" (treated as quota) rather than returned to the pool,
/// the budget eventually reaches zero and later flows time out. A successful
/// run over 20 iterations proves budget conservation (Rule 2).
#[tokio::test]
async fn r02_permit_budget_conserved_across_sequential_flows() {
    let echo_addr = spawn_echo_server().await;
    let server_addr = spawn_server("r02").await;
    let client = Arc::new(connect("r02", server_addr).await);

    for i in 0u8..20 {
        let c = Arc::clone(&client);
        let addr = echo_addr.to_string();
        tokio::time::timeout(Duration::from_secs(5), async move {
            let mut proxy = c.tcp(&addr).await.expect("tcp failed");
            let payload = vec![i; 512];
            proxy.write_all(&payload).await.expect("write failed");
            let mut buf = vec![0u8; 512];
            proxy.read_exact(&mut buf).await.expect("read failed");
            assert_eq!(buf, payload, "echo mismatch at flow {i}");
        })
        .await
        .unwrap_or_else(|_| {
            panic!("flow {i} timed out — permit budget may be exhausted (R02)")
        });
    }

    client.close();
}

// ─────────────────────────────────────────────────────────────────────────────
// R03 — Low-bandwidth deadlock
// ─────────────────────────────────────────────────────────────────────────────

/// R03: Forward progress must occur even at a very low configured bandwidth.
///
/// Proof: server configured at 50 Kbps (Brutal mode). A 256-byte payload
/// takes ~40 ms at 50 Kbps; the test allows 15 s. If the token-bucket or
/// permit system deadlocks when bucket capacity < chunk size, this test
/// times out. The fix (reclaim_from_flow never touches capacity) ensures
/// that give_back() can always restore credit (Rule 4).
#[tokio::test]
async fn r03_forward_progress_at_low_bandwidth() {
    let echo_addr = spawn_echo_server().await;
    let server_addr = spawn_server_with_bps("r03", 50_000).await;
    let client = connect("r03", server_addr).await;

    let mut proxy = tokio::time::timeout(
        Duration::from_secs(5),
        client.tcp(&echo_addr.to_string()),
    )
    .await
    .expect("tcp() timed out")
    .expect("tcp() failed");

    let payload = vec![0xABu8; 256];
    proxy.write_all(&payload).await.expect("write failed");
    proxy.shutdown().await.expect("shutdown failed");

    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), proxy.read_to_end(&mut received))
        .await
        .expect("low-bandwidth delivery timed out — forward-progress deadlock? (R03)")
        .expect("read_to_end failed");

    assert_eq!(received, payload, "Data integrity check failed at low bandwidth (R03)");
    client.close();
}

// ─────────────────────────────────────────────────────────────────────────────
// R04 — Missing TCP FIN on QUIC-to-TCP completion
// ─────────────────────────────────────────────────────────────────────────────

/// R04: A correct TCP FIN must be delivered to the target server after the
/// QUIC stream write side is closed.
///
/// Proof: after proxy.shutdown(), the echo server must receive FIN, drain
/// its send buffer (echoing all received data), and send its own FIN. The
/// client's read_to_end() returns only after receiving the echo + EOF.
/// Without FIN delivery, the echo server holds the connection open forever
/// and read_to_end() hangs until the test timeout fires (Rule 7).
#[tokio::test]
async fn r04_tcp_fin_delivered_on_proxy_shutdown() {
    let echo_addr = spawn_echo_server().await;
    let server_addr = spawn_server("r04").await;
    let client = connect("r04", server_addr).await;

    let mut proxy = tokio::time::timeout(
        Duration::from_secs(5),
        client.tcp(&echo_addr.to_string()),
    )
    .await
    .expect("tcp() timed out")
    .expect("tcp() failed");

    let payload = b"r04-fin-test-payload";
    proxy.write_all(payload).await.expect("write failed");
    proxy.shutdown().await.expect("shutdown failed");

    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), proxy.read_to_end(&mut received))
        .await
        .expect("read_to_end timed out — TCP FIN not delivered? (R04)")
        .expect("read_to_end failed");

    assert_eq!(
        received,
        payload.as_ref(),
        "Echoed data must match sent payload (R04)"
    );
    client.close();
}

// ─────────────────────────────────────────────────────────────────────────────
// R05 — Last-chunk loss during close race
// ─────────────────────────────────────────────────────────────────────────────

/// R05: All bytes must be received even when write and shutdown are issued
/// back-to-back with no intermediate yield.
///
/// Proof: if the close signal races ahead of the last data chunk (e.g.,
/// the upload channel is dropped before all data is forwarded), the received
/// byte count will be less than the sent count. A successful run with 8 KiB
/// proves close ordering is correct (Rule 6).
#[tokio::test]
async fn r05_last_chunk_not_dropped_on_immediate_shutdown() {
    let echo_addr = spawn_echo_server().await;
    let server_addr = spawn_server("r05").await;
    let client = connect("r05", server_addr).await;

    let mut proxy = tokio::time::timeout(
        Duration::from_secs(5),
        client.tcp(&echo_addr.to_string()),
    )
    .await
    .expect("tcp() timed out")
    .expect("tcp() failed");

    // Write a substantial payload then immediately shut down — no yield between.
    let payload: Vec<u8> = (0u8..=255).cycle().take(8 * 1024).collect();
    proxy.write_all(&payload).await.expect("write failed");
    proxy.shutdown().await.expect("shutdown failed");

    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), proxy.read_to_end(&mut received))
        .await
        .expect("read_to_end timed out — close race dropped data? (R05)")
        .expect("read_to_end failed");

    assert_eq!(
        received.len(),
        payload.len(),
        "Must receive all {} bytes; got {} — last-chunk loss (R05)",
        payload.len(),
        received.len()
    );
    assert_eq!(received, payload, "Data integrity check failed (R05)");
    client.close();
}

// ─────────────────────────────────────────────────────────────────────────────
// R06 — Speedtest degradation to zero throughput
// ─────────────────────────────────────────────────────────────────────────────

/// R06: Throughput must remain stable across many concurrent TCP flows.
///
/// Proof: 8 concurrent streams each transfer 32 KiB. If permit budget leaks
/// or is permanently consumed rather than returned, the connection-level
/// budget collapses and later flows time out waiting for credit that never
/// returns (Rule 2, Rule 10).
#[tokio::test]
async fn r06_throughput_stable_across_concurrent_flows() {
    const NUM_FLOWS: usize = 8;
    const PAYLOAD: usize = 32 * 1024;

    let echo_addr = spawn_echo_server().await;
    let server_addr = spawn_server("r06").await;
    let client = Arc::new(connect("r06", server_addr).await);

    let handles: Vec<_> = (0..NUM_FLOWS)
        .map(|i| {
            let c = Arc::clone(&client);
            let addr = echo_addr.to_string();
            tokio::spawn(async move {
                let mut proxy =
                    tokio::time::timeout(Duration::from_secs(5), c.tcp(&addr))
                        .await
                        .unwrap_or_else(|_| panic!("flow {i}: tcp() timed out"))
                        .unwrap_or_else(|e| panic!("flow {i}: tcp() failed: {e}"));

                let payload = vec![(i as u8).wrapping_add(0xC0); PAYLOAD];
                proxy
                    .write_all(&payload)
                    .await
                    .unwrap_or_else(|e| panic!("flow {i}: write: {e}"));

                let mut buf = vec![0u8; PAYLOAD];
                tokio::time::timeout(Duration::from_secs(10), proxy.read_exact(&mut buf))
                    .await
                    .unwrap_or_else(|_| {
                        panic!("flow {i}: read timed out — budget starvation? (R06)")
                    })
                    .unwrap_or_else(|e| panic!("flow {i}: read: {e}"));

                assert_eq!(buf, payload, "flow {i}: echo mismatch (R06)");
            })
        })
        .collect();

    for h in handles {
        h.await.expect("flow task panicked");
    }
    client.close();
}

// ─────────────────────────────────────────────────────────────────────────────
// R07 — Graceful shutdown delay theater
// ─────────────────────────────────────────────────────────────────────────────

/// R07: An idle client must close within 1 second — no fixed-delay theater.
///
/// Proof: a client with no active flows is already idle. Closing it must
/// not unconditionally sleep or wait for a fixed drain period. An
/// implementation that uses `tokio::time::sleep(drain_timeout)` regardless
/// of actual idle state would fail this test (Rule 12).
#[tokio::test]
async fn r07_idle_shutdown_completes_quickly() {
    let server_addr = spawn_server("r07").await;
    let client = connect("r07", server_addr).await;

    // No flows opened — the system is idle from the start.
    let start = Instant::now();
    client.close();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "Idle shutdown took {elapsed:?} — expected < 1 s (R07, no fixed-sleep theater)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// R09 — Queue or batch head-of-line blocking
// ─────────────────────────────────────────────────────────────────────────────

/// R09: An interactive TCP flow must not be blocked by a concurrent bulk flow.
///
/// Proof: a bulk TCP flow is started first and generates sustained load.
/// An interactive echo (4 bytes) submitted afterward must complete within
/// 5 s. The per-flow DRR scheduler and independent QUIC stream ownership
/// prevent head-of-line blocking (Rules 9, Rule 8).
#[tokio::test]
async fn r09_interactive_not_blocked_by_bulk_flow() {
    let echo_addr = spawn_echo_server().await;
    let sink_addr = spawn_sink_server().await;
    let server_addr = spawn_server("r09").await;
    let client = Arc::new(connect("r09", server_addr).await);

    // Start bulk TCP flow to generate sustained load.
    let bulk_client = Arc::clone(&client);
    let bulk_sink = sink_addr.to_string();
    tokio::spawn(async move {
        if let Ok(mut proxy) = bulk_client.tcp(&bulk_sink).await {
            let data = vec![0xFFu8; 64 * 1024];
            for _ in 0..32 {
                if proxy.write_all(&data).await.is_err() {
                    break;
                }
            }
            let _ = proxy.shutdown().await;
        }
    });

    // Give the bulk flow a head start before submitting the interactive flow.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Interactive echo must complete independently of the bulk flow.
    let interactive = Arc::clone(&client);
    let echo = echo_addr.to_string();
    tokio::time::timeout(Duration::from_secs(5), async move {
        let mut proxy = interactive.tcp(&echo).await.expect("interactive tcp failed");
        proxy.write_all(b"ping").await.expect("write failed");
        let mut buf = [0u8; 4];
        proxy.read_exact(&mut buf).await.expect("read failed");
        assert_eq!(&buf, b"ping", "interactive echo mismatch (R09)");
    })
    .await
    .expect("Interactive flow timed out — head-of-line blocking by bulk flow (R09)");

    client.close();
}

// ─────────────────────────────────────────────────────────────────────────────
// R10 — Large-flow timeout self-destruction
// ─────────────────────────────────────────────────────────────────────────────

/// R10: A large sustained TCP transfer must not be killed by a write timeout.
///
/// Proof: transfers 512 KiB through the proxy within a generous timeout.
/// A fixed short write-timeout would fire while QUIC flow control is
/// legitimately blocking writes, destroying the flow. No such timeout exists
/// in the current implementation (Rule 8).
#[tokio::test]
async fn r10_large_flow_not_killed_by_write_timeout() {
    const PAYLOAD_SIZE: usize = 512 * 1024;

    let echo_addr = spawn_echo_server().await;
    let server_addr = spawn_server("r10").await;
    let client = connect("r10", server_addr).await;

    let mut proxy = tokio::time::timeout(
        Duration::from_secs(5),
        client.tcp(&echo_addr.to_string()),
    )
    .await
    .expect("tcp() timed out")
    .expect("tcp() failed");

    let payload: Vec<u8> = (0u8..=255).cycle().take(PAYLOAD_SIZE).collect();
    proxy.write_all(&payload).await.expect("write failed");
    proxy.shutdown().await.expect("shutdown failed");

    let mut received = Vec::with_capacity(PAYLOAD_SIZE);
    tokio::time::timeout(Duration::from_secs(15), proxy.read_to_end(&mut received))
        .await
        .expect("512 KiB transfer timed out — write timeout killed the flow? (R10)")
        .expect("read_to_end failed");

    assert_eq!(received, payload, "Data integrity failed on 512 KiB transfer (R10)");
    client.close();
}

// ─────────────────────────────────────────────────────────────────────────────
// R11 — Download-throughput self-sabotage
// ─────────────────────────────────────────────────────────────────────────────

/// R11: Long-running downloads must not collapse because of internal design.
///
/// Proof: transfers 1 MiB through the proxy. Scheduler, permit, queue, or
/// buffering bugs that degrade throughput over time manifest as a timeout
/// on this test. A successful run proves sustained throughput.
#[tokio::test]
async fn r11_large_download_throughput_sustained() {
    const PAYLOAD_SIZE: usize = 1024 * 1024;

    let echo_addr = spawn_echo_server().await;
    let server_addr = spawn_server("r11").await;
    let client = connect("r11", server_addr).await;

    let mut proxy = tokio::time::timeout(
        Duration::from_secs(5),
        client.tcp(&echo_addr.to_string()),
    )
    .await
    .expect("tcp() timed out")
    .expect("tcp() failed");

    let payload: Vec<u8> = (0u8..=255).cycle().take(PAYLOAD_SIZE).collect();
    proxy.write_all(&payload).await.expect("write failed");
    proxy.shutdown().await.expect("shutdown failed");

    let mut received = Vec::with_capacity(PAYLOAD_SIZE);
    tokio::time::timeout(Duration::from_secs(30), proxy.read_to_end(&mut received))
        .await
        .expect("1 MiB download timed out — internal throughput collapse (R11)")
        .expect("read_to_end failed");

    assert_eq!(received.len(), PAYLOAD_SIZE, "Must receive full 1 MiB (R11)");
    assert_eq!(received, payload, "Data integrity failed on 1 MiB transfer (R11)");
    client.close();
}

// ─────────────────────────────────────────────────────────────────────────────
// R12 — 4K or 8K playback stutter under mixed traffic
// ─────────────────────────────────────────────────────────────────────────────

/// R12: Interactive TCP and UDP must remain responsive during a sustained
/// bulk TCP transfer (simulating 4K video playback alongside web browsing).
///
/// Proof: all three traffic types — bulk TCP, interactive TCP echo, and UDP
/// echo — must succeed concurrently. The bulk flow must not starve the other
/// two via scheduling, queueing, or timeout mistakes (Rules 9, 3).
#[tokio::test]
async fn r12_mixed_traffic_interactive_and_udp_unaffected_by_bulk() {
    let echo_addr = spawn_echo_server().await;
    let sink_addr = spawn_sink_server().await;
    let udp_addr = spawn_udp_echo().await;
    let server_addr = spawn_server("r12").await;
    let client = Arc::new(connect("r12", server_addr).await);

    // Bulk TCP (simulating a large sustained download).
    let bulk_client = Arc::clone(&client);
    let bulk_sink = sink_addr.to_string();
    let bulk_handle = tokio::spawn(async move {
        if let Ok(mut proxy) = bulk_client.tcp(&bulk_sink).await {
            let data = vec![0xAAu8; 64 * 1024];
            for _ in 0..16 {
                if proxy.write_all(&data).await.is_err() {
                    break;
                }
            }
            let _ = proxy.shutdown().await;
        }
    });

    // Give the bulk flow a head start.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Interactive TCP echo (simulating a web request during download).
    let interactive_client = Arc::clone(&client);
    let echo = echo_addr.to_string();
    let interactive_handle = tokio::spawn(async move {
        let mut proxy = interactive_client.tcp(&echo).await.expect("interactive tcp");
        proxy.write_all(b"hello").await.expect("write");
        let mut buf = [0u8; 5];
        proxy.read_exact(&mut buf).await.expect("read");
        buf
    });

    // UDP echo (simulating real-time traffic such as VoIP or gaming).
    let udp_conn = tokio::time::timeout(Duration::from_secs(5), client.udp())
        .await
        .expect("udp() timed out")
        .expect("udp() failed");
    udp_conn
        .send(b"r12-udp", &udp_addr.to_string())
        .await
        .expect("UDP send failed");

    // Interactive TCP must complete promptly — not head-of-line blocked.
    let interactive_result = tokio::time::timeout(Duration::from_secs(5), interactive_handle)
        .await
        .expect("Interactive TCP timed out during bulk transfer (R12)")
        .expect("interactive task panicked");
    assert_eq!(&interactive_result, b"hello", "Interactive echo mismatch (R12)");

    // UDP must arrive promptly — not starved by bulk TCP scheduling.
    let (udp_data, _) = tokio::time::timeout(Duration::from_secs(3), udp_conn.receive())
        .await
        .expect("UDP timed out during bulk transfer — scheduler starvation? (R12)")
        .expect("UDP receive failed");
    assert_eq!(udp_data, b"r12-udp", "UDP echo mismatch (R12)");

    udp_conn.close();
    let _ = bulk_handle.await;
    client.close();
}

// ─────────────────────────────────────────────────────────────────────────────
// R13 — Datagram buffer mis-sizing
// ─────────────────────────────────────────────────────────────────────────────

/// R13: A burst of UDP datagrams must all be received without loss.
///
/// Proof: if datagram send/receive buffers were set to MAX_DATAGRAM_FRAME_SIZE
/// (~1200 bytes, one datagram), all but one datagram in the burst would be
/// silently dropped. Using Quinn defaults (large buffer) allows all burst
/// datagrams to be queued and delivered. 10 datagrams sent, all 10 must
/// echo back (Rule 11).
#[tokio::test]
async fn r13_udp_burst_no_datagram_loss() {
    const NUM: usize = 10;

    let udp_addr = spawn_udp_echo().await;
    let server_addr = spawn_server("r13").await;
    let client = connect("r13", server_addr).await;

    let udp = tokio::time::timeout(Duration::from_secs(5), client.udp())
        .await
        .expect("udp() timed out")
        .expect("udp() failed");

    let target = udp_addr.to_string();

    // Send all datagrams in rapid burst — no yield between sends.
    for i in 0u8..NUM as u8 {
        udp.send(&[i; 32], &target).await.expect("UDP burst send failed");
    }

    // Collect echoed datagrams within a bounded total window.
    let mut received_ids: HashSet<u8> = HashSet::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if received_ids.len() == NUM {
            break;
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, udp.receive()).await {
            Ok(Ok((data, _))) if !data.is_empty() => {
                received_ids.insert(data[0]);
            }
            _ => break,
        }
    }

    assert_eq!(
        received_ids.len(),
        NUM,
        "All {NUM} burst datagrams must be received; got {} — \
         datagram buffer mis-sizing drops excess? (R13)",
        received_ids.len()
    );

    udp.close();
    client.close();
}

// ─────────────────────────────────────────────────────────────────────────────
// R14 — Port-hopping recovery without tunnel rebuild
// ─────────────────────────────────────────────────────────────────────────────

/// R14: Port-hopping recovers traffic without a full tunnel rebuild.
///
/// Proof: uses UdpHopSocket (5-second hop interval) with generation-aware
/// FaultInjectionSocket. After verifying initial traffic (generation 0),
/// injects DropGeneration(0) to simulate tuple-specific impairment on the
/// current hop path. When the hop timer fires and the generation counter
/// increments to 1, the fault clears automatically (DropGeneration(0) no
/// longer matches). The test asserts:
///   1. Traffic recovers after the hop (TCP echo succeeds on the new path).
///   2. connect_count == 1 (no tunnel rebuild — the hop absorbed the disruption).
///
/// This proves the layered recovery model: UdpHopSocket absorbs path-local
/// disruption before TunnelManager considers a full tunnel rebuild.
/// Complements R15-A (socket-wide brief outage, QUIC self-heals) and R15-B
/// (prolonged outage, forced tunnel rebuild).
#[tokio::test]
async fn r14_port_hop_recovers_without_tunnel_rebuild() {
    use rysteria::core::client::ReconnectableClient;
    use std::sync::atomic::{AtomicU8, AtomicU64, AtomicU32, Ordering};

    let echo_addr = spawn_echo_server().await;
    let server_addr = spawn_server("r14").await;

    // Shared atoms for generation-aware fault injection.
    let fault_policy = Arc::new(AtomicU8::new(FaultPolicy::Pass as u8));
    let target_generation = Arc::new(AtomicU64::new(0));
    let hop_generation = Arc::new(AtomicU64::new(0));
    let policy_for_config = Arc::clone(&fault_policy);
    let target_for_config = Arc::clone(&target_generation);
    let hopgen_for_config = Arc::clone(&hop_generation);

    // Connect counter — must remain 1 (hop recovery, NOT tunnel rebuild).
    let connect_count = Arc::new(AtomicU32::new(0));
    let cc_for_callback = Arc::clone(&connect_count);

    let rc = ReconnectableClient::new(
        move || {
            let policy = Arc::clone(&policy_for_config);
            let target = Arc::clone(&target_for_config);
            let hopgen = Arc::clone(&hopgen_for_config);
            let hopgen_for_hop = Arc::clone(&hopgen);

            Ok(ClientConfig {
                auth: "r14".to_string(),
                server_addr,
                server_name: "localhost".to_string(),
                tls: ClientTlsConfig::InsecureSkipVerify { client_identity: None },
                bandwidth_tx: 0,
                bandwidth_rx: 0,
                transport: None,
                udp_socket_factory: None,
                packet_transport: ClientPacketTransport::UdpHop {
                    addrs: vec![server_addr],
                    hop_interval: Duration::from_secs(5),
                },
                obfs: None,
                fast_open: false,
                persistent_tunnel: true,
                tunnel_keepalive_secs: 25,
                conn_send_budget: None,
                socket_wrapper: Some(Arc::new(move |inner| {
                    FaultInjectionSocket::with_generation(
                        inner,
                        Arc::clone(&policy),
                        Arc::clone(&target),
                        Arc::clone(&hopgen),
                    )
                })),
                hop_generation: Some(hopgen_for_hop),
            })
        },
        Some(move |_client: Arc<Client>, _info: &rysteria::core::client::HandshakeInfo, _n: u32| {
            cc_for_callback.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }),
        false, // eager connect
        None,
    )
    .await
    .expect("ReconnectableClient creation failed");

    assert_eq!(
        connect_count.load(Ordering::Relaxed),
        1,
        "Initial connection: connect_count must be 1"
    );

    // Step 1: TCP echo works normally (Pass policy, generation 0).
    {
        let mut proxy = tokio::time::timeout(
            Duration::from_secs(5),
            rc.tcp(&echo_addr.to_string()),
        )
        .await
        .expect("tcp() timed out (pre-fault)")
        .expect("tcp() failed (pre-fault)");

        proxy.write_all(b"hop_ok").await.expect("write failed");
        let mut buf = [0u8; 6];
        tokio::time::timeout(Duration::from_secs(3), proxy.read_exact(&mut buf))
            .await
            .expect("read timed out (pre-fault)")
            .unwrap();
        assert_eq!(&buf, b"hop_ok", "Pre-fault echo mismatch");
    }

    // Step 2: Snapshot current generation and inject generation-targeted fault.
    // DropGeneration(current_gen) drops packets only while the hop counter
    // matches the snapshot. After the hop fires, generation increments and
    // the fault clears automatically.
    let current_gen = hop_generation.load(Ordering::Relaxed);
    target_generation.store(current_gen, Ordering::Relaxed);
    fault_policy.store(FaultPolicy::DropGeneration as u8, Ordering::Relaxed);

    // Step 3: Wait for the hop to fire (generation advances past current_gen).
    // UdpHopSocket hops every 5s; allow up to 10s for the hop to complete.
    let hop_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if hop_generation.load(Ordering::Relaxed) > current_gen {
            break;
        }
        if Instant::now() >= hop_deadline {
            panic!(
                "Hop did not fire within 10s — generation stuck at {} (R14)",
                hop_generation.load(Ordering::Relaxed)
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Generation has advanced. DropGeneration(current_gen) no longer matches
    // the live counter, so traffic should resume without policy change.

    // Step 4: Verify traffic recovered via TCP echo.
    let mut recovered = false;
    for attempt in 0..5 {
        match tokio::time::timeout(
            Duration::from_secs(10),
            rc.tcp(&echo_addr.to_string()),
        )
        .await
        {
            Ok(Ok(mut proxy)) => {
                proxy.write_all(b"hop_ok").await.expect("write failed (post-hop)");
                let mut buf = [0u8; 6];
                match tokio::time::timeout(Duration::from_secs(5), proxy.read_exact(&mut buf)).await
                {
                    Ok(Ok(_)) => {
                        assert_eq!(&buf, b"hop_ok", "Post-hop echo mismatch");
                        recovered = true;
                        break;
                    }
                    _ => {
                        // Read failed — transport may still be settling after hop.
                    }
                }
            }
            Ok(Err(_)) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(_) => {
                panic!(
                    "tcp() timed out on recovery attempt {attempt} — \
                     port hop failed to restore traffic (R14)"
                );
            }
        }
    }

    assert!(
        recovered,
        "Traffic must recover after port hop without tunnel rebuild (R14)"
    );

    // Step 5: The critical negative assertion — no tunnel rebuild occurred.
    // connect_count must still be 1, proving the hop (not a full reconnect)
    // absorbed the disruption. This distinguishes R14 from R15-B.
    let final_count = connect_count.load(Ordering::Relaxed);
    assert_eq!(
        final_count, 1,
        "connect_count must remain 1 (hop recovery, not tunnel rebuild), got {final_count} (R14)"
    );

    let _ = rc.close().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// R15 — Recovery after brief interruption + forced tunnel rebuild
// ─────────────────────────────────────────────────────────────────────────────

use rysteria::extras::transport::fault::{FaultInjectionSocket, FaultPolicy};

/// R15-A: QUIC+Brutal self-heals after a brief total network outage.
///
/// Proof: uses FaultInjectionSocket to simulate a 2-second total outage
/// (DropAll policy), then restores the link. Because the default idle timeout
/// is 30s and the outage is only 2s, the QUIC connection survives without
/// reconnect. A TCP echo through the recovered client proves the transport
/// layer resumed normally.
///
/// This test does NOT prove TunnelManager reconnect — see
/// r15_forced_tunnel_rebuild_after_prolonged_outage for that.
#[tokio::test]
async fn r15_brief_interruption_recovery() {
    use rysteria::core::client::ReconnectableClient;
    use std::sync::atomic::AtomicU8;

    let echo_addr = spawn_echo_server().await;
    let server_addr = spawn_server("r15").await;

    // Shared fault policy — test code toggles this to inject/remove faults.
    let fault_policy = Arc::new(AtomicU8::new(FaultPolicy::Pass as u8));
    let policy_for_config = Arc::clone(&fault_policy);

    // ReconnectableClient with FaultInjectionSocket injected via socket_wrapper.
    let rc = ReconnectableClient::new(
        move || {
            let policy = Arc::clone(&policy_for_config);
            Ok(ClientConfig {
                auth: "r15".to_string(),
                server_addr,
                server_name: "localhost".to_string(),
                tls: ClientTlsConfig::InsecureSkipVerify { client_identity: None },
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
                socket_wrapper: Some(Arc::new(move |inner| {
                    FaultInjectionSocket::with_policy(inner, Arc::clone(&policy))
                })),
                hop_generation: None,
            })
        },
        None::<fn(Arc<Client>, &rysteria::core::client::HandshakeInfo, u32)>,
        false, // eager connect
        None,
    )
    .await
    .expect("ReconnectableClient creation failed");

    // Step 1: TCP echo works normally (Pass policy).
    {
        let mut proxy = tokio::time::timeout(
            Duration::from_secs(5),
            rc.tcp(&echo_addr.to_string()),
        )
        .await
        .expect("tcp() timed out (pre-fault)")
        .expect("tcp() failed (pre-fault)");

        proxy.write_all(b"before").await.expect("write failed");
        let mut buf = [0u8; 6];
        tokio::time::timeout(Duration::from_secs(3), proxy.read_exact(&mut buf))
            .await
            .expect("read timed out (pre-fault)")
            .unwrap();
        assert_eq!(&buf, b"before", "Pre-fault echo mismatch");
    }

    // Step 2: Inject total outage.
    fault_policy.store(FaultPolicy::DropAll as u8, std::sync::atomic::Ordering::Relaxed);

    // Wait 2s — well under the 30s idle timeout, so the QUIC connection
    // survives. This tests transport-level resilience, not reconnect.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 3: Restore the link.
    fault_policy.store(FaultPolicy::Pass as u8, std::sync::atomic::Ordering::Relaxed);

    // Step 4: The connection should still be alive (2s < 30s timeout).
    // Retry up to 3 times in case in-flight streams need to settle.
    let mut recovered = false;
    for attempt in 0..3 {
        match tokio::time::timeout(
            Duration::from_secs(10),
            rc.tcp(&echo_addr.to_string()),
        )
        .await
        {
            Ok(Ok(mut proxy)) => {
                proxy.write_all(b"after").await.expect("write failed (recovery)");
                let mut buf = [0u8; 5];
                match tokio::time::timeout(Duration::from_secs(5), proxy.read_exact(&mut buf)).await
                {
                    Ok(Ok(_)) => {
                        assert_eq!(&buf, b"after", "Recovery echo mismatch");
                        recovered = true;
                        break;
                    }
                    _ => {
                        // Read failed — connection may still be dead, retry.
                    }
                }
            }
            Ok(Err(_)) => {
                // Stream-level error possible while transport settles.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(_) => {
                panic!(
                    "tcp() timed out on recovery attempt {attempt} — \
                     transport failed to resume (R15-A)"
                );
            }
        }
    }

    assert!(
        recovered,
        "QUIC transport must self-heal after 2s outage (R15-A)"
    );

    let _ = rc.close().await;
}

/// R15-B: TunnelManager rebuilds the tunnel after a prolonged outage kills
/// the QUIC connection.
///
/// Proof: configures a short max_idle_timeout (3s) and injects a 5-second
/// total outage via FaultInjectionSocket. Because 5s > 3s idle timeout, the
/// QUIC connection is guaranteed dead. After restoring the link, the test
/// asserts:
///   1. connect_count increased from 1 to >= 2 (factory called again).
///   2. TCP echo succeeds on the new tunnel (end-to-end recovery).
///
/// This test proves TunnelManager automatic reconnect, not just transport
/// resilience. See r15_brief_interruption_recovery for the complementary test.
#[tokio::test]
async fn r15_forced_tunnel_rebuild_after_prolonged_outage() {
    use rysteria::core::client::ReconnectableClient;
    use std::sync::atomic::{AtomicU8, AtomicU32};

    let echo_addr = spawn_echo_server().await;
    let server_addr = spawn_server("r15b").await;

    // Shared fault policy — test code toggles this to inject/remove faults.
    let fault_policy = Arc::new(AtomicU8::new(FaultPolicy::Pass as u8));
    let policy_for_config = Arc::clone(&fault_policy);

    // Connect counter — incremented by connected_func on each new connection.
    let connect_count = Arc::new(AtomicU32::new(0));
    let cc_for_callback = Arc::clone(&connect_count);

    let rc = ReconnectableClient::new(
        move || {
            let policy = Arc::clone(&policy_for_config);
            // Each call to config_func creates a fresh transport config with
            // the short idle timeout, because Client::connect() takes ownership.
            let mut transport = quinn::TransportConfig::default();
            if let Ok(idle_timeout) = Duration::from_secs(3).try_into() {
                transport.max_idle_timeout(Some(idle_timeout));
            }
            transport.keep_alive_interval(None);

            Ok(ClientConfig {
                auth: "r15b".to_string(),
                server_addr,
                server_name: "localhost".to_string(),
                tls: ClientTlsConfig::InsecureSkipVerify { client_identity: None },
                bandwidth_tx: 0,
                bandwidth_rx: 0,
                transport: Some(transport),
                udp_socket_factory: None,
                packet_transport: ClientPacketTransport::Udp,
                obfs: None,
                fast_open: false,
                persistent_tunnel: true,
                tunnel_keepalive_secs: 25,
                conn_send_budget: None,
                socket_wrapper: Some(Arc::new(move |inner| {
                    FaultInjectionSocket::with_policy(inner, Arc::clone(&policy))
                })),
                hop_generation: None,
            })
        },
        Some(move |_client: Arc<Client>, _info: &rysteria::core::client::HandshakeInfo, _n: u32| {
            cc_for_callback.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }),
        false, // eager connect
        None,
    )
    .await
    .expect("ReconnectableClient creation failed");

    // After eager connect, factory should have been called exactly once.
    assert_eq!(
        connect_count.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "Initial connection: connect_count must be 1"
    );

    // Step 1: TCP echo works normally (Pass policy).
    {
        let mut proxy = tokio::time::timeout(
            Duration::from_secs(5),
            rc.tcp(&echo_addr.to_string()),
        )
        .await
        .expect("tcp() timed out (pre-fault)")
        .expect("tcp() failed (pre-fault)");

        proxy.write_all(b"alive1").await.expect("write failed");
        let mut buf = [0u8; 6];
        tokio::time::timeout(Duration::from_secs(3), proxy.read_exact(&mut buf))
            .await
            .expect("read timed out (pre-fault)")
            .unwrap();
        assert_eq!(&buf, b"alive1", "Pre-fault echo mismatch");
    }

    // Step 2: Inject prolonged outage (5s > 3s idle timeout).
    fault_policy.store(FaultPolicy::DropAll as u8, std::sync::atomic::Ordering::Relaxed);

    // Wait long enough for the QUIC connection to die (idle timeout = 3s).
    // 5s gives comfortable margin above the 3s threshold.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Step 3: Restore the link.
    fault_policy.store(FaultPolicy::Pass as u8, std::sync::atomic::Ordering::Relaxed);

    // Step 4: Retry tcp() — the old connection is dead, so TunnelManager
    // must detect the failure, invalidate, and rebuild with a fresh
    // QUIC connection + auth handshake.
    let mut recovered = false;
    for attempt in 0..5 {
        match tokio::time::timeout(
            Duration::from_secs(10),
            rc.tcp(&echo_addr.to_string()),
        )
        .await
        {
            Ok(Ok(mut proxy)) => {
                proxy.write_all(b"alive2").await.expect("write failed (recovery)");
                let mut buf = [0u8; 6];
                match tokio::time::timeout(Duration::from_secs(5), proxy.read_exact(&mut buf)).await
                {
                    Ok(Ok(_)) => {
                        assert_eq!(&buf, b"alive2", "Recovery echo mismatch");
                        recovered = true;
                        break;
                    }
                    _ => {
                        // Read failed — new connection may still be settling.
                    }
                }
            }
            Ok(Err(_)) => {
                // ClosedError expected — old tunnel is dead. TunnelManager
                // invalidates on this call and reconnects on the next.
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(_) => {
                panic!(
                    "tcp() timed out on recovery attempt {attempt} — \
                     TunnelManager reconnect stalled (R15-B)"
                );
            }
        }
    }

    assert!(
        recovered,
        "TunnelManager must rebuild tunnel after prolonged outage (R15-B)"
    );

    // The hard proof: connect_count must have increased, proving the factory
    // was called again to create a new QUIC connection.
    let final_count = connect_count.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        final_count >= 2,
        "connect_count must be >= 2 after tunnel rebuild, got {final_count} (R15-B)"
    );

    let _ = rc.close().await;
}
