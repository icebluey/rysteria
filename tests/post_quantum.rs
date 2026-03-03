use std::sync::Arc;

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

#[test]
fn rustls_prefers_post_quantum_hybrid_kx_by_default() {
    let first_group = rustls::crypto::aws_lc_rs::DEFAULT_KX_GROUPS
        .first()
        .expect("aws-lc-rs default kx groups must not be empty")
        .name();

    assert_eq!(first_group, rustls::NamedGroup::X25519MLKEM768);
}

#[test]
fn client_and_server_negotiate_post_quantum_hybrid_kx() {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("generate cert");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("build server config");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("add root cert");
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server_cfg = Arc::new(server_cfg);
    let client_cfg = Arc::new(client_cfg);
    let server_name = ServerName::try_from("localhost")
        .expect("valid server name")
        .to_owned();

    let mut client = rustls::ClientConnection::new(client_cfg, server_name).expect("new client");
    let mut server = rustls::ServerConnection::new(server_cfg).expect("new server");

    while client.is_handshaking() || server.is_handshaking() {
        while client.wants_write() {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).expect("client write_tls");
            if buf.is_empty() {
                break;
            }
            let mut rd = &buf[..];
            server.read_tls(&mut rd).expect("server read_tls");
            server
                .process_new_packets()
                .expect("server process_new_packets");
        }

        while server.wants_write() {
            let mut buf = Vec::new();
            server.write_tls(&mut buf).expect("server write_tls");
            if buf.is_empty() {
                break;
            }
            let mut rd = &buf[..];
            client.read_tls(&mut rd).expect("client read_tls");
            client
                .process_new_packets()
                .expect("client process_new_packets");
        }
    }

    let client_group = client
        .negotiated_key_exchange_group()
        .expect("client has negotiated key exchange group")
        .name();
    let server_group = server
        .negotiated_key_exchange_group()
        .expect("server has negotiated key exchange group")
        .name();

    assert_eq!(client_group, rustls::NamedGroup::X25519MLKEM768);
    assert_eq!(server_group, rustls::NamedGroup::X25519MLKEM768);
}
