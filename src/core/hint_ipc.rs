/// Unix-domain socket IPC listener for client cooperation hints.
///
/// Each authenticated QUIC connection creates one listener at a per-connection
/// path. Browser extensions, media players, or other cooperating processes
/// open the socket and send hint commands that influence scheduling priority
/// in the connection's `Scheduler`.
///
/// ## Wire format
///
/// One command per line (UTF-8, LF-terminated). Fields separated by `:`.
///
/// | Command | Format | VisibilityHint variant |
/// |---------|--------|------------------------|
/// | `v` | `v:{flow_id}:{generation}` | `FlowVisible` |
/// | `h` | `h:{flow_id}` | `FlowHidden` |
/// | `m` | `m:{flow_id}` | `MediaPlaying` |
/// | `p` | `p:{flow_id}` | `MediaPaused` |
/// | `g` | `g:{generation}` | `GenerationObsolete` |
///
/// All fields are decimal unsigned integers. Lines that do not parse are
/// silently ignored — partial or malformed input never crashes the listener.
///
/// ## Socket path
///
/// `/tmp/rysteria-hints-{conn_id_hex}.sock`
///
/// where `{conn_id_hex}` is the 16-digit lower-hex encoding of the 64-bit
/// `ConnId`. The path is removed when the connection closes.
///
/// ## Usage (shell example)
///
/// ```sh
/// # Mark flow 5 as visible in page generation 3:
/// echo "v:5:3" | socat - UNIX-CONNECT:/tmp/rysteria-hints-deadbeef01234567.sock
///
/// # Notify that generation 3 is obsolete (page navigated away):
/// echo "g:3"   | socat - UNIX-CONNECT:/tmp/rysteria-hints-deadbeef01234567.sock
/// ```
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::core::connection_actor::ConnControl;
use crate::core::internal::shard::ConnId;
use crate::core::scheduler::{FlowId, VisibilityHint};

/// Compute the Unix socket path for a given connection ID.
pub(crate) fn hint_socket_path(conn_id: ConnId) -> String {
    format!("/tmp/rysteria-hints-{:016x}.sock", conn_id.0)
}

/// Spawn a hint IPC listener task for one authenticated QUIC connection.
///
/// Binds a Unix domain socket at `hint_socket_path(conn_id)` and accepts
/// client connections. Each client connection is handled in its own task.
/// Hints are deserialized and forwarded to `ctrl_tx` as `ConnControl::ApplyHint`.
///
/// The listener is stopped (and the socket file removed) when `cancel` is
/// triggered — call `cancel.cancel()` when the QUIC connection closes.
pub(crate) fn spawn_hint_listener(
    conn_id: ConnId,
    ctrl_tx: mpsc::Sender<ConnControl>,
    cancel: CancellationToken,
) {
    let path = hint_socket_path(conn_id);

    // Remove any stale socket file left by a previous crash.
    let _ = std::fs::remove_file(&path);

    tokio::spawn(async move {
        // RAII: remove the socket file when this task exits (on drop).
        let _cleanup = DeferRemove(path.clone());

        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                tracing::debug!(path = %path, error = %e, "hint IPC: bind failed (non-fatal)");
                return;
            }
        };

        tracing::debug!(path = %path, "hint IPC: listening");

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            let ctrl = ctrl_tx.clone();
                            let c = cancel.clone();
                            tokio::spawn(handle_hint_client(stream, ctrl, c));
                        }
                        Err(_) => break,
                    }
                }
                _ = cancel.cancelled() => break,
            }
        }

        tracing::debug!(path = %path, "hint IPC: stopped");
    });
}

/// Handle one IPC client connection: read hint commands line by line.
async fn handle_hint_client(
    stream: tokio::net::UnixStream,
    ctrl_tx: mpsc::Sender<ConnControl>,
    cancel: CancellationToken,
) {
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    loop {
        tokio::select! {
            result = lines.next_line() => {
                match result {
                    Ok(Some(line)) => {
                        if let Some(hint) = parse_hint_line(&line) {
                            // Non-blocking send: drop hint if the channel is full
                            // (scheduler backpressure) rather than blocking the IPC client.
                            let _ = ctrl_tx.try_send(ConnControl::ApplyHint(hint));
                        }
                    }
                    _ => break, // EOF or I/O error — client disconnected
                }
            }
            _ = cancel.cancelled() => break,
        }
    }
}

/// Parse one line of hint text into a `VisibilityHint`.
///
/// Returns `None` for unrecognised commands or malformed input.
fn parse_hint_line(line: &str) -> Option<VisibilityHint> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None; // blank lines and comments are silently ignored
    }

    let mut parts = line.splitn(3, ':');
    let cmd = parts.next()?;

    match cmd {
        "v" => {
            let flow_id = parts.next()?.trim().parse::<u64>().ok()?;
            let generation = parts.next()?.trim().parse::<u64>().ok()?;
            Some(VisibilityHint::FlowVisible { flow_id: FlowId(flow_id), generation })
        }
        "h" => {
            let flow_id = parts.next()?.trim().parse::<u64>().ok()?;
            Some(VisibilityHint::FlowHidden { flow_id: FlowId(flow_id) })
        }
        "m" => {
            let flow_id = parts.next()?.trim().parse::<u64>().ok()?;
            Some(VisibilityHint::MediaPlaying { flow_id: FlowId(flow_id) })
        }
        "p" => {
            let flow_id = parts.next()?.trim().parse::<u64>().ok()?;
            Some(VisibilityHint::MediaPaused { flow_id: FlowId(flow_id) })
        }
        "g" => {
            let generation = parts.next()?.trim().parse::<u64>().ok()?;
            Some(VisibilityHint::GenerationObsolete { generation })
        }
        _ => None, // unknown command — silently ignored
    }
}

/// RAII guard: remove a file path when this value is dropped.
struct DeferRemove(String);

impl Drop for DeferRemove {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scheduler::FlowId;

    fn parse(s: &str) -> Option<VisibilityHint> {
        parse_hint_line(s)
    }

    #[test]
    fn test_parse_flow_visible() {
        let h = parse("v:42:7").unwrap();
        if let VisibilityHint::FlowVisible { flow_id, generation } = h {
            assert_eq!(flow_id, FlowId(42));
            assert_eq!(generation, 7);
        } else {
            panic!("expected FlowVisible");
        }
    }

    #[test]
    fn test_parse_flow_hidden() {
        let h = parse("h:100").unwrap();
        if let VisibilityHint::FlowHidden { flow_id } = h {
            assert_eq!(flow_id, FlowId(100));
        } else {
            panic!("expected FlowHidden");
        }
    }

    #[test]
    fn test_parse_media_playing() {
        let h = parse("m:3").unwrap();
        if let VisibilityHint::MediaPlaying { flow_id } = h {
            assert_eq!(flow_id, FlowId(3));
        } else {
            panic!("expected MediaPlaying");
        }
    }

    #[test]
    fn test_parse_media_paused() {
        let h = parse("p:3").unwrap();
        if let VisibilityHint::MediaPaused { flow_id } = h {
            assert_eq!(flow_id, FlowId(3));
        } else {
            panic!("expected MediaPaused");
        }
    }

    #[test]
    fn test_parse_generation_obsolete() {
        let h = parse("g:99").unwrap();
        if let VisibilityHint::GenerationObsolete { generation } = h {
            assert_eq!(generation, 99);
        } else {
            panic!("expected GenerationObsolete");
        }
    }

    #[test]
    fn test_parse_blank_and_comment() {
        assert!(parse("").is_none());
        assert!(parse("   ").is_none());
        assert!(parse("# a comment").is_none());
    }

    #[test]
    fn test_parse_unknown_command() {
        assert!(parse("x:1:2").is_none());
        assert!(parse("z:").is_none());
    }

    #[test]
    fn test_parse_malformed() {
        assert!(parse("v:notanumber:7").is_none());
        assert!(parse("v:1").is_none()); // missing generation field
        assert!(parse("g:").is_none()); // empty generation
    }

    #[test]
    fn test_hint_socket_path_format() {
        let path = hint_socket_path(ConnId(0xdeadbeef01234567));
        assert_eq!(path, "/tmp/rysteria-hints-deadbeef01234567.sock");
    }
}
