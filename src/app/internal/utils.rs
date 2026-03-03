use std::io;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

fn join_err_to_io(err: tokio::task::JoinError) -> io::Error {
    io::Error::other(format!("task join error: {err}"))
}

/// Bidirectional copy pump.
///
/// Spawns two independent tasks and returns when either direction exits.
/// The losing JoinHandle is dropped — this does NOT abort the task; it keeps
/// running until its I/O closes naturally via half-close propagation.
/// Never call abort(): that can drop a SendStream without finish(), sending a
/// QUIC RESET_STREAM that truncates in-flight data (blank pages, broken downloads).
pub(crate) async fn copy_two_way<L, R>(left: L, right: R) -> io::Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut left_r, mut left_w) = tokio::io::split(left);
    let (mut right_r, mut right_w) = tokio::io::split(right);

    let a = tokio::spawn(async move {
        tokio::io::copy(&mut left_r, &mut right_w).await?;
        right_w.shutdown().await?;
        Ok::<(), io::Error>(())
    });
    let b = tokio::spawn(async move {
        tokio::io::copy(&mut right_r, &mut left_w).await?;
        left_w.shutdown().await?;
        Ok::<(), io::Error>(())
    });

    tokio::select! {
        r = a => r.map_err(join_err_to_io)?,
        r = b => r.map_err(join_err_to_io)?,
    }
}
