use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

pub type DispatchHandler =
    Arc<dyn Fn(TcpStream) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Proxy multiplexer: dispatch TCP connections by first byte.
///
/// `0x05` => SOCKS5, everything else => HTTP.
pub async fn serve(
    listener: TcpListener,
    socks_handler: DispatchHandler,
    http_handler: DispatchHandler,
) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let socks_handler = Arc::clone(&socks_handler);
        let http_handler = Arc::clone(&http_handler);
        tokio::spawn(async move {
            let mut first = [0u8; 1];
            let n = match stream.peek(&mut first).await {
                Ok(n) => n,
                Err(_) => return,
            };
            if n == 0 {
                return;
            }
            if first[0] == 0x05 {
                (socks_handler)(stream).await;
            } else {
                (http_handler)(stream).await;
            }
        });
    }
}
