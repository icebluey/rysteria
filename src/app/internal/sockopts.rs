use std::fmt;
use std::io;

#[derive(Debug, Clone, Default)]
pub struct SocketOptions {
    pub bind_interface: Option<String>,
    pub fwmark: Option<u32>,
    pub fd_control_unix_socket: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UnsupportedError {
    pub field: &'static str,
}

impl fmt::Display for UnsupportedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is not supported on this platform", self.field)
    }
}

impl std::error::Error for UnsupportedError {}

impl SocketOptions {
    pub fn check_supported(&self) -> Result<(), UnsupportedError> {
        #[cfg(target_os = "linux")]
        {
            let _ = self;
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            if self.bind_interface.is_some() {
                return Err(UnsupportedError {
                    field: "bindInterface",
                });
            }
            if self.fwmark.is_some() {
                return Err(UnsupportedError { field: "fwmark" });
            }
            if self.fd_control_unix_socket.is_some() {
                return Err(UnsupportedError {
                    field: "fdControlUnixSocket",
                });
            }
            Ok(())
        }
    }

    pub async fn listen_udp(&self) -> io::Result<tokio::net::UdpSocket> {
        let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        self.apply_to_udp_socket(&std_sock)?;
        std_sock.set_nonblocking(true)?;
        tokio::net::UdpSocket::from_std(std_sock)
    }

    pub fn apply_to_udp_socket(&self, socket: &std::net::UdpSocket) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CString;
            use std::os::fd::AsRawFd;
            use std::os::unix::net::UnixStream;
            use std::time::Duration;

            let fd = socket.as_raw_fd();

            if let Some(device) = &self.bind_interface {
                let dev = CString::new(device.as_str()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "bindInterface contains NUL")
                })?;

                let rc = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        dev.as_ptr().cast(),
                        (dev.as_bytes_with_nul().len()) as libc::socklen_t,
                    )
                };
                if rc != 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            if let Some(mark) = self.fwmark {
                let value: libc::c_int = mark as libc::c_int;
                let rc = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        (&value as *const libc::c_int).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if rc != 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            if let Some(path) = &self.fd_control_unix_socket {
                let stream = UnixStream::connect(path)?;
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                send_fd(stream.as_raw_fd(), fd)?;

                let mut ack = [0u8; 1];
                let mut s = stream;
                let n = std::io::Read::read(&mut s, &mut ack)?;
                if n != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "fd control unix socket closed unexpectedly",
                    ));
                }
            }

            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = socket;
            self.check_supported()
                .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e.to_string()))
        }
    }
}

#[cfg(target_os = "linux")]
fn send_fd(sock_fd: std::os::fd::RawFd, fd_to_send: std::os::fd::RawFd) -> io::Result<()> {
    use std::mem::{size_of, zeroed};
    use std::ptr;

    let mut data = [1u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };

    let control_len = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;
    let mut control = vec![0u8; control_len];

    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::other("failed to build SCM_RIGHTS header"));
        }

        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;

        let data_ptr = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
        ptr::write(data_ptr, fd_to_send as libc::c_int);
        msg.msg_controllen = (*cmsg).cmsg_len;

        if libc::sendmsg(sock_fd, &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}
