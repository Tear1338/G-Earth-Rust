//! SOCKS5 CONNECT, with optional RFC 1929 username/password authentication.
use std::{
    io::{self, Read, Write},
    net::{IpAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};
#[derive(Clone, Debug)]
pub struct SocksConfig {
    pub proxy: String,
    pub credentials: Option<(String, String)>,
}
impl SocksConfig {
    /// Connect without blocking the async runtime. The destination hostname is
    /// sent to the proxy, so it is never resolved locally.
    #[cfg(feature = "web")]
    pub async fn connect_async(&self, target: &str) -> io::Result<tokio::net::TcpStream> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (host, port) = target.rsplit_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "target requires host:port")
        })?;
        let port: u16 = port
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid target port"))?;
        let host = if let Some(ip) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            ip.parse::<std::net::Ipv6Addr>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid bracketed IPv6 address",
                )
            })?;
            ip
        } else {
            if host.is_empty() || host.contains(['[', ']', ':']) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid target host; IPv6 addresses require brackets",
                ));
            }
            host
        };
        let mut request = vec![5, 1, 0];
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                request.push(1);
                request.extend_from_slice(&ip.octets());
            }
            Ok(IpAddr::V6(ip)) => {
                request.push(4);
                request.extend_from_slice(&ip.octets());
            }
            Err(_) => {
                let length = u8::try_from(host.len())
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "SOCKS hostname must be 1..255 bytes",
                        )
                    })?;
                request.extend_from_slice(&[3, length]);
                request.extend_from_slice(host.as_bytes());
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        let authentication = self
            .credentials
            .as_ref()
            .map(|(user, password)| {
                let user_len = u8::try_from(user.len())
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "SOCKS username must be 1..255 bytes",
                        )
                    })?;
                let password_len = u8::try_from(password.len())
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "SOCKS password must be 1..255 bytes",
                        )
                    })?;
                let mut bytes = vec![1, user_len];
                bytes.extend_from_slice(user.as_bytes());
                bytes.push(password_len);
                bytes.extend_from_slice(password.as_bytes());
                Ok::<_, io::Error>(bytes)
            })
            .transpose()?;
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = tokio::net::TcpStream::connect(&self.proxy).await?;
            let method = if authentication.is_some() { 2 } else { 0 };
            stream.write_all(&[5, 1, method]).await?;
            let mut selected = [0; 2];
            stream.read_exact(&mut selected).await?;
            if selected != [5, method] {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS authentication method rejected",
                ));
            }
            if let Some(authentication) = authentication {
                stream.write_all(&authentication).await?;
                stream.read_exact(&mut selected).await?;
                if selected != [1, 0] {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SOCKS credentials rejected",
                    ));
                }
            }
            stream.write_all(&request).await?;
            let mut reply = [0; 4];
            stream.read_exact(&mut reply).await?;
            if reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("SOCKS CONNECT failed ({})", reply[1]),
                ));
            }
            let length = match reply[3] {
                1 => 4,
                4 => 16,
                3 => {
                    let mut length = [0];
                    stream.read_exact(&mut length).await?;
                    usize::from(length[0])
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid SOCKS address type",
                    ))
                }
            };
            let mut bound = vec![0; length + 2];
            stream.read_exact(&mut bound).await?;
            Ok(stream)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS handshake timed out"))?
    }
    pub fn connect(&self, target: &str) -> io::Result<TcpStream> {
        let (host, port) = target.rsplit_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "target requires host:port")
        })?;
        let port: u16 = port
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid target port"))?;
        let host = if let Some(ip) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            ip.parse::<std::net::Ipv6Addr>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid bracketed IPv6 address",
                )
            })?;
            ip
        } else {
            if host.is_empty() || host.contains(['[', ']', ':']) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid target host; IPv6 addresses require brackets",
                ));
            }
            host
        };
        if host.len() > 255 && host.parse::<IpAddr>().is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS hostname must be 1..255 bytes",
            ));
        }
        let addresses: Vec<_> = self.proxy.to_socket_addrs()?.collect();
        let mut stream = addresses
            .iter()
            .find_map(|a| TcpStream::connect_timeout(a, Duration::from_secs(2)).ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionRefused, "SOCKS proxy unreachable")
            })?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let greeting = if self.credentials.is_some() {
            vec![5, 1, 2]
        } else {
            vec![5, 1, 0]
        };
        stream.write_all(&greeting)?;
        let mut selected = [0; 2];
        stream.read_exact(&mut selected)?;
        if selected[0] != 5 || selected[1] != greeting[2] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS authentication method rejected",
            ));
        }
        if let Some((user, password)) = &self.credentials {
            let u = u8::try_from(user.len())
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "SOCKS username must be 1..255 bytes",
                    )
                })?;
            let p = u8::try_from(password.len())
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "SOCKS password must be 1..255 bytes",
                    )
                })?;
            let mut auth = vec![1, u];
            auth.extend_from_slice(user.as_bytes());
            auth.push(p);
            auth.extend_from_slice(password.as_bytes());
            stream.write_all(&auth)?;
            stream.read_exact(&mut selected)?;
            if selected != [1, 0] {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS credentials rejected",
                ));
            }
        }
        let mut request = vec![5, 1, 0];
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                request.push(1);
                request.extend_from_slice(&ip.octets());
            }
            Ok(IpAddr::V6(ip)) => {
                request.push(4);
                request.extend_from_slice(&ip.octets());
            }
            Err(_) => {
                let n = u8::try_from(host.len())
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "SOCKS hostname must be 1..255 bytes",
                        )
                    })?;
                request.extend_from_slice(&[3, n]);
                request.extend_from_slice(host.as_bytes());
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request)?;
        let mut reply = [0; 4];
        stream.read_exact(&mut reply)?;
        if reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("SOCKS CONNECT failed ({})", reply[1]),
            ));
        }
        let n = match reply[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut n = [0];
                stream.read_exact(&mut n)?;
                n[0] as usize
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SOCKS address type",
                ))
            }
        };
        let mut bound = vec![0; n + 2];
        stream.read_exact(&mut bound)?;
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;
        Ok(stream)
    }
}
