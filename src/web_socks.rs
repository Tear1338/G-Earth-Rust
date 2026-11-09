//! Upstream transport selection for the HTTP proxy.
use crate::socks::SocksConfig;
use hudsucker::{
    hyper::Uri,
    hyper_util::{client::legacy::connect::HttpConnector, rt::TokioIo},
    UpstreamDialer,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::net::TcpStream;
use tower_service::Service;

fn target(uri: &Uri) -> io::Result<String> {
    let host = uri
        .host()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "upstream URI has no host"))?;
    let default_port = match uri.scheme_str() {
        Some("http" | "ws") => 80,
        Some("https" | "wss") => 443,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upstream URI has no supported scheme",
            ))
        }
    };
    let authority = uri.authority().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "upstream URI has no authority")
    })?;
    let host_port = authority.as_str().rsplit('@').next().unwrap_or_default();
    let suffix = host_port
        .strip_prefix(host)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid upstream authority"))?;
    if !suffix.is_empty() && uri.port_u16().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid upstream port",
        ));
    }
    let port = match uri.port_u16() {
        Some(port) => port,
        None => default_port,
    };
    Ok(format!("{host}:{port}"))
}

#[derive(Clone)]
pub(crate) struct OutboundConnector {
    direct: HttpConnector,
    socks: Option<SocksConfig>,
}
impl OutboundConnector {
    pub(crate) fn new(socks: Option<SocksConfig>) -> Self {
        let mut direct = HttpConnector::new();
        direct.enforce_http(false);
        Self { direct, socks }
    }
}
impl Service<Uri> for OutboundConnector {
    type Response = TokioIo<TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.socks.is_some() {
            Poll::Ready(Ok(()))
        } else {
            self.direct.poll_ready(cx).map_err(io::Error::other)
        }
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        if let Some(socks) = self.socks.clone() {
            Box::pin(async move { socks.connect_async(&target(&uri)?).await.map(TokioIo::new) })
        } else {
            let connecting = self.direct.call(uri);
            Box::pin(async move { connecting.await.map_err(io::Error::other) })
        }
    }
}

pub(crate) fn dialer(socks: SocksConfig) -> UpstreamDialer {
    Arc::new(move |uri| {
        let socks = socks.clone();
        Box::pin(async move { socks.connect_async(&target(&uri)?).await })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_targets_preserve_domain_ipv6_and_default_ports() {
        for (uri, expected) in [
            ("http://example.invalid/path", "example.invalid:80"),
            ("https://example.invalid/path", "example.invalid:443"),
            ("wss://example.invalid:8443/path", "example.invalid:8443"),
            ("ws://[2001:db8::1]/", "[2001:db8::1]:80"),
        ] {
            assert_eq!(target(&uri.parse().unwrap()).unwrap(), expected);
        }
        assert!(target(&"/relative".parse().unwrap()).is_err());
        for invalid in [
            "http://example.invalid:bad/",
            "https://example.invalid:65536/",
            "ftp://example.invalid:443/",
        ] {
            if let Ok(uri) = invalid.parse() {
                assert!(target(&uri).is_err(), "{invalid}");
            }
        }
    }
}
