//! SOCKS-backed HTTPS metadata transport shared by minimal and web builds.
use crate::{packet_info::PacketInfoManager, socks::SocksConfig};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, Uri};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
};
use rustls::{self, crypto::aws_lc_rs};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};
use tokio::net::TcpStream;
use tower_service::Service;

pub(crate) fn target(uri: &Uri) -> io::Result<String> {
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

pub(crate) fn default_tls() -> io::Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(
        rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

pub(crate) async fn download_json(
    socks: SocksConfig,
    tls: rustls::ClientConfig,
    endpoint: &str,
) -> io::Result<Vec<u8>> {
    const MAX_BYTES: usize = 8 * 1024 * 1024;
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .wrap_connector(OutboundConnector::new(Some(socks)));
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);
    let mut url = url::Url::parse(endpoint).map_err(io::Error::other)?;
    tokio::time::timeout(Duration::from_secs(10), async {
        for redirects in 0..=5 {
            if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
                return Err(io::Error::other(
                    "metadata redirect must use HTTPS without URL credentials",
                ));
            }
            let request = Request::builder()
                .uri(url.as_str())
                .header("accept", "application/json")
                .body(Empty::<Bytes>::new())
                .map_err(io::Error::other)?;
            let response = client.request(request).await.map_err(io::Error::other)?;
            if response.status().is_redirection() {
                if redirects == 5 {
                    return Err(io::Error::other("too many metadata redirects"));
                }
                let location = response
                    .headers()
                    .get("location")
                    .ok_or_else(|| io::Error::other("metadata redirect has no location"))?
                    .to_str()
                    .map_err(io::Error::other)?;
                url = url.join(location).map_err(io::Error::other)?;
                continue;
            }
            if !response.status().is_success() {
                return Err(io::Error::other(format!(
                    "metadata HTTP status {}",
                    response.status()
                )));
            }
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame.map_err(io::Error::other)?.into_data() {
                    if data.len() > MAX_BYTES.saturating_sub(bytes.len()) {
                        return Err(io::Error::other("metadata exceeds 8 MiB"));
                    }
                    bytes.extend_from_slice(&data);
                }
            }
            return Ok(bytes);
        }
        Err(io::Error::other("too many metadata redirects"))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "metadata request timed out"))?
}

pub(crate) fn fetch_sulek(
    socks: SocksConfig,
    requested: &str,
    origins: bool,
) -> io::Result<PacketInfoManager> {
    let cache_dir = crate::settings::Settings::default_path()
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("packet-identifiers");
    fetch_sulek_using(
        socks,
        default_tls()?,
        "https://api.sulek.dev",
        &cache_dir,
        requested,
        origins,
        SystemTime::now(),
    )
}

pub(crate) fn fetch_sulek_using(
    socks: SocksConfig,
    tls: rustls::ClientConfig,
    base: &str,
    cache_dir: &std::path::Path,
    requested: &str,
    origins: bool,
    now: SystemTime,
) -> io::Result<PacketInfoManager> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let version = crate::packet_info::resolve_sulek_version(requested, origins, || {
        runtime.block_on(download_json(
            socks.clone(),
            tls.clone(),
            &format!("{base}/releases?variant=shockwave-windows"),
        ))
    })?;
    let cache = cache_dir.join(format!(
        "{}-{version}.bin",
        if origins { "SHOCKWAVE" } else { "FLASH" }
    ));
    let endpoint = if origins {
        format!("{base}/releases/shockwave-windows/{version}/messages")
    } else {
        format!("{base}/releases/{version}/messages")
    };
    let mut database = PacketInfoManager::load_or_refresh(&cache, &version, now, || {
        let bytes = runtime.block_on(download_json(socks, tls, &endpoint))?;
        PacketInfoManager::from_json(&version, &bytes).map_err(io::Error::other)
    })?;
    if origins && database.entries().is_empty() {
        database.version = requested.to_owned();
    }
    Ok(database)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn origins_metadata_succeeds_via_authenticated_socks_without_web() {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["fixture.invalid".into()]).unwrap();
        let cert = cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(signing_key.serialize_der().into());
        let provider = Arc::new(aws_lc_rs::default_provider());
        let server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let client_tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for index in 0..2 {
                let (stream, _) = upstream.accept().await.unwrap();
                let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls.clone()))
                    .accept(stream)
                    .await
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 8192);
                }
                let path = if index == 0 {
                    "/releases?variant=shockwave-windows"
                } else {
                    "/releases/shockwave-windows/ORIG-2/messages"
                };
                assert!(request.starts_with(format!("GET {path} HTTP/1.1\r\n").as_bytes()));
                let body = if index == 0 {
                    r#"[{"version":"ORIG-2"}]"#
                } else {
                    r#"{"messages":{"incoming":[],"outgoing":[{"id":900,"name":"KnownComposer"}]}}"#
                };
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = proxy.local_addr().unwrap();
        let socks_server = tokio::spawn(async move {
            let mut tasks = Vec::new();
            for _ in 0..2 {
                let (mut client, _) = proxy.accept().await.unwrap();
                tasks.push(tokio::spawn(async move {
                    let mut greeting = [0; 3];
                    client.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 1, 2]);
                    client.write_all(&[5, 2]).await.unwrap();
                    let mut auth = [0; 5];
                    client.read_exact(&mut auth).await.unwrap();
                    assert_eq!(auth, [1, 1, b'u', 1, b'p']);
                    client.write_all(&[1, 0]).await.unwrap();
                    let mut header = [0; 5];
                    client.read_exact(&mut header).await.unwrap();
                    assert_eq!(&header[..4], &[5, 1, 0, 3]);
                    let mut destination = vec![0; usize::from(header[4]) + 2];
                    client.read_exact(&mut destination).await.unwrap();
                    assert_eq!(&destination[..destination.len() - 2], b"fixture.invalid");
                    assert_eq!(
                        &destination[destination.len() - 2..],
                        &target.port().to_be_bytes()
                    );
                    let mut remote = TcpStream::connect(target).await.unwrap();
                    client
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
        });
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "gearth-socks-core-{:032x}",
            u128::from_ne_bytes(random)
        ));
        std::fs::create_dir(&directory).unwrap();
        let cache = directory.clone();
        let database = tokio::task::spawn_blocking(move || {
            fetch_sulek_using(
                SocksConfig {
                    proxy: address.to_string(),
                    credentials: Some(("u".into(), "p".into())),
                },
                client_tls,
                &format!("https://fixture.invalid:{}", target.port()),
                &cache,
                "ORIG-OLD",
                true,
                SystemTime::now(),
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(database.version, "ORIG-2");
        assert_eq!(database.entries()[0].header, 900);
        server.await.unwrap();
        socks_server.await.unwrap();
        std::fs::remove_file(directory.join("SHOCKWAVE-ORIG-2.bin")).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
