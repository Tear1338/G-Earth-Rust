//! Upstream transport selection for the HTTP proxy.
use crate::{packet_info::PacketInfoManager, socks::SocksConfig, web_proxy::NITRO_REVISION};
use http_body_util::BodyExt;
use hudsucker::{
    hyper::{Request, Uri},
    hyper_util::{
        client::legacy::{connect::HttpConnector, Client},
        rt::{TokioExecutor, TokioIo},
    },
    rustls::{self, crypto::aws_lc_rs},
    Body, UpstreamDialer,
};
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

fn default_tls() -> io::Result<rustls::ClientConfig> {
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

async fn download_json(
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
    let client: Client<_, Body> = Client::builder(TokioExecutor::new()).build(connector);
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
                .body(Body::empty())
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

pub(crate) fn fetch_nitro(socks: SocksConfig) -> io::Result<PacketInfoManager> {
    fetch_sulek(socks, NITRO_REVISION, false)
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

fn fetch_sulek_using(
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
fn fetch_nitro_using(
    socks: SocksConfig,
    tls: rustls::ClientConfig,
    base: &str,
    cache: &std::path::Path,
    now: SystemTime,
) -> io::Result<PacketInfoManager> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let endpoint = format!("{base}/releases/{NITRO_REVISION}/messages");
    PacketInfoManager::load_or_refresh(cache, NITRO_REVISION, now, || {
        let bytes = runtime.block_on(download_json(socks, tls, &endpoint))?;
        PacketInfoManager::from_json(NITRO_REVISION, &bytes).map_err(io::Error::other)
    })
}

async fn upload_city(
    socks: SocksConfig,
    tls: rustls::ClientConfig,
    endpoint: &str,
    content_type: &str,
    body: Vec<u8>,
) -> io::Result<crate::nitro_city::CityKeys> {
    let url = url::Url::parse(endpoint).map_err(io::Error::other)?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(io::Error::other(
            "Nitro helper URL must use HTTPS without credentials",
        ));
    }
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .wrap_connector(OutboundConnector::new(Some(socks)));
    let client: Client<_, Body> = Client::builder(TokioExecutor::new()).build(connector);
    tokio::time::timeout(Duration::from_secs(20), async {
        let request = Request::post(url.as_str())
            .header("content-type", content_type)
            .body(Body::from(body))
            .map_err(io::Error::other)?;
        let response = client.request(request).await.map_err(io::Error::other)?;
        // Never follow a redirect with the uploaded module.
        if !response.status().is_success() {
            return Err(io::Error::other(format!(
                "Nitro helper HTTP status {}",
                response.status()
            )));
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame.map_err(io::Error::other)?.into_data() {
                if data.len() > 65536usize.saturating_sub(bytes.len()) {
                    return Err(io::Error::other("Nitro helper response exceeds 64 KiB"));
                }
                bytes.extend_from_slice(&data);
            }
        }
        crate::nitro_city::CityKeys::from_json(&bytes)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Nitro helper request timed out"))?
}

/// Call only after the user's session-specific Nitro Helper opt-in.
pub(crate) fn fetch_city(
    socks: SocksConfig,
    wasm: &[u8],
) -> io::Result<crate::nitro_city::CityKeys> {
    let (content_type, body) = crate::nitro_city::helper_multipart(wasm)?;
    let tls = default_tls()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(upload_city(
        socks,
        tls,
        "https://nitro.sulek.dev/habbocity",
        &content_type,
        body,
    ))
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

    #[tokio::test]
    async fn nitro_metadata_and_city_helper_use_socks_with_bounded_https() {
        use crate::web_ca::ProxyIdentity;
        use hudsucker::{
            certificate_authority::CertificateAuthority, rustls::pki_types::CertificateDer,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                for file in [
                    "ca/gearth-proxy-cert.pem",
                    "ca/gearth-proxy-key.pem",
                    "metadata.bin",
                    "bad.bin",
                    "SHOCKWAVE-ORIG-2.bin",
                    "SHOCKWAVE-ORIG-OLD.bin",
                    "FLASH-FLASH-2.bin",
                ] {
                    let _ = std::fs::remove_file(self.0.join(file));
                }
                let _ = std::fs::remove_dir(self.0.join("ca"));
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let directory = Directory(std::env::temp_dir().join(format!(
            "gearth-socks-metadata-{:032x}",
            u128::from_ne_bytes(random)
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let identity = ProxyIdentity::ensure(&directory.0.join("ca")).unwrap();
        let authority = identity.authority().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(identity.certificate_der))
            .unwrap();
        let tls =
            rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = upstream.local_addr().unwrap();
        let server_config = authority
            .gen_server_config(
                &format!("fixture.invalid:{}", target.port())
                    .parse()
                    .unwrap(),
            )
            .await;
        let server = tokio::spawn(async move {
            for index in 0..16 {
                let (stream, _) = upstream.accept().await.unwrap();
                let mut stream = tokio_rustls::TlsAcceptor::from(server_config.clone())
                    .accept(stream)
                    .await
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut b = [0];
                    stream.read_exact(&mut b).await.unwrap();
                    request.push(b[0]);
                    assert!(request.len() < 8192);
                }
                if (8..=10).contains(&index) {
                    assert!(request.starts_with(b"POST /habbocity HTTP/1.1\r\n"));
                    let headers = String::from_utf8(request.clone())
                        .unwrap()
                        .to_ascii_lowercase();
                    assert!(headers.contains("content-type: multipart/form-data; boundary=gearth-"));
                    let length: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    let mut body = vec![0; length];
                    stream.read_exact(&mut body).await.unwrap();
                    assert!(body.windows(8).any(|chunk| chunk == b"\0asm\x01\0\0\0"));
                } else if index >= 11 {
                    let expected = match index {
                        11 | 14 => "/releases?variant=shockwave-windows",
                        12 => "/releases/shockwave-windows/ORIG-2/messages",
                        13 => "/releases/FLASH-2/messages",
                        _ => "/releases/shockwave-windows/ORIG-OLD/messages",
                    };
                    assert!(request.starts_with(format!("GET {expected} HTTP/1.1\r\n").as_bytes()));
                } else if index == 1 {
                    assert!(request.starts_with(b"GET /redirect HTTP/1.1\r\n"));
                } else {
                    assert!(request.starts_with(
                        format!("GET /releases/{NITRO_REVISION}/messages HTTP/1.1\r\n").as_bytes()
                    ));
                }
                let response = match index {
                    0 => "HTTP/1.1 302 Found\r\nLocation: /redirect\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                    1 => { let body = r#"{"messages":{"incoming":[],"outgoing":[{"id":900,"name":"KnownComposer"}]}}"#; format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()) },
                    2 => "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                    3 => "HTTP/1.1 302 Found\r\nLocation: http://fixture.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                    4 => "HTTP/1.1 302 Found\r\nLocation: https://user:pass@fixture.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                    5 => { let body = "x".repeat(8 * 1024 * 1024 + 1); format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()) },
                    6 => "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{".to_owned(),
                    7 => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_owned(),
                    8 => { let body = r#"{"status":"ok","result":{"aes_key":"000102030405060708090a0b0c0d0e0f","aes_iv":"000102030405060708090a0b","salt_key":["11","22"],"salt_iv":["33"]}}"#; format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()) },
                    9 => "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://leak.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                    10 => { let body = "x".repeat(65537); format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()) },
                    11 => "HTTP/1.1 200 OK\r\nContent-Length: 22\r\nConnection: close\r\n\r\n[{\"version\":\"ORIG-2\"}]".to_owned(),
                    14 => "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                    _ => { let body = r#"{"messages":{"incoming":[],"outgoing":[{"id":900,"name":"KnownComposer"}]}}"#; format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()) },
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let socks_server = tokio::spawn(async move {
            let mut tasks = Vec::new();
            for _ in 0..16 {
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
                    let mut host = vec![0; usize::from(header[4])];
                    client.read_exact(&mut host).await.unwrap();
                    assert_eq!(host, b"fixture.invalid");
                    let mut port = [0; 2];
                    client.read_exact(&mut port).await.unwrap();
                    assert_eq!(u16::from_be_bytes(port), target.port());
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
        let config = SocksConfig {
            proxy: proxy_address.to_string(),
            credentials: Some(("u".into(), "p".into())),
        };
        let endpoint = format!("https://fixture.invalid:{}", target.port());
        let cache = directory.0.join("metadata.bin");
        let now = SystemTime::now();
        for (test_config, time) in [
            (config.clone(), now),
            (
                SocksConfig {
                    proxy: "127.0.0.1:0".into(),
                    credentials: None,
                },
                now,
            ),
            (config.clone(), now + Duration::from_secs(301)),
        ] {
            let tls = tls.clone();
            let endpoint = endpoint.clone();
            let cache = cache.clone();
            let database = tokio::task::spawn_blocking(move || {
                fetch_nitro_using(test_config, tls, &endpoint, &cache, time)
            })
            .await
            .unwrap()
            .unwrap();
            assert_eq!(database.version, NITRO_REVISION);
            assert_eq!(database.entries()[0].header, 900);
        }
        let url = format!("{endpoint}/releases/{NITRO_REVISION}/messages");
        for _ in 0..2 {
            let error = download_json(config.clone(), tls.clone(), &url)
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("HTTPS without URL credentials"),
                "{error}"
            );
        }
        let error = download_json(config.clone(), tls.clone(), &url)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("8 MiB"), "{error}");
        assert!(
            download_json(config.clone(), tls.clone(), &url)
                .await
                .is_err(),
            "truncated response accepted"
        );
        let bad_cache = directory.0.join("bad.bin");
        let bad_endpoint = endpoint.clone();
        let bad_config = config.clone();
        let bad_tls = tls.clone();
        let result = tokio::task::spawn_blocking(move || {
            fetch_nitro_using(bad_config, bad_tls, &bad_endpoint, &bad_cache, now)
        })
        .await
        .unwrap();
        assert!(result.is_err(), "malformed metadata accepted");
        assert!(crate::nitro_city::helper_multipart(b"invalid").is_err());
        let wasm = b"\0asm\x01\0\0\0";
        let city_endpoint = format!("{endpoint}/habbocity");
        for index in 0..3 {
            let (content_type, body) = crate::nitro_city::helper_multipart(wasm).unwrap();
            let result = upload_city(
                config.clone(),
                tls.clone(),
                &city_endpoint,
                &content_type,
                body,
            )
            .await;
            if index == 0 {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err(), "unsafe helper response accepted");
            }
        }
        let (content_type, body) = crate::nitro_city::helper_multipart(wasm).unwrap();
        let result = upload_city(
            config.clone(),
            tls.clone(),
            "http://fixture.invalid/habbocity",
            &content_type,
            body,
        )
        .await;
        assert!(result.is_err(), "non-HTTPS helper upload accepted");
        for (requested, origins, expected) in [
            ("OLD", true, "ORIG-2"),
            ("FLASH-2", false, "FLASH-2"),
            ("ORIG-OLD", true, "ORIG-OLD"),
        ] {
            let config = config.clone();
            let tls = tls.clone();
            let endpoint = endpoint.clone();
            let cache_dir = directory.0.clone();
            let database = tokio::task::spawn_blocking(move || {
                fetch_sulek_using(config, tls, &endpoint, &cache_dir, requested, origins, now)
            })
            .await
            .unwrap()
            .unwrap();
            assert_eq!(database.version, expected);
            assert_eq!(database.entries()[0].header, 900);
        }
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), socks_server)
            .await
            .unwrap()
            .unwrap();
    }
}
