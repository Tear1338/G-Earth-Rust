//! Per-user proxy identity. Creation never modifies an operating-system trust store.
use hudsucker::{
    certificate_authority::RcgenAuthority,
    rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose},
    rustls::crypto::aws_lc_rs,
};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
pub struct ProxyIdentity {
    pub certificate_path: PathBuf,
    pub certificate_der: Vec<u8>,
    key_pem: String,
    certificate_pem: String,
}
fn private_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
impl ProxyIdentity {
    pub fn ensure(directory: &Path) -> io::Result<Self> {
        let key_path = directory.join("gearth-proxy-key.pem");
        let certificate_path = directory.join("gearth-proxy-cert.pem");
        if !directory.exists() {
            let parent = directory
                .parent()
                .ok_or_else(|| io::Error::other("certificate directory requires a parent"))?;
            fs::create_dir_all(parent)?;
            let mut random = [0; 16];
            getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
            let token = random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let temporary = parent.join(format!(".gearth-ca-{token}"));
            fs::create_dir(&temporary)?;
            let result = (|| -> io::Result<()> {
                let key = KeyPair::generate().map_err(io::Error::other)?;
                let mut params = CertificateParams::default();
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params
                    .distinguished_name
                    .push(DnType::CommonName, "G-Earth Rust Local Proxy");
                params.key_usages = vec![
                    KeyUsagePurpose::KeyCertSign,
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::CrlSign,
                ];
                let certificate = params.self_signed(&key).map_err(io::Error::other)?;
                private_write(
                    &temporary.join("gearth-proxy-key.pem"),
                    key.serialize_pem().as_bytes(),
                )?;
                private_write(
                    &temporary.join("gearth-proxy-cert.pem"),
                    certificate.pem().as_bytes(),
                )?;
                fs::rename(&temporary, directory)
            })();
            if result.is_err() {
                let _ = fs::remove_file(temporary.join("gearth-proxy-key.pem"));
                let _ = fs::remove_file(temporary.join("gearth-proxy-cert.pem"));
                let _ = fs::remove_dir(&temporary);
                if !directory.is_dir() {
                    result?;
                }
            }
        }
        if fs::metadata(&key_path)?.len() > 65536 || fs::metadata(&certificate_path)?.len() > 65536
        {
            return Err(io::Error::other("proxy identity file too large"));
        }
        let key_pem = fs::read_to_string(key_path)?;
        let certificate_pem = fs::read_to_string(&certificate_path)?;
        let key = KeyPair::from_pem(&key_pem).map_err(io::Error::other)?;
        Issuer::from_ca_cert_pem(&certificate_pem, key).map_err(io::Error::other)?;
        // PEM decoding only; issuing and certificate validation are handled by rcgen/rustls.
        use base64::Engine;
        let encoded = certificate_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        let certificate_der = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(io::Error::other)?;
        Ok(Self {
            certificate_path,
            certificate_der,
            key_pem,
            certificate_pem,
        })
    }
    pub fn authority(&self) -> io::Result<RcgenAuthority> {
        let key = KeyPair::from_pem(&self.key_pem).map_err(io::Error::other)?;
        let issuer =
            Issuer::from_ca_cert_pem(&self.certificate_pem, key).map_err(io::Error::other)?;
        Ok(RcgenAuthority::new(
            issuer,
            128,
            aws_lc_rs::default_provider(),
        ))
    }
}
