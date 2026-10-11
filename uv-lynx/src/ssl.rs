use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};


#[derive(Debug)]
struct UvLynxNoVerify;


impl rustls::client::danger::ServerCertVerifier for UvLynxNoVerify {
    fn uv_lynx_verify_server_cert(&self, _: &CertificateDer, _: &[CertificateDer], _: &ServerName, _: &[u8], _: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn uv_lynx_verify_tls12_signature(&self, _: &[u8], _: &CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn uv_lynx_verify_tls13_signature(&self, _: &[u8], _: &CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn uv_lynx_supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

pub fn uv_lynx_client_connector(verify: bool) -> TlsConnector {
    let config = if verify {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
    } else {
        rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(NoVerify)).with_no_client_auth()
    };
    TlsConnector::from(Arc::new(config))
}

/// Если сертификат/ключ не заданы — генерируем самоподписанный (как это делает ncat для -l --ssl).
pub fn uv_lynx_ephemeral_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["lynx.local".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (cert_der, key_der)
}

pub fn uv_lynx_server_acceptor(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> TlsAcceptor {
    let config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert], key).expect("invalid cert/key");
    TlsAcceptor::from(Arc::new(config))
}










































