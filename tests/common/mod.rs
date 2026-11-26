use std::path::Path;
use std::sync::Arc;

use nbdwire::tokio_rustls::TlsAcceptor;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::RootCertStore;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;

/// A CA, and a server and a client certificate it signed. Writes the CA's
/// certificate and the client's certificate and key to `dir` under the names
/// libnbd reads (`tls-certificates=DIR`), and returns an acceptor for the
/// server that wants client certificates from the CA.
pub fn tls(dir: &Path) -> TlsAcceptor {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca = Issuer::new(ca_params, ca_key);

    let leaf = |name: &str, usage| {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        (params.signed_by(&key, &ca).unwrap(), key)
    };
    let (server_cert, server_key) = leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth);
    let (client_cert, client_key) = leaf("client", ExtendedKeyUsagePurpose::ClientAuth);
    std::fs::write(dir.join("ca-cert.pem"), ca_cert.pem()).unwrap();
    std::fs::write(dir.join("client-cert.pem"), client_cert.pem()).unwrap();
    std::fs::write(dir.join("client-key.pem"), client_key.serialize_pem()).unwrap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap();
    let server_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server_cert.der().clone()], server_key)
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}
