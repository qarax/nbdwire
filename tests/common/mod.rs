use std::path::Path;
use std::sync::Arc;

use nbdwire::tokio_rustls::{TlsAcceptor, TlsConnector};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;

/// Both ends of TLS from one CA.
pub struct Tls {
    /// For a server: wants client certificates from the CA.
    pub acceptor: TlsAcceptor,
    /// For a client: trusts the CA, and presents the client's certificate.
    #[allow(dead_code)]
    pub connector: TlsConnector,
}

/// A CA, and a server certificate for "localhost" and a client certificate
/// it signed, written to `dir` under the names libnbd and QEMU read:
/// `ca-cert.pem`, `server-cert.pem` and `server-key.pem`,
/// `client-cert.pem` and `client-key.pem`.
pub fn tls(dir: &Path) -> Tls {
    // Each certificate with a name of its own: QEMU takes a certificate whose
    // subject is its issuer's, as rcgen's default names make them, for a CA.
    let named = |name: &str| {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        dn
    };
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.distinguished_name = named("nbdwire test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca = Issuer::new(ca_params, ca_key);

    let leaf = |name: &str, usage| {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.distinguished_name = named(name);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        (params.signed_by(&key, &ca).unwrap(), key)
    };
    let (server_cert, server_key) = leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth);
    let (client_cert, client_key) = leaf("client", ExtendedKeyUsagePurpose::ClientAuth);
    for (name, pem) in [
        ("ca-cert.pem", ca_cert.pem()),
        ("server-cert.pem", server_cert.pem()),
        ("server-key.pem", server_key.serialize_pem()),
        ("client-cert.pem", client_cert.pem()),
        ("client-key.pem", client_key.serialize_pem()),
    ] {
        std::fs::write(dir.join(name), pem).unwrap();
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    let roots = Arc::new(roots);
    let key = |key: &KeyPair| PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let chain =
        |cert: &rcgen::Certificate| -> Vec<CertificateDer<'static>> { vec![cert.der().clone()] };

    let verifier = WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone())
        .build()
        .unwrap();
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain(&server_cert), key(&server_key))
        .unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain(&client_cert), key(&client_key))
        .unwrap();
    Tls {
        acceptor: TlsAcceptor::from(Arc::new(server)),
        connector: TlsConnector::from(Arc::new(client)),
    }
}
