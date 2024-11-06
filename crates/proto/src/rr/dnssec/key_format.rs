/// The format of the binary key
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFormat {
    /// A der encoded key
    Der,
    /// A pem encoded key, the default of OpenSSL
    Pem,
    /// Pkcs8, a pkcs8 formatted private key
    Pkcs8,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;
    use crate::rr::dnssec::Algorithm;
    #[cfg(feature = "dnssec-openssl")]
    use crate::rr::dnssec::{EcSigningKey, RsaSigningKey};
    #[cfg(feature = "dnssec-ring")]
    use crate::rr::dnssec::{EcdsaSigningKey, Ed25519SigningKey};

    #[test]
    #[cfg(feature = "dnssec-openssl")]
    fn test_rsa_encode_decode_der() {
        let algorithm = Algorithm::RSASHA256;
        let key = RsaSigningKey::generate(algorithm).unwrap();
        let encoded = key.encode_der().unwrap();
        RsaSigningKey::decode_key(&encoded, None, algorithm, KeyFormat::Der).unwrap();
    }

    #[test]
    #[cfg(feature = "dnssec-openssl")]
    fn test_rsa_encode_decode_pem() {
        let algorithm = Algorithm::RSASHA256;
        let key = RsaSigningKey::generate(algorithm).unwrap();
        let encoded = key.encode_pem(None).unwrap();
        RsaSigningKey::decode_key(&encoded, None, algorithm, KeyFormat::Pem).unwrap();
        let encrypted = key.encode_pem(Some("test password")).unwrap();
        RsaSigningKey::decode_key(&encrypted, Some("test password"), algorithm, KeyFormat::Pem)
            .unwrap();
    }

    #[test]
    #[cfg(feature = "dnssec-openssl")]
    fn test_ec_encode_decode_der() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let key = EcSigningKey::generate(algorithm).unwrap();
        let encoded = key.encode_der().unwrap();
        EcSigningKey::decode_key(&encoded, None, algorithm, KeyFormat::Der).unwrap();
    }

    #[test]
    #[cfg(feature = "dnssec-openssl")]
    fn test_ec_encode_decode_pem() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let key = EcSigningKey::generate(algorithm).unwrap();
        let encoded = key.encode_pem(None).unwrap();
        EcSigningKey::decode_key(&encoded, None, algorithm, KeyFormat::Pem).unwrap();
        let encrypted = key.encode_pem(Some("test password")).unwrap();
        EcSigningKey::decode_key(&encrypted, Some("test password"), algorithm, KeyFormat::Pem)
            .unwrap();
    }

    #[test]
    #[cfg(feature = "dnssec-ring")]
    fn test_ec_encode_decode_pkcs8() {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).unwrap();
        EcdsaSigningKey::from_pkcs8(&pkcs8, algorithm).unwrap();
    }

    #[test]
    #[cfg(feature = "dnssec-ring")]
    fn test_ed25519_encode_decode_pkcs8() {
        let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
        Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
    }
}
