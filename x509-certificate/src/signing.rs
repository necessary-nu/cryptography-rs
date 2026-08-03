// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use {
    crate::{
        EcdsaCurve, KeyAlgorithm, SignatureAlgorithm, X509CertificateError as Error,
        rfc5958::OneAsymmetricKey,
    },
    bcder::decode::Constructed,
    bytes::Bytes,
    der::SecretDocument,
    p256::elliptic_curve::Generate,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    rand::{SeedableRng, rngs::{StdRng, SysRng}},
    rsa::{
        pkcs1::EncodeRsaPublicKey,
        traits::{PrivateKeyParts, PublicKeyParts},
    },
    signature::{
        RandomizedSigner, SignatureEncoding as SignatureTrait, Signer,
    },
    std::fmt::{Debug, Formatter},
    zeroize::Zeroizing,
};

/// Signifies that an entity is capable of producing cryptographic signatures.
pub trait Sign {
    /// Create a cyrptographic signature over a message.
    ///
    /// Takes the message to be signed, which will be digested by the implementation.
    ///
    /// Returns the raw bytes constituting the signature and which signature algorithm
    /// was used. The returned [SignatureAlgorithm] can be serialized into an
    /// ASN.1 `AlgorithmIdentifier` via `.into()`.
    #[deprecated(since = "0.13.0", note = "use the signature::Signer trait instead")]
    fn sign(&self, message: &[u8]) -> Result<(Vec<u8>, SignatureAlgorithm), Error>;

    /// Obtain the algorithm of the private key.
    ///
    /// If we can't coerce the key algorithm to [KeyAlgorithm], None is returned.
    fn key_algorithm(&self) -> Option<KeyAlgorithm>;

    /// Obtain the raw bytes constituting the public key of the signing certificate.
    ///
    /// This will be `.tbs_certificate.subject_public_key_info.subject_public_key` of a parsed
    /// X.509 public certificate.
    fn public_key_data(&self) -> Bytes;

    /// Obtain the [SignatureAlgorithm] that this signer will use.
    ///
    /// Instances can be coerced into the ASN.1 `AlgorithmIdentifier` via `.into()`
    /// for easy inclusion in ASN.1 structures.
    fn signature_algorithm(&self) -> Result<SignatureAlgorithm, Error>;

    /// Obtain the raw private key data.
    fn private_key_data(&self) -> Option<Zeroizing<Vec<u8>>>;

    /// Obtain RSA key primes p and q, if available.
    #[allow(clippy::type_complexity)]
    fn rsa_primes(&self) -> Result<Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>, Error>;
}

/// A superset of [Signer] and [Sign].
pub trait KeyInfoSigner: Signer<Signature> + Sign {}

#[derive(Clone, Debug)]
pub struct Signature(Vec<u8>);

impl From<Vec<u8>> for Signature {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<Signature> for Vec<u8> {
    fn from(v: Signature) -> Vec<u8> {
        v.0
    }
}

impl From<Signature> for Bytes {
    fn from(v: Signature) -> Self {
        Self::copy_from_slice(&v.0)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl SignatureTrait for Signature {
    type Repr = Vec<u8>;
}

impl TryFrom<&[u8]> for Signature {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.to_vec()))
    }
}

/// An ECDSA key pair.
pub struct EcdsaKeyPair {
    pkcs8_der: SecretDocument,
    key_pair: EcdsaPrivateKey,
    curve: EcdsaCurve,
    private_key: Zeroizing<Vec<u8>>,
    public_key: Bytes,
}

impl Debug for EcdsaKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaKeyPair")
            .field("curve", &self.curve)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
enum EcdsaPrivateKey {
    Secp256r1(p256::ecdsa::SigningKey),
    Secp384r1(p384::ecdsa::SigningKey),
}

/// An ED25519 key pair.
pub struct Ed25519KeyPair {
    pkcs8_der: SecretDocument,
    key_pair: ed25519_dalek::SigningKey,
    public_key: Bytes,
}

impl Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// An RSA key pair.
pub struct RsaKeyPair {
    pkcs8_der: SecretDocument,
    key_pair: rsa::RsaPrivateKey,
    private_key: Zeroizing<Vec<u8>>,
    public_key: Bytes,
}

impl Debug for RsaKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaKeyPair")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// Represents a key pair that exists in memory and can be used to create cryptographic signatures.
///
/// This is a wrapper around RustCrypto's various key pair types. It provides
/// abstractions tailored for X.509 certificates.
///
/// # RSA timing warning
///
/// The RustCrypto `rsa` crate is covered by RUSTSEC-2023-0071. Do not use this
/// type for RSA private-key operations where an attacker can repeatedly request
/// operations and measure their timing. Prefer Ed25519/ECDSA or a hardened
/// external signer/HSM in that threat model.
pub enum InMemorySigningKeyPair {
    /// ECDSA key pair.
    Ecdsa(Box<EcdsaKeyPair>),

    /// ED25519 key pair.
    Ed25519(Box<Ed25519KeyPair>),

    /// RSA key pair.
    Rsa(Box<RsaKeyPair>),
}

impl Debug for InMemorySigningKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ecdsa(key) => key.fmt(f),
            Self::Ed25519(key) => key.fmt(f),
            Self::Rsa(key) => key.fmt(f),
        }
    }
}

fn secure_rng() -> Result<StdRng, Error> {
    StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::KeyPairGenerationError)
}

impl Signer<Signature> for InMemorySigningKeyPair {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        match self {
            Self::Rsa(kp) => {
                let signing_key =
                    rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(kp.key_pair.clone());
                let mut rng = StdRng::try_from_rng(&mut SysRng)
                    .map_err(|_| signature::Error::new())?;
                let signature = signing_key.try_sign_with_rng(&mut rng, msg)?;

                Ok(signature.to_vec().into())
            }
            Self::Ecdsa(kp) => match &kp.key_pair {
                EcdsaPrivateKey::Secp256r1(key) => {
                    let signature: p256::ecdsa::DerSignature = key.try_sign(msg)?;
                    Ok(Signature::from(signature.to_vec()))
                }
                EcdsaPrivateKey::Secp384r1(key) => {
                    let signature: p384::ecdsa::DerSignature = key.try_sign(msg)?;
                    Ok(Signature::from(signature.to_vec()))
                }
            },
            Self::Ed25519(kp) => {
                let signature: ed25519_dalek::Signature = kp.key_pair.sign(msg);

                Ok(Signature::from(signature.to_vec()))
            }
        }
    }
}

impl Sign for InMemorySigningKeyPair {
    /// RSA signatures use PKCS#1 v1.5 with SHA-256.
    ///
    fn sign(&self, message: &[u8]) -> Result<(Vec<u8>, SignatureAlgorithm), Error> {
        let algorithm = self.signature_algorithm()?;

        Ok((self.try_sign(message)?.into(), algorithm))
    }

    fn key_algorithm(&self) -> Option<KeyAlgorithm> {
        Some(match self {
            Self::Rsa(_) => KeyAlgorithm::Rsa,
            Self::Ed25519(_) => KeyAlgorithm::Ed25519,
            Self::Ecdsa(kp) => KeyAlgorithm::Ecdsa(kp.curve),
        })
    }

    fn public_key_data(&self) -> Bytes {
        match self {
            Self::Rsa(kp) => kp.public_key.clone(),
            Self::Ecdsa(kp) => kp.public_key.clone(),
            Self::Ed25519(kp) => kp.public_key.clone(),
        }
    }

    fn signature_algorithm(&self) -> Result<SignatureAlgorithm, Error> {
        Ok(match self {
            Self::Rsa(_) => SignatureAlgorithm::RsaSha256,
            Self::Ecdsa(kp) => {
                match kp.curve {
                    EcdsaCurve::Secp256r1 => SignatureAlgorithm::EcdsaSha256,
                    EcdsaCurve::Secp384r1 => SignatureAlgorithm::EcdsaSha384,
                }
            }
            Self::Ed25519(_) => SignatureAlgorithm::Ed25519,
        })
    }

    fn private_key_data(&self) -> Option<Zeroizing<Vec<u8>>> {
        match self {
            Self::Rsa(kp) => Some(kp.private_key.clone()),
            Self::Ecdsa(kp) => Some(kp.private_key.clone()),
            Self::Ed25519(_) => None,
        }
    }

    fn rsa_primes(&self) -> Result<Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>, Error> {
        match self {
            Self::Rsa(kp) => {
                let primes = kp.key_pair.primes();
                let [p, q] = primes else {
                    return Err(Error::PrivateKeyRejected(
                        "RSA key must contain exactly two primes".to_string(),
                    ));
                };

                Ok(Some((
                    Zeroizing::new(p.to_be_bytes_trimmed_vartime().into_vec()),
                    Zeroizing::new(q.to_be_bytes_trimmed_vartime().into_vec()),
                )))
            }
            Self::Ecdsa(_) => Ok(None),
            Self::Ed25519(_) => Ok(None),
        }
    }
}

impl KeyInfoSigner for InMemorySigningKeyPair {}

impl InMemorySigningKeyPair {
    /// Attempt to instantiate an instance from PKCS#8 DER data.
    ///
    /// The DER data should be a [OneAsymmetricKey] ASN.1 structure.
    pub fn from_pkcs8_der(data: impl AsRef<[u8]>) -> Result<Self, Error> {
        let pkcs8_der = SecretDocument::try_from(data.as_ref())?;

        // We need to parse the PKCS#8 to know what kind of key we're dealing with.
        let key = Constructed::decode(data.as_ref(), bcder::Mode::Der, |cons| {
            OneAsymmetricKey::take_from(cons)
        })?;

        let algorithm = KeyAlgorithm::try_from(&key.private_key_algorithm)?;

        // self.key_algorithm() assumes a 1:1 mapping between KeyAlgorithm and our enum
        // variants. If you change this, change that function as well.
        match algorithm {
            KeyAlgorithm::Rsa => {
                let pair = rsa::RsaPrivateKey::from_pkcs8_der(data.as_ref())
                    .map_err(|e| Error::PrivateKeyRejected(e.to_string()))?;
                if !(2048..=8192).contains(&pair.n().bits()) {
                    return Err(Error::PrivateKeyRejected(
                        "RSA modulus must be between 2048 and 8192 bits".to_string(),
                    ));
                }
                let public_key = rsa::RsaPublicKey::from(&pair)
                    .to_pkcs1_der()
                    .map_err(|e| Error::PrivateKeyRejected(e.to_string()))?;

                Ok(Self::Rsa(Box::new(RsaKeyPair {
                    pkcs8_der,
                    key_pair: pair,
                    private_key: Zeroizing::new(key.private_key.into_bytes().to_vec()),
                    public_key: Bytes::copy_from_slice(public_key.as_bytes()),
                })))
            }
            KeyAlgorithm::Ecdsa(curve) => {
                let (pair, public_key) = match curve {
                    EcdsaCurve::Secp256r1 => {
                        let pair = p256::ecdsa::SigningKey::from_pkcs8_der(data.as_ref())
                            .map_err(|e| Error::PrivateKeyRejected(e.to_string()))?;
                        let public_key = pair.verifying_key().to_sec1_point(false);
                        (
                            EcdsaPrivateKey::Secp256r1(pair),
                            Bytes::copy_from_slice(public_key.as_ref()),
                        )
                    }
                    EcdsaCurve::Secp384r1 => {
                        let pair = p384::ecdsa::SigningKey::from_pkcs8_der(data.as_ref())
                            .map_err(|e| Error::PrivateKeyRejected(e.to_string()))?;
                        let public_key = pair.verifying_key().to_sec1_point(false);
                        (
                            EcdsaPrivateKey::Secp384r1(pair),
                            Bytes::copy_from_slice(public_key.as_ref()),
                        )
                    }
                };

                Ok(Self::Ecdsa(Box::new(EcdsaKeyPair {
                    pkcs8_der,
                    key_pair: pair,
                    curve,
                    private_key: Zeroizing::new(data.as_ref().to_vec()),
                    public_key,
                })))
            }
            KeyAlgorithm::Ed25519 => {
                let pair = ed25519_dalek::SigningKey::from_pkcs8_der(data.as_ref())
                    .map_err(|e| Error::PrivateKeyRejected(e.to_string()))?;
                let public_key = Bytes::copy_from_slice(pair.verifying_key().as_bytes());

                Ok(Self::Ed25519(Box::new(Ed25519KeyPair {
                    pkcs8_der,
                    key_pair: pair,
                    public_key,
                })))
            }
        }
    }

    /// Attempt to instantiate an instance from PEM encoded PKCS#8.
    ///
    /// This is just a wrapper for [Self::from_pkcs8_der] that does the PEM
    /// decoding for you.
    pub fn from_pkcs8_pem(data: impl AsRef<[u8]>) -> Result<Self, Error> {
        let der = pem::parse(data.as_ref()).map_err(Error::PemDecode)?;

        Self::from_pkcs8_der(der.contents())
    }

    /// Generate a random key pair given a key algorithm and optional ECDSA signing algorithm.
    ///
    /// The raw PKCS#8 document is returned to facilitate access to the private key.
    ///
    /// Not attempt is made to protect the private key in memory.
    pub fn generate_random(key_algorithm: KeyAlgorithm) -> Result<Self, Error> {
        let mut rng = secure_rng()?;

        let document = match key_algorithm {
            KeyAlgorithm::Ed25519 => ed25519_dalek::SigningKey::generate(&mut rng)
                .to_pkcs8_der()
                .map_err(|_| Error::KeyPairGenerationError),
            KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1) => {
                p256::ecdsa::SigningKey::generate_from_rng(&mut rng)
                    .to_pkcs8_der()
                    .map_err(|_| Error::KeyPairGenerationError)
            }
            KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1) => {
                p384::ecdsa::SigningKey::generate_from_rng(&mut rng)
                    .to_pkcs8_der()
                    .map_err(|_| Error::KeyPairGenerationError)
            }
            KeyAlgorithm::Rsa => rsa::RsaPrivateKey::new(&mut rng, 2048)
                .map_err(|_| Error::KeyPairGenerationError)?
                .to_pkcs8_der()
                .map_err(|_| Error::KeyPairGenerationError),
        }?;

        Self::from_pkcs8_der(document.as_bytes())
    }

    /// Attempt to resolve a verification algorithm for this key pair.
    ///
    /// This is a wrapper around [SignatureAlgorithm::resolve_verification_algorithm()]
    /// with our bound [KeyAlgorithm]. However, since there are no parameters
    /// that can result in wrong choices, this is guaranteed to always work
    /// and doesn't require `Result`.
    pub fn verification_algorithm(
        &self,
    ) -> Result<crate::VerificationAlgorithm, Error> {
        self.signature_algorithm()?
            .resolve_verification_algorithm(KeyAlgorithm::from(self))
    }

    /// Serialize this instance to a PKCS#8 [OneAsymmetricKey] ASN.1 structure.
    pub fn to_pkcs8_one_asymmetric_key_der(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::Ecdsa(kp) => kp.pkcs8_der.to_bytes(),
            Self::Ed25519(kp) => kp.pkcs8_der.to_bytes(),
            Self::Rsa(kp) => kp.pkcs8_der.to_bytes(),
        }
    }
}

impl From<&InMemorySigningKeyPair> for KeyAlgorithm {
    fn from(key: &InMemorySigningKeyPair) -> Self {
        match key {
            InMemorySigningKeyPair::Rsa(_) => KeyAlgorithm::Rsa,
            InMemorySigningKeyPair::Ecdsa(kp) => KeyAlgorithm::Ecdsa(kp.curve),
            InMemorySigningKeyPair::Ed25519(_) => KeyAlgorithm::Ed25519,
        }
    }
}

#[cfg(test)]
mod test {
    use {super::*, crate::rfc5280, crate::testutil::*};

    #[test]
    fn generate_random_ecdsa() {
        for curve in EcdsaCurve::all() {
            InMemorySigningKeyPair::generate_random(KeyAlgorithm::Ecdsa(*curve)).unwrap();
        }
    }

    #[test]
    fn generate_random_ed25519() {
        InMemorySigningKeyPair::generate_random(KeyAlgorithm::Ed25519).unwrap();
    }

    #[test]
    fn generate_random_rsa() {
        InMemorySigningKeyPair::generate_random(KeyAlgorithm::Rsa).unwrap();
    }

    #[test]
    fn rejects_an_rsa_modulus_below_2048_bits() {
        let mut rng = secure_rng().unwrap();
        let document = rsa::RsaPrivateKey::new(&mut rng, 2047)
            .unwrap()
            .to_pkcs8_der()
            .unwrap();

        assert!(matches!(
            InMemorySigningKeyPair::from_pkcs8_der(document.as_bytes()),
            Err(Error::PrivateKeyRejected(_))
        ));
    }

    #[test]
    fn signing_key_from_ecdsa_pkcs8() {
        let mut rng = secure_rng().unwrap();
        let docs = [
            (
                EcdsaCurve::Secp256r1,
                p256::ecdsa::SigningKey::generate_from_rng(&mut rng)
                    .to_pkcs8_der()
                    .unwrap(),
            ),
            (
                EcdsaCurve::Secp384r1,
                p384::ecdsa::SigningKey::generate_from_rng(&mut rng)
                    .to_pkcs8_der()
                    .unwrap(),
            ),
        ];

        for (expected, doc) in docs {

            let signing_key = InMemorySigningKeyPair::from_pkcs8_der(doc.as_bytes()).unwrap();
            assert!(matches!(signing_key, InMemorySigningKeyPair::Ecdsa(_,)));

            let pem_data = pem::Pem::new("PRIVATE KEY", doc.as_bytes()).to_string();

            let signing_key = InMemorySigningKeyPair::from_pkcs8_pem(pem_data.as_bytes()).unwrap();
            assert!(matches!(signing_key, InMemorySigningKeyPair::Ecdsa(_)));

            let key_pair_asn1 = Constructed::decode(doc.as_bytes(), bcder::Mode::Der, |cons| {
                OneAsymmetricKey::take_from(cons)
            })
            .unwrap();
            assert_eq!(
                key_pair_asn1.private_key_algorithm.algorithm,
                // Inner value doesn't matter here.
                KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1).into()
            );

            assert!(key_pair_asn1.private_key_algorithm.parameters.is_some());
            let oid = key_pair_asn1
                .private_key_algorithm
                .parameters
                .unwrap()
                .decode_oid()
                .unwrap();

            assert_eq!(EcdsaCurve::try_from(&oid).unwrap(), expected);
        }
    }

    #[test]
    fn signing_key_from_ed25519_pkcs8() {
        let mut rng = secure_rng().unwrap();
        let doc = ed25519_dalek::SigningKey::generate(&mut rng)
            .to_pkcs8_der()
            .unwrap();

        let signing_key = InMemorySigningKeyPair::from_pkcs8_der(doc.as_bytes()).unwrap();
        assert!(matches!(signing_key, InMemorySigningKeyPair::Ed25519(_)));

        let pem_data = pem::Pem::new("PRIVATE KEY", doc.as_bytes()).to_string();

        let signing_key = InMemorySigningKeyPair::from_pkcs8_pem(pem_data.as_bytes()).unwrap();
        assert!(matches!(signing_key, InMemorySigningKeyPair::Ed25519(_)));

        let key_pair_asn1 = Constructed::decode(doc.as_bytes(), bcder::Mode::Der, |cons| {
            OneAsymmetricKey::take_from(cons)
        })
        .unwrap();
        assert_eq!(
            key_pair_asn1.private_key_algorithm.algorithm,
            SignatureAlgorithm::Ed25519.into()
        );
        assert!(key_pair_asn1.private_key_algorithm.parameters.is_none());
    }

    #[test]
    fn ecdsa_self_signed_certificate_verification() {
        for curve in EcdsaCurve::all() {
            let (cert, key) = self_signed_ecdsa_key_pair(Some(*curve));
            cert.verify_signed_by_certificate(&cert).unwrap();

            let message = b"verify the subject key curve from the full SPKI";
            let signature = Signer::try_sign(&key, message).unwrap();
            cert.verify_signed_data_with_algorithm(
                message,
                signature.as_ref(),
                key.verification_algorithm().unwrap(),
            )
            .unwrap();

            let raw: &rfc5280::Certificate = cert.as_ref();

            let tbs_signature_algorithm =
                SignatureAlgorithm::try_from(&raw.tbs_certificate.signature).unwrap();
            let expected = match curve {
                EcdsaCurve::Secp256r1 => SignatureAlgorithm::EcdsaSha256,
                EcdsaCurve::Secp384r1 => SignatureAlgorithm::EcdsaSha384,
            };
            assert_eq!(tbs_signature_algorithm, expected);

            let spki = &raw.tbs_certificate.subject_public_key_info;

            // The algorithm in the SPKI should be constant.
            assert_eq!(
                spki.algorithm.algorithm,
                crate::algorithm::OID_EC_PUBLIC_KEY
            );
            // But the parameters depend on the curve in use.
            let expected = match curve {
                EcdsaCurve::Secp256r1 => crate::algorithm::OID_EC_SECP256R1,
                EcdsaCurve::Secp384r1 => crate::algorithm::OID_EC_SECP384R1,
            };
            assert!(spki.algorithm.parameters.is_some());
            assert_eq!(
                spki.algorithm
                    .parameters
                    .as_ref()
                    .unwrap()
                    .decode_oid()
                    .unwrap(),
                expected
            );

            // This should match the tbs signature algorithm.
            let cert_algorithm = SignatureAlgorithm::try_from(&raw.signature_algorithm).unwrap();
            assert_eq!(cert_algorithm, tbs_signature_algorithm);
        }
    }

    #[test]
    fn ed25519_self_signed_certificate_verification() {
        let (cert, _) = self_signed_ed25519_key_pair();
        cert.verify_signed_by_certificate(&cert).unwrap();
    }

    #[test]
    fn rsa_signing_roundtrip() {
        let key = rsa_private_key();
        let cert = rsa_cert();
        let message = b"hello, world";

        let signature = Signer::try_sign(&key, message).unwrap();

        let public_key = crate::SignatureVerifier::new(
            key.verification_algorithm().unwrap(),
            cert.public_key_data(),
        );

        public_key.verify(message, signature.as_ref()).unwrap();
    }
}
