// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Cryptographic algorithms commonly encountered in X.509 certificates.

use {
    crate::{
        rfc3447::DigestInfo,
        rfc5280::{AlgorithmIdentifier, AlgorithmParameter},
        X509CertificateError as Error,
    },
    bcder::{encode::Values, ConstOid, OctetString, Oid},
    digest::Digest as DigestTrait,
    rsa::{pkcs1::DecodeRsaPublicKey, traits::PublicKeyParts},
    signature::{Verifier, hazmat::PrehashVerifier},
    spki::ObjectIdentifier,
    std::{fmt::{Debug, Display, Formatter}, ops::Deref},
};

/// SHA-1 digest algorithm.
///
/// 1.3.14.3.2.26
const OID_SHA1: ConstOid = Oid(&[43, 14, 3, 2, 26]);

/// SHA-256 digest algorithm.
///
/// 2.16.840.1.101.3.4.2.1
const OID_SHA256: ConstOid = Oid(&[96, 134, 72, 1, 101, 3, 4, 2, 1]);

/// SHA-384 digest algorithm.
///
/// 2.16.840.1.101.3.4.2.2
const OID_SHA384: ConstOid = Oid(&[96, 134, 72, 1, 101, 3, 4, 2, 2]);

/// SHA-512 digest algorithm.
///
/// 2.16.840.1.101.3.4.2.3
const OID_SHA512: ConstOid = Oid(&[96, 134, 72, 1, 101, 3, 4, 2, 3]);

/// RSA+SHA-1 encryption.
///
/// 1.2.840.113549.1.1.5
const OID_SHA1_RSA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 5]);

/// RSA+SHA-256 encryption.
///
/// 1.2.840.113549.1.1.11
const OID_SHA256_RSA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 11]);

/// RSA+SHA-384 encryption.
///
/// 1.2.840.113549.1.1.12
const OID_SHA384_RSA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 12]);

/// RSA+SHA-512 encryption.
///
/// 1.2.840.113549.1.1.13
const OID_SHA512_RSA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 13]);

/// RSA encryption.
///
/// 1.2.840.113549.1.1.1
const OID_RSA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]);

/// ECDSA with SHA-256.
///
/// 1.2.840.10045.4.3.3
pub(crate) const OID_ECDSA_SHA256: ConstOid = Oid(&[42, 134, 72, 206, 61, 4, 3, 2]);

/// ECDSA with SHA-384.
///
/// 1.2.840.10045.4.3.2
pub(crate) const OID_ECDSA_SHA384: ConstOid = Oid(&[42, 134, 72, 206, 61, 4, 3, 3]);

/// Elliptic curve public key cryptography.
///
/// 1.2.840.10045.2.1
pub(crate) const OID_EC_PUBLIC_KEY: ConstOid = Oid(&[42, 134, 72, 206, 61, 2, 1]);

/// Edwards curve digital signature algorithm.
///
/// 1.3.101.112
const OID_ED25519_SIGNATURE_ALGORITHM: ConstOid = Oid(&[43, 101, 112]);

/// Elliptic curve identifier for secp256r1.
///
/// 1.2.840.10045.3.1.7
pub(crate) const OID_EC_SECP256R1: ConstOid = Oid(&[42, 134, 72, 206, 61, 3, 1, 7]);

/// Elliptic curve identifier for secp384r1.
///
/// 1.3.132.0.34
pub(crate) const OID_EC_SECP384R1: ConstOid = Oid(&[43, 129, 4, 0, 34]);

/// No signature identifier
/// 
/// 1.3.6.1.5.5.7.6.2
pub(crate) const OID_NO_SIGNATURE_ALGORITHM: ConstOid = Oid(&[43, 6, 1, 5, 5, 7, 6, 2]);

/// A hashing algorithm used for digesting data.
///
/// Instances can be converted to and from [Oid] via `From`/`Into`
/// implementations.
///
/// They can also be converted to and from The ASN.1 [AlgorithmIdentifier],
/// which is commonly used to represent them in X.509 certificates.
///
/// Instances can be converted into a [DigestContext] capable of computing
/// digests via `From`/`Into`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DigestAlgorithm {
    /// SHA-1.
    ///
    /// Corresponds to OID 1.3.14.3.2.26.
    Sha1,

    /// SHA-256.
    ///
    /// Corresponds to OID 2.16.840.1.101.3.4.2.1.
    Sha256,

    /// SHA-384.
    ///
    /// Corresponds to OID 2.16.840.1.101.3.4.2.2.
    Sha384,

    /// SHA-512.
    ///
    /// Corresponds to OID 2.16.840.1.101.3.4.2.3.
    Sha512,
}

/// Bytes produced by a cryptographic digest operation.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Digest(Vec<u8>);

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Digest {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Digest").field(&hex::encode(&self.0)).finish()
    }
}

impl From<Digest> for Vec<u8> {
    fn from(value: Digest) -> Self {
        value.0
    }
}

/// Incremental cryptographic digest state.
pub enum DigestContext {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl DigestContext {
    /// Add data to the digest state.
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha1(hasher) => DigestTrait::update(hasher, data),
            Self::Sha256(hasher) => DigestTrait::update(hasher, data),
            Self::Sha384(hasher) => DigestTrait::update(hasher, data),
            Self::Sha512(hasher) => DigestTrait::update(hasher, data),
        }
    }

    /// Finish hashing and return the digest bytes.
    pub fn finish(self) -> Digest {
        Digest(match self {
            Self::Sha1(hasher) => hasher.finalize().to_vec(),
            Self::Sha256(hasher) => hasher.finalize().to_vec(),
            Self::Sha384(hasher) => hasher.finalize().to_vec(),
            Self::Sha512(hasher) => hasher.finalize().to_vec(),
        })
    }
}

impl Display for DigestAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DigestAlgorithm::Sha1 => f.write_str("SHA-1"),
            DigestAlgorithm::Sha256 => f.write_str("SHA-256"),
            DigestAlgorithm::Sha384 => f.write_str("SHA-384"),
            DigestAlgorithm::Sha512 => f.write_str("SHA-512"),
        }
    }
}

impl From<DigestAlgorithm> for Oid {
    fn from(alg: DigestAlgorithm) -> Self {
        Oid(match alg {
            DigestAlgorithm::Sha1 => OID_SHA1.as_ref(),
            DigestAlgorithm::Sha256 => OID_SHA256.as_ref(),
            DigestAlgorithm::Sha384 => OID_SHA384.as_ref(),
            DigestAlgorithm::Sha512 => OID_SHA512.as_ref(),
        }
        .into())
    }
}

impl TryFrom<&Oid> for DigestAlgorithm {
    type Error = Error;

    fn try_from(v: &Oid) -> Result<Self, Self::Error> {
        if v == &OID_SHA1 {
            Ok(Self::Sha1)
        } else if v == &OID_SHA256 {
            Ok(Self::Sha256)
        } else if v == &OID_SHA384 {
            Ok(Self::Sha384)
        } else if v == &OID_SHA512 {
            Ok(Self::Sha512)
        } else {
            Err(Error::UnknownDigestAlgorithm(format!("{}", v)))
        }
    }
}

impl TryFrom<&AlgorithmIdentifier> for DigestAlgorithm {
    type Error = Error;

    fn try_from(v: &AlgorithmIdentifier) -> Result<Self, Self::Error> {
        let algorithm = Self::try_from(&v.algorithm)?;
        if v.parameters.as_ref().is_some_and(|parameters| !parameters.is_null()) {
            return Err(Error::UnhandledDigestAlgorithmParameters(
                "expected absent or NULL parameters",
            ));
        }

        Ok(algorithm)
    }
}

impl From<DigestAlgorithm> for AlgorithmIdentifier {
    fn from(alg: DigestAlgorithm) -> Self {
        Self {
            algorithm: alg.into(),
            parameters: None,
        }
    }
}

impl From<DigestAlgorithm> for DigestContext {
    fn from(alg: DigestAlgorithm) -> Self {
        match alg {
            DigestAlgorithm::Sha1 => Self::Sha1(sha1::Sha1::new()),
            DigestAlgorithm::Sha256 => Self::Sha256(sha2::Sha256::new()),
            DigestAlgorithm::Sha384 => Self::Sha384(sha2::Sha384::new()),
            DigestAlgorithm::Sha512 => Self::Sha512(sha2::Sha512::new()),
        }
    }
}

impl DigestAlgorithm {
    /// Obtain an object that can be used to digest content using this algorithm.
    pub fn digester(&self) -> DigestContext {
        DigestContext::from(*self)
    }

    /// Digest a slice of data.
    pub fn digest_data(&self, data: &[u8]) -> Vec<u8> {
        let mut h = self.digester();
        h.update(data);
        h.finish().as_ref().to_vec()
    }

    /// Digest content from a reader.
    pub fn digest_reader<R: std::io::Read>(&self, fh: &mut R) -> Result<Vec<u8>, std::io::Error> {
        let mut h = self.digester();

        loop {
            let mut buffer = [0u8; 16384];
            let count = fh.read(&mut buffer)?;

            if count == 0 {
                break;
            }

            h.update(&buffer[..count]);
        }

        Ok(h.finish().as_ref().to_vec())
    }

    /// Digest the content of a path.
    pub fn digest_path(&self, path: &std::path::Path) -> Result<Vec<u8>, std::io::Error> {
        self.digest_reader(&mut std::fs::File::open(path)?)
    }

    /// EMSA-PKCS1-v1_5 padding procedure.
    ///
    /// As defined by <https://tools.ietf.org/html/rfc3447#section-9.2>.
    ///
    /// `message` is the message to digest and encode.
    ///
    /// `target_length_in_bytes` is the target length of the padding. This should match the RSA
    /// key length. e.g. 2048 bit keys are length 256.
    pub fn rsa_pkcs1_encode(
        &self,
        message: &[u8],
        target_length_in_bytes: usize,
    ) -> Result<Vec<u8>, Error> {
        let digest = self.digest_data(message);

        let mut algorithm: AlgorithmIdentifier = (*self).into();
        algorithm.parameters = Some(AlgorithmParameter::null());

        let digest_info = DigestInfo {
            algorithm,
            digest: OctetString::new(digest.into()),
        };
        let mut digest_info_der = vec![];
        digest_info.write_encoded(bcder::Mode::Der, &mut digest_info_der)?;

        let encoded_digest_len = digest_info_der.len();

        // At least 8 bytes of padding are required. And there's a 2 byte header plus NULL
        // termination of the padding. So the target length must be 11+ bytes longer than
        // the encoded digest.
        if encoded_digest_len + 11 > target_length_in_bytes {
            return Err(Error::PkcsEncodeTooShort);
        }

        let pad_len = target_length_in_bytes - encoded_digest_len - 3;

        let mut res = vec![0xff; target_length_in_bytes];
        // Constant header.
        res[0] = 0x00;
        // Private key block type.
        res[1] = 0x01;
        // Padding bytes are already filled in.
        // NULL terminate padding.
        res[2 + pad_len] = 0x00;

        let digest_destination = &mut res[3 + pad_len..];
        digest_destination.copy_from_slice(&digest_info_der);

        Ok(res)
    }
}

/// An algorithm used to digitally sign content.
///
/// Instances can be converted to/from [Oid] via `From`/`Into`.
///
/// Similarly, instances can be converted to/from an ASN.1
/// [AlgorithmIdentifier].
///
/// It is also possible to obtain a [VerificationAlgorithm] from
/// an instance. This type can perform actual cryptographic verification
/// that was signed with this algorithm.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    /// SHA-1 with RSA encryption.
    ///
    /// Corresponds to OID 1.2.840.113549.1.1.5.
    RsaSha1,

    /// SHA-256 with RSA encryption.
    ///
    /// Corresponds to OID 1.2.840.113549.1.1.11.
    RsaSha256,

    /// SHA-384 with RSA encryption.
    ///
    /// Corresponds to OID 1.2.840.113549.1.1.12.
    RsaSha384,

    /// SHA-512 with RSA encryption.
    ///
    /// Corresponds to OID 1.2.840.113549.1.1.13.
    RsaSha512,

    /// ECDSA with SHA-256.
    ///
    /// Corresponds to OID 1.2.840.10045.4.3.2.
    EcdsaSha256,

    /// ECDSA with SHA-384.
    ///
    /// Corresponds to OID 1.2.840.10045.4.3.3.
    EcdsaSha384,

    /// ED25519
    ///
    /// Corresponds to OID 1.3.101.112.
    Ed25519,

    /// No signature with digest algorithm
    /// 
    /// Corresponds to OID 1.3.6.1.5.5.7.6.2
    NoSignature(DigestAlgorithm)
}

/// A validated combination of signature and public-key algorithms.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VerificationAlgorithm {
    signature_algorithm: SignatureAlgorithm,
    key_algorithm: KeyAlgorithm,
}

impl VerificationAlgorithm {
    /// Verify a signature using an encoded public key.
    ///
    /// RSA keys must be PKCS#1 `RSAPublicKey` values, ECDSA keys must be SEC1
    /// encoded points, and Ed25519 keys must be their 32-byte compressed form.
    pub fn verify(
        &self,
        public_key_data: &[u8],
        message: &[u8],
        signature_bytes: &[u8],
    ) -> Result<(), Error> {
        let failed = || Error::CertificateSignatureVerificationFailed;

        match (self.key_algorithm, self.signature_algorithm) {
            (KeyAlgorithm::Rsa, signature_algorithm) => {
                let public_key = rsa::RsaPublicKey::from_pkcs1_der(public_key_data)
                    .map_err(|_| failed())?;

                // Preserve the bounds enforced by ring's previous verification
                // algorithms and reject obsolete or unreasonably large RSA keys.
                if !(2048..=8192).contains(&public_key.n().bits()) {
                    return Err(failed());
                }

                let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes)
                    .map_err(|_| failed())?;

                match signature_algorithm {
                    SignatureAlgorithm::RsaSha1 => {
                        rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(public_key)
                            .verify(message, &signature)
                    }
                    SignatureAlgorithm::RsaSha256 => {
                        rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public_key)
                            .verify(message, &signature)
                    }
                    SignatureAlgorithm::RsaSha384 => {
                        rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(public_key)
                            .verify(message, &signature)
                    }
                    SignatureAlgorithm::RsaSha512 => {
                        rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(public_key)
                            .verify(message, &signature)
                    }
                    _ => return Err(failed()),
                }
                .map_err(|_| failed())
            }
            (KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1), signature_algorithm) => {
                let public_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key_data)
                    .map_err(|_| failed())?;
                let signature = p256::ecdsa::DerSignature::try_from(signature_bytes)
                    .map_err(|_| failed())?;
                let digest = signature_algorithm
                    .digest_algorithm()
                    .ok_or_else(failed)?
                    .digest_data(message);

                public_key
                    .verify_prehash(&digest, &signature)
                    .map_err(|_| failed())
            }
            (KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1), signature_algorithm) => {
                let public_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key_data)
                    .map_err(|_| failed())?;
                let signature = p384::ecdsa::DerSignature::try_from(signature_bytes)
                    .map_err(|_| failed())?;
                let digest = signature_algorithm
                    .digest_algorithm()
                    .ok_or_else(failed)?
                    .digest_data(message);

                public_key
                    .verify_prehash(&digest, &signature)
                    .map_err(|_| failed())
            }
            (KeyAlgorithm::Ed25519, SignatureAlgorithm::Ed25519) => {
                let public_key_bytes: &[u8; 32] = public_key_data.try_into().map_err(|_| failed())?;
                let public_key = ed25519_dalek::VerifyingKey::from_bytes(public_key_bytes)
                    .map_err(|_| failed())?;
                let signature = ed25519_dalek::Signature::try_from(signature_bytes)
                    .map_err(|_| failed())?;

                public_key
                    .verify_strict(message, &signature)
                    .map_err(|_| failed())
            }
            _ => Err(Error::UnsupportedSignatureVerification(
                self.key_algorithm,
                self.signature_algorithm,
            )),
        }
    }
}

/// A public key paired with a validated verification algorithm.
#[derive(Clone, Debug)]
pub struct SignatureVerifier<B> {
    algorithm: VerificationAlgorithm,
    public_key: B,
}

impl<B> SignatureVerifier<B> {
    pub fn new(algorithm: VerificationAlgorithm, public_key: B) -> Self {
        Self {
            algorithm,
            public_key,
        }
    }
}

impl<B: AsRef<[u8]>> SignatureVerifier<B> {
    /// Verify a signature over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        self.algorithm
            .verify(self.public_key.as_ref(), message, signature)
    }
}

impl SignatureAlgorithm {
    /// Attempt to resolve an instance from an OID, known [KeyAlgorithm], and optional [DigestAlgorithm].
    ///
    /// Signature algorithm OIDs in the wild are typically either:
    ///
    /// a) an OID that denotes the key algorithm and corresponding digest format (what this
    ///    enumeration represents)
    /// b) an OID that denotes just the key algorithm.
    ///
    /// What this function does is attempt to construct an instance from any OID.
    /// If the OID defines a key + digest algorithm, we get a [SignatureAlgorithm]
    /// from that. If we get a key algorithm we combine with the provided [DigestAlgorithm]
    /// to resolve an appropriate [SignatureAlgorithm].
    pub fn from_oid_and_digest_algorithm(
        oid: &Oid,
        digest_algorithm: DigestAlgorithm,
    ) -> Result<Self, Error> {
        match Self::try_from(oid) { Ok(alg) => {
            Ok(alg)
        } _ => { match KeyAlgorithm::try_from(oid) { Ok(key_alg) => {
            match key_alg {
                KeyAlgorithm::Rsa => match digest_algorithm {
                    DigestAlgorithm::Sha1 => Ok(Self::RsaSha1),
                    DigestAlgorithm::Sha256 => Ok(Self::RsaSha256),
                    DigestAlgorithm::Sha384 => Ok(Self::RsaSha384),
                    DigestAlgorithm::Sha512 => Ok(Self::RsaSha512),
                },
                KeyAlgorithm::Ed25519 => Ok(Self::Ed25519),
                KeyAlgorithm::Ecdsa(_) => match digest_algorithm {
                    DigestAlgorithm::Sha256 => Ok(Self::EcdsaSha256),
                    DigestAlgorithm::Sha384 => Ok(Self::EcdsaSha384),
                    DigestAlgorithm::Sha1 | DigestAlgorithm::Sha512 => {
                        Err(Error::UnknownSignatureAlgorithm(format!(
                            "cannot use digest {:?} with ECDSA",
                            digest_algorithm
                        )))
                    }
                },
            }
        } _ => if oid == &OID_NO_SIGNATURE_ALGORITHM {
            Ok(Self::NoSignature(digest_algorithm))
        } else {
            Err(Error::UnknownSignatureAlgorithm(format!(
                "do not know how to resolve {} to a signature algorithm",
                oid
            )))
        }}}}
    }

    /// Creates an instance with the noSignature mechanism and [DigestAlgorithm]
    pub fn from_digest_algorithm(
        digest_algorithm: DigestAlgorithm,
    ) -> Self {
        Self::NoSignature(digest_algorithm)
    }

    /// Attempt to resolve the verification algorithm using info about the signing key algorithm.
    ///
    /// Only specific combinations of methods are supported. e.g. you can only use
    /// RSA verification with RSA signing keys. Same for ECDSA and ED25519.
    pub fn resolve_verification_algorithm(
        &self,
        key_algorithm: KeyAlgorithm,
    ) -> Result<VerificationAlgorithm, Error> {
        match key_algorithm {
            KeyAlgorithm::Rsa => match self {
                Self::RsaSha1 | Self::RsaSha256 | Self::RsaSha384 | Self::RsaSha512 => Ok(
                    VerificationAlgorithm {
                        signature_algorithm: *self,
                        key_algorithm,
                    },
                ),
                alg => Err(Error::UnsupportedSignatureVerification(key_algorithm, *alg)),
            },
            KeyAlgorithm::Ed25519 => match self {
                Self::Ed25519 => Ok(VerificationAlgorithm {
                    signature_algorithm: *self,
                    key_algorithm,
                }),
                alg => Err(Error::UnsupportedSignatureVerification(key_algorithm, *alg)),
            },
            KeyAlgorithm::Ecdsa(curve) => match curve {
                EcdsaCurve::Secp256r1 => match self {
                    Self::EcdsaSha256 | Self::EcdsaSha384 => Ok(VerificationAlgorithm {
                        signature_algorithm: *self,
                        key_algorithm,
                    }),
                    alg => Err(Error::UnsupportedSignatureVerification(key_algorithm, *alg)),
                },
                EcdsaCurve::Secp384r1 => match self {
                    Self::EcdsaSha256 | Self::EcdsaSha384 => Ok(VerificationAlgorithm {
                        signature_algorithm: *self,
                        key_algorithm,
                    }),
                    alg => Err(Error::UnsupportedSignatureVerification(key_algorithm, *alg)),
                },
            },
        }
    }

    /// Resolve the [DigestAlgorithm] for this signature algorithm.
    pub fn digest_algorithm(&self) -> Option<DigestAlgorithm> {
        match self {
            SignatureAlgorithm::RsaSha1 => Some(DigestAlgorithm::Sha1),
            SignatureAlgorithm::RsaSha256 => Some(DigestAlgorithm::Sha256),
            SignatureAlgorithm::RsaSha384 => Some(DigestAlgorithm::Sha384),
            SignatureAlgorithm::RsaSha512 => Some(DigestAlgorithm::Sha512),
            SignatureAlgorithm::EcdsaSha256 => Some(DigestAlgorithm::Sha256),
            SignatureAlgorithm::EcdsaSha384 => Some(DigestAlgorithm::Sha384),
            // TODO there's got to be a digest algorithm, right?
            SignatureAlgorithm::Ed25519 => None,
            SignatureAlgorithm::NoSignature(digest_algorithm) => Some(*digest_algorithm),
        }
    }
}

impl Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureAlgorithm::RsaSha1 => f.write_str("SHA-1 with RSA encryption"),
            SignatureAlgorithm::RsaSha256 => f.write_str("SHA-256 with RSA encryption"),
            SignatureAlgorithm::RsaSha384 => f.write_str("SHA-384 with RSA encryption"),
            SignatureAlgorithm::RsaSha512 => f.write_str("SHA-512 with RSA encryption"),
            SignatureAlgorithm::EcdsaSha256 => f.write_str("ECDSA with SHA-256"),
            SignatureAlgorithm::EcdsaSha384 => f.write_str("ECDSA with SHA-384"),
            SignatureAlgorithm::Ed25519 => f.write_str("ED25519"),
            SignatureAlgorithm::NoSignature(digest_algorithm) => f.write_fmt(format_args!("No signature with {}", digest_algorithm)),
        }
    }
}

impl From<SignatureAlgorithm> for Oid {
    fn from(alg: SignatureAlgorithm) -> Self {
        Oid(match alg {
            SignatureAlgorithm::RsaSha1 => OID_SHA1_RSA.as_ref(),
            SignatureAlgorithm::RsaSha256 => OID_SHA256_RSA.as_ref(),
            SignatureAlgorithm::RsaSha384 => OID_SHA384_RSA.as_ref(),
            SignatureAlgorithm::RsaSha512 => OID_SHA512_RSA.as_ref(),
            SignatureAlgorithm::EcdsaSha256 => OID_ECDSA_SHA256.as_ref(),
            SignatureAlgorithm::EcdsaSha384 => OID_ECDSA_SHA384.as_ref(),
            SignatureAlgorithm::Ed25519 => OID_ED25519_SIGNATURE_ALGORITHM.as_ref(),
            SignatureAlgorithm::NoSignature(_) => OID_NO_SIGNATURE_ALGORITHM.as_ref(),
        }
        .into())
    }
}

impl TryFrom<&Oid> for SignatureAlgorithm {
    type Error = Error;

    fn try_from(v: &Oid) -> Result<Self, Self::Error> {
        if v == &OID_SHA1_RSA {
            Ok(Self::RsaSha1)
        } else if v == &OID_SHA256_RSA {
            Ok(Self::RsaSha256)
        } else if v == &OID_SHA384_RSA {
            Ok(Self::RsaSha384)
        } else if v == &OID_SHA512_RSA {
            Ok(Self::RsaSha512)
        } else if v == &OID_ECDSA_SHA256 {
            Ok(Self::EcdsaSha256)
        } else if v == &OID_ECDSA_SHA384 {
            Ok(Self::EcdsaSha384)
        } else if v == &OID_ED25519_SIGNATURE_ALGORITHM {
            Ok(Self::Ed25519)
        } else {
            Err(Error::UnknownSignatureAlgorithm(format!("{}", v)))
        }
    }
}

impl TryFrom<&AlgorithmIdentifier> for SignatureAlgorithm {
    type Error = Error;

    fn try_from(v: &AlgorithmIdentifier) -> Result<Self, Self::Error> {
        let algorithm = Self::try_from(&v.algorithm)?;

        match algorithm {
            Self::RsaSha1 | Self::RsaSha256 | Self::RsaSha384 | Self::RsaSha512 => {
                if v.parameters.as_ref().is_some_and(|parameters| !parameters.is_null()) {
                    return Err(Error::UnhandledSignatureAlgorithmParameters(
                        "RSA parameters must be absent or NULL",
                    ));
                }
            }
            Self::EcdsaSha256 | Self::EcdsaSha384 | Self::Ed25519 => {
                if v.parameters.is_some() {
                    return Err(Error::UnhandledSignatureAlgorithmParameters(
                        "ECDSA and Ed25519 parameters must be absent",
                    ));
                }
            }
            Self::NoSignature(_) => {}
        }

        Ok(algorithm)
    }
}

impl From<SignatureAlgorithm> for AlgorithmIdentifier {
    fn from(alg: SignatureAlgorithm) -> Self {
        let parameters = match alg {
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512 => Some(AlgorithmParameter::null()),
            SignatureAlgorithm::EcdsaSha256
            | SignatureAlgorithm::EcdsaSha384
            | SignatureAlgorithm::Ed25519
            | SignatureAlgorithm::NoSignature(_) => None,
        };

        Self {
            algorithm: alg.into(),
            parameters,
        }
    }
}

/// Represents a known curve used with ECDSA.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EcdsaCurve {
    Secp256r1,
    Secp384r1,
}

impl EcdsaCurve {
    /// Obtain all variants of this type.
    pub fn all() -> &'static [Self] {
        &[Self::Secp256r1, Self::Secp384r1]
    }

    /// Obtain the OID representing this elliptic curve.
    pub fn as_signature_oid(&self) -> Oid {
        Oid(match self {
            Self::Secp256r1 => OID_EC_SECP256R1.as_ref().into(),
            Self::Secp384r1 => OID_EC_SECP384R1.as_ref().into(),
        })
    }
}

impl TryFrom<&Oid> for EcdsaCurve {
    type Error = Error;

    fn try_from(v: &Oid) -> Result<Self, Self::Error> {
        if v == &OID_EC_SECP256R1 {
            Ok(Self::Secp256r1)
        } else if v == &OID_EC_SECP384R1 {
            Ok(Self::Secp384r1)
        } else {
            Err(Error::UnknownEllipticCurve(format!("{}", v)))
        }
    }
}

/// Cryptographic algorithm used by a private key.
///
/// Instances can be converted to/from the underlying ASN.1 type and
/// OIDs.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyAlgorithm {
    /// RSA
    ///
    /// Corresponds to OID 1.2.840.113549.1.1.1.
    Rsa,

    /// Corresponds to OID 1.2.840.10045.2.1
    ///
    /// The inner OID tracks the curve / parameter in use.
    Ecdsa(EcdsaCurve),

    /// Corresponds to OID 1.3.101.112.
    Ed25519,
}

impl Display for KeyAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa => f.write_str("RSA"),
            Self::Ecdsa(_) => f.write_str("ECDSA"),
            Self::Ed25519 => f.write_str("ED25519"),
        }
    }
}

impl TryFrom<&Oid> for KeyAlgorithm {
    type Error = Error;

    fn try_from(v: &Oid) -> Result<Self, Self::Error> {
        if v == &OID_RSA {
            Ok(Self::Rsa)
        } else if v == &OID_EC_PUBLIC_KEY {
            // Default to an arbitrary elliptic curve when just the OID is given to us.
            Ok(Self::Ecdsa(EcdsaCurve::Secp384r1))
        } else if v == &OID_ED25519_SIGNATURE_ALGORITHM {
            Ok(Self::Ed25519)
        } else {
            Err(Error::UnknownKeyAlgorithm(format!("{}", v)))
        }
    }
}

impl TryFrom<&ObjectIdentifier> for KeyAlgorithm {
    type Error = Error;

    fn try_from(v: &ObjectIdentifier) -> Result<Self, Self::Error> {
        // Similar implementation as above.
        match v.as_bytes() {
            x if x == OID_RSA.as_ref() => Ok(Self::Rsa),
            x if x == OID_EC_PUBLIC_KEY.as_ref() => Ok(Self::Ecdsa(EcdsaCurve::Secp384r1)),
            x if x == OID_ED25519_SIGNATURE_ALGORITHM.as_ref() => Ok(Self::Ed25519),
            _ => Err(Error::UnknownKeyAlgorithm(v.to_string())),
        }
    }
}

impl From<KeyAlgorithm> for Oid {
    fn from(alg: KeyAlgorithm) -> Self {
        Oid(match alg {
            KeyAlgorithm::Rsa => OID_RSA.as_ref(),
            KeyAlgorithm::Ecdsa(_) => OID_EC_PUBLIC_KEY.as_ref(),
            KeyAlgorithm::Ed25519 => OID_ED25519_SIGNATURE_ALGORITHM.as_ref(),
        }
        .into())
    }
}

impl From<KeyAlgorithm> for ObjectIdentifier {
    fn from(alg: KeyAlgorithm) -> Self {
        let bytes = match alg {
            KeyAlgorithm::Rsa => OID_RSA.as_ref(),
            KeyAlgorithm::Ecdsa(_) => OID_EC_PUBLIC_KEY.as_ref(),
            KeyAlgorithm::Ed25519 => OID_ED25519_SIGNATURE_ALGORITHM.as_ref(),
        };

        ObjectIdentifier::from_bytes(bytes).expect("OID bytes should be valid")
    }
}

impl TryFrom<&AlgorithmIdentifier> for KeyAlgorithm {
    type Error = Error;

    fn try_from(v: &AlgorithmIdentifier) -> Result<Self, Self::Error> {
        // This will obtain a generic instance with defaults for configurable
        // parameters. So check for and apply parameters.
        let ka = Self::try_from(&v.algorithm)?;

        let ka = if let Some(params) = &v.parameters {
            match ka {
                Self::Ecdsa(_) => {
                    let curve_oid = params.decode_oid()?;
                    let curve = EcdsaCurve::try_from(&curve_oid)?;

                    Ok(Self::Ecdsa(curve))
                }
                Self::Ed25519 => Err(Error::UnhandledKeyAlgorithmParameters("on ED25519")),
                Self::Rsa => {
                    // NULL is meaningless. Just a placeholder. Allow it through.
                    if params.is_null() {
                        Ok(ka)
                    } else {
                        Err(Error::UnhandledKeyAlgorithmParameters("on RSA"))
                    }
                }
            }?
        } else {
            if matches!(ka, Self::Ecdsa(_)) {
                return Err(Error::UnhandledKeyAlgorithmParameters(
                    "named curve is required for ECDSA",
                ));
            }
            ka
        };

        Ok(ka)
    }
}

impl From<KeyAlgorithm> for AlgorithmIdentifier {
    fn from(alg: KeyAlgorithm) -> Self {
        let parameters = match alg {
            KeyAlgorithm::Ed25519 => None,
            KeyAlgorithm::Rsa => Some(AlgorithmParameter::null()),
            KeyAlgorithm::Ecdsa(curve) => {
                Some(AlgorithmParameter::from_oid(curve.as_signature_oid()))
            }
        };

        Self {
            algorithm: alg.into(),
            parameters,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn digest_pkcs1() -> Result<(), Error> {
        let message = b"deadbeef";
        let raw_digest = DigestAlgorithm::Sha256.digest_data(message);

        // RSA 1024.
        let encoded = DigestAlgorithm::Sha256.rsa_pkcs1_encode(message, 128)?;
        assert_eq!(&encoded[0..3], &[0x00, 0x01, 0xff]);
        assert_eq!(&encoded[96..], &raw_digest);

        Ok(())
    }

    #[test]
    fn digest_reader_handles_short_reads() {
        struct ShortReader<'a> {
            remaining: &'a [u8],
        }

        impl std::io::Read for ShortReader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let count = self.remaining.len().min(buf.len()).min(3);
                buf[..count].copy_from_slice(&self.remaining[..count]);
                self.remaining = &self.remaining[count..];
                Ok(count)
            }
        }

        let data = b"a reader may return fewer bytes without being at EOF";
        let expected = DigestAlgorithm::Sha256.digest_data(data);
        let actual = DigestAlgorithm::Sha256
            .digest_reader(&mut ShortReader { remaining: data })
            .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn key_algorithm_oids() -> Result<(), Error> {
        let oid = ObjectIdentifier::from(KeyAlgorithm::Rsa);
        assert_eq!(oid.to_string(), "1.2.840.113549.1.1.1");
        let oid = ObjectIdentifier::new("1.2.840.113549.1.1.1").unwrap();
        assert_eq!(KeyAlgorithm::try_from(&oid)?, KeyAlgorithm::Rsa);

        let oid = ObjectIdentifier::from(KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1));
        assert_eq!(oid.to_string(), "1.2.840.10045.2.1");
        let oid = ObjectIdentifier::new("1.2.840.10045.2.1").unwrap();
        assert_eq!(
            KeyAlgorithm::try_from(&oid)?,
            KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1)
        );

        let oid = ObjectIdentifier::from(KeyAlgorithm::Ed25519);
        assert_eq!(oid.to_string(), "1.3.101.112");
        let oid = ObjectIdentifier::new("1.3.101.112").unwrap();
        assert_eq!(KeyAlgorithm::try_from(&oid)?, KeyAlgorithm::Ed25519);

        Ok(())
    }

    #[test]
    fn algorithm_identifier_parameters_follow_algorithm_requirements() {
        let mut ed25519 = Vec::new();
        AlgorithmIdentifier::from(SignatureAlgorithm::Ed25519)
            .write_encoded(bcder::Mode::Der, &mut ed25519)
            .unwrap();
        assert_eq!(ed25519, [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);

        let mut rsa = Vec::new();
        AlgorithmIdentifier::from(SignatureAlgorithm::RsaSha256)
            .write_encoded(bcder::Mode::Der, &mut rsa)
            .unwrap();
        assert!(rsa.ends_with(&[0x05, 0x00]));

        let invalid_ed25519 = AlgorithmIdentifier {
            algorithm: SignatureAlgorithm::Ed25519.into(),
            parameters: Some(AlgorithmParameter::null()),
        };
        assert!(SignatureAlgorithm::try_from(&invalid_ed25519).is_err());
        assert!(KeyAlgorithm::try_from(&invalid_ed25519).is_err());
    }
}
