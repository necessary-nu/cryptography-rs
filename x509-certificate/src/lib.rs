// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Interface with X.509 certificates.
//!
//! This crate provides an interface to X.509 certificates.
//!
//! Low-level ASN.1 primitives are defined in modules having the name of the
//! RFC in which they are defined.
//!
//! Higher-level primitives that most end-users will want to use are defined
//! in sub-modules but exported from the main crate.
//!
//! # Features
//!
//! * Parse X.509 certificates from BER, DER, and PEM.
//! * Access and manipulation of low-level ASN.1 data structures defining
//!   certificates. See [rfc5280::Certificate] for the main X.509 certificate type.
//! * Serialize X.509 certificates to BER, DER, and PEM.
//! * Higher-level APIs for interfacing with [rfc3280::Name] types, which
//!   define subject and issuer fields but have a very difficult to work with
//!   data structure.
//! * Rust enums defining key algorithms [KeyAlgorithm], signature algorithms
//!   [SignatureAlgorithm], and digest algorithms [DigestAlgorithm] commonly
//!   found in X.509 certificates. These can be converted to/from OIDs as well
//!   as to their respective ASN.1 types that express them in X.509 certificates.
//! * Verification of cryptographic signatures in certificates. If you have a
//!   parsed X.509 certificate and a public key (which is embedded in the
//!   issuing certificate), we can tell you if that certificate was signed
//!   by that key/certificate.
//! * Generating new X.509 certificates with an easy-to-use builder type. See
//!   [X509CertificateBuilder].
//!
//! # Security Disclaimer
//!
//! This crate has not received a formal, independent security audit. It may
//! contain severe bugs and does not implement X.509 path or trust validation.
//!
//! In particular, the ASN.1 parser is not hardened against malicious inputs and
//! has no explicit input-size, nesting-depth, or allocation limits. Support for
//! ASN.1 types and algorithms is intentionally partial. Unsupported encodings
//! normally return errors, but callers should not treat successful parsing or
//! signature verification as evidence that a certificate is trusted.
//!
//! RSA operations use the RustCrypto `rsa` crate, which is currently covered by
//! RUSTSEC-2023-0071. Do not expose RSA private-key operations where an attacker
//! can make requests and observe their timing. Prefer Ed25519 or ECDSA, or use a
//! separately hardened signer/HSM, for such deployments.
//!
//! # Known Issues
//!
//! This code was originally developed as part of the [cryptographic-message-syntax]
//! crate, which was developed to support implement Apple code signing in pure Rust.
//! After reinventing X.509 certificate handling logic in multiple crates, it was
//! decided to create this crate as a unified interface to managing X.509 certificates.
//! While an attempt has been made to make the APIs useful in a standalone context,
//! some of the history of this crate's intent may leak into its design. PRs that
//! pass GitHub Actions to improve matters are gladly accepted!
//!
//! Not all ASN.1 types are implemented. Unsupported variants and less-tested
//! code paths can return errors. Patches to improve the situation are much
//! appreciated!
//!
//! We are using the bcder crate for ASN.1. Use of the yasna crate would be preferred,
//! as it seems to be more popular. However, the author initially couldn't get yasna
//! working with RFC 5652 ASN.1. However, this was likely due to his lack of knowledge
//! of ASN.1 at the time. A port to yasna (or any other ASN.1 parser) might be in the
//! future.
//!
//! Because of the history of this crate, many tests covering its functionality exist
//! elsewhere in the repo. Overall test coverage could also likely be improved.
//! There is no fuzzing or corpora of X.509 certificates that we're testing against,
//! for example.

pub mod algorithm;
pub use algorithm::{
    Digest, DigestAlgorithm, DigestContext, EcdsaCurve, KeyAlgorithm, SignatureAlgorithm,
    SignatureVerifier, VerificationAlgorithm,
};
pub mod asn1time;
pub mod certificate;
pub use certificate::{
    CapturedX509Certificate, MutableX509Certificate, X509Certificate, X509CertificateBuilder,
};
pub mod rfc2986;
pub mod rfc3280;
pub mod rfc3447;
pub mod rfc4519;
pub mod rfc5280;
pub mod rfc5480;
pub mod rfc5652;
pub mod rfc5915;
pub mod rfc5958;
pub mod rfc8017;
pub mod signing;
pub use signing::{InMemorySigningKeyPair, KeyInfoSigner, Sign, Signature};
#[cfg(any(feature = "test", test))]
pub mod testutil;

use thiserror::Error;
use std::io::Write;

use bcder::{Mode, encode::Values};

pub use bcder::{ConstOid, Oid};
pub use signature::Signer;

/// Errors related to X.509 certificate handling.
#[derive(Debug, Error)]
pub enum X509CertificateError {
    #[error("unknown digest algorithm: {0}")]
    UnknownDigestAlgorithm(String),

    #[error("unknown signature algorithm: {0}")]
    UnknownSignatureAlgorithm(String),

    #[error("unknown key algorithm: {0}")]
    UnknownKeyAlgorithm(String),

    #[error("unknown elliptic curve: {0}")]
    UnknownEllipticCurve(String),

    #[error("KeyAlgorithm encountered unexpected algorithm parameters: {0}")]
    UnhandledKeyAlgorithmParameters(&'static str),

    #[error("DigestAlgorithm encountered unexpected algorithm parameters: {0}")]
    UnhandledDigestAlgorithmParameters(&'static str),

    #[error("SignatureAlgorithm encountered unexpected algorithm parameters: {0}")]
    UnhandledSignatureAlgorithmParameters(&'static str),

    #[error("can not verify {1:?} signatures made with key algorithm {0:?}")]
    UnsupportedSignatureVerification(KeyAlgorithm, SignatureAlgorithm),

    #[error("rejected private key: {0}")]
    PrivateKeyRejected(String),

    #[error("DER error: {0}")]
    Der(der::Error),

    #[error("error when decoding ASN.1 data: {0}")]
    Asn1Parse(bcder::decode::DecodeError<std::convert::Infallible>),

    #[error("I/O error occurred: {0}")]
    Io(#[from] std::io::Error),

    #[error("error decoding PEM data: {0}")]
    PemDecode(pem::PemError),

    #[error("error creating signature: {0}")]
    SigningError(#[from] signature::Error),

    #[error("error creating cryptographic signature with memory-backed key-pair")]
    SignatureCreationInMemoryKey,

    #[error("certificate signature verification failed")]
    CertificateSignatureVerificationFailed,

    #[error("original TBSCertificate data is unavailable")]
    CertificateMissingData,

    #[error("certificate signature algorithm does not match TBSCertificate signature algorithm")]
    CertificateSignatureAlgorithmMismatch,

    #[error("certificate signature BIT STRING has unused bits")]
    CertificateSignatureHasUnusedBits,

    #[error("error generating key pair")]
    KeyPairGenerationError,

    #[error("RSA key generation is not supported")]
    RsaKeyGenerationNotSupported,

    #[error("target length for PKCS#1 padding to too short")]
    PkcsEncodeTooShort,

    #[error("certificate serial number must be positive")]
    InvalidCertificateSerialNumber,

    #[error("certificate validity end precedes its start")]
    InvalidCertificateValidity,

    #[error("duplicate certificate extension: {0}")]
    DuplicateCertificateExtension(String),

    #[error("CSR attribute must contain at least one value: {0}")]
    EmptyCsrAttributeValues(String),

    #[error("an explicit issuer name requires a distinct issuer signing key")]
    IssuerSigningKeyRequired,

    #[error("an issuer name is required when the issuer and subject keys differ")]
    IssuerNameRequired,

    #[error("certificate issuer name must not be empty")]
    EmptyCertificateIssuer,

    #[error("an empty certificate subject requires a non-empty critical subjectAltName")]
    EmptyCertificateSubjectWithoutSubjectAltName,

    #[error("unhandled error: {0}")]
    Other(String),
}

/// Encoder used for public ASN.1 variants whose representation is not implemented.
///
/// Returning an encoding error is preferable to panicking when a caller constructs
/// one of these low-level variants directly.
pub(crate) struct UnsupportedEncoder(pub(crate) &'static str);

impl Values for UnsupportedEncoder {
    fn encoded_len(&self, _mode: Mode) -> usize {
        0
    }

    fn write_encoded<W: Write>(
        &self,
        _mode: Mode,
        _target: &mut W,
    ) -> Result<(), std::io::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            self.0,
        ))
    }
}

/// Re-emit captured ASN.1 only when it is structurally valid in the requested mode.
///
/// `bcder::Captured` panics when its parse and output modes differ. Public
/// parse-then-encode APIs should return an I/O error instead.
pub(crate) struct CapturedValues<'a>(pub(crate) &'a bcder::Captured);

fn validate_captured_values(data: &[u8], mode: Mode) -> Result<(), std::io::Error> {
    // Give bcder a bounded constructed value so it can validate any number of
    // captured child values without relying on Captured's original mode.
    let mut envelope = Vec::with_capacity(data.len() + 16);
    envelope.push(0x30);
    if mode.is_cer() {
        envelope.push(0x80);
        envelope.extend_from_slice(data);
        envelope.extend_from_slice(&[0, 0]);
    } else {
        if data.len() < 0x80 {
            envelope.push(data.len() as u8);
        } else {
            let bytes = data.len().to_be_bytes();
            let first = bytes.iter().position(|value| *value != 0).unwrap_or(bytes.len() - 1);
            envelope.push(0x80 | (bytes.len() - first) as u8);
            envelope.extend_from_slice(&bytes[first..]);
        }
        envelope.extend_from_slice(data);
    }

    bcder::decode::Constructed::decode(envelope.as_slice(), mode, |cons| {
        cons.take_sequence(|cons| cons.skip_all())
    })
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))
}

impl Values for CapturedValues<'_> {
    fn encoded_len(&self, _mode: Mode) -> usize {
        self.0.as_slice().len()
    }

    fn write_encoded<W: Write>(
        &self,
        mode: Mode,
        target: &mut W,
    ) -> Result<(), std::io::Error> {
        validate_captured_values(self.0.as_slice(), mode)?;
        target.write_all(self.0.as_slice())
    }
}

impl From<der::Error> for X509CertificateError {
    fn from(e: der::Error) -> Self {
        Self::Der(e)
    }
}

impl From<bcder::decode::DecodeError<std::convert::Infallible>> for X509CertificateError {
    fn from(e: bcder::decode::DecodeError<std::convert::Infallible>) -> Self {
        Self::Asn1Parse(e)
    }
}
