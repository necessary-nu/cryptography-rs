// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*! Cryptographic Message Syntax (RFC 5652) in Pure Rust

This crate attempts to implement parts of
[RFC 5652](https://tools.ietf.org/rfc/rfc5652.txt) in pure, safe Rust.

Functionality includes:

* Partial (de)serialization support for ASN.1 data structures. The
  Rust structs are all defined. But not everything has (de)serialization
  code implemented.
* High-level Rust API for extracting useful attributes from a parsed
  `SignedData` structure and performing common operations, such as verifying
  signature integrity.

RFC 5652 is quite old. If you are looking to digitally sign content, you may
want to look at something newer, such as RPKI (RFC 6488). (RPKI appears to
be the spiritual success to this specification.)

# IMPORTANT SECURITY LIMITATIONS

**The verification functionality in this crate is purposefully limited
and isn't sufficient for trusting signed data. You need to include additional
trust verification if you are using this crate for verifying signed data.**

This crate exposes functionality to verify signatures and content integrity
of *signed data*. Specifically it can verify that an embedded cryptographic
signature over some arbitrary/embedded content was issued by a known signing
certificate. This answers the question *did certificate X sign content Y*.
This is an important question to answer, but it fails to answer other important
questions such as:

* Is the signature cryptographically strong or weak? Do I trust the signature?
* Do I trust the signer?

Answering *do I trust the signer* is an extremely difficult and nuanced
problem. It entails things like:

* Ensuring the signing certificate is using secure cryptography.
* Validating that the signing certificate is one you think it was or was
  issued by a trusted party.
* Validating the certificate isn't expired or hasn't been revoked.
* Validating that the certificate contains attributes/extensions desired
  (e.g. a certificate can be earmarked as used for signing code).

If you are using this crate as part of verifying signed content, you need
to have answers to these hard questions. This will require writing code
beyond what is available in this crate. You ideally want to use existing
libraries for this, as getting this correct is difficult. Ideally you would
consult a security/cryptography domain expert for help.

Use `SignerInfo::verify_with_signed_data()` for encapsulated content or
`SignerInfo::verify_with_content()` for detached content when you want the
signature, signed content type, and signed message digest checked together.
The lower-level verification methods intentionally perform only part of that
work and are easy to misuse as a complete verifier.

Time-stamp verification checks CMS integrity, the message-imprint binding, ESS
certificate binding, time-stamping EKU, and certificate validity at generation
time. It does not validate the TSA chain, a trust anchor, revocation, or policy.

The ASN.1 parser has no general input-size, nesting-depth, or allocation limits;
the HTTP time-stamp client applies a 16 MiB response limit. Parsing untrusted
in-memory CMS still requires an application-level size limit.

RSA private-key operations use the RustCrypto `rsa` crate, which is covered by
RUSTSEC-2023-0071. Do not expose those operations to attackers who can repeatedly
request signatures and observe timing; use Ed25519/ECDSA or a hardened external
signer/HSM in that threat model.

# Technical Notes

RFC 5652 is based off PKCS #7 version 1.5 (RFC 2315). So common tools/libraries
for interacting with PKCS #7 may have success parsing this format. For example,
you can use OpenSSL to read the data structures:

```text
$ openssl pkcs7 -inform DER -in <filename> -print
$ openssl pkcs7 -inform PEM -in <filename> -print
$ openssl asn1parse -inform DER -in <filename>
```

RFC 5652 uses BER (not DER) for serialization. There were attempts to use
other, more popular BER/DER/ASN.1 serialization crates. However, we could
only get `bcder` working. In a similar vein, there are other crates
implementing support for common ASN.1 functionality, such as serializing
X.509 certificates. Again, many of these depend on serializers that don't
seem to be compatible with BER. So we've recursively defined ASN.1 data
structures referenced by RFC5652 and taught them to serialize using `bcder`.
*/

pub mod asn1;

mod signing;
#[cfg(feature = "http")]
mod time_stamp_protocol;

pub use signing::{SignedDataBuilder, SignerBuilder};
#[cfg(feature = "http")]
pub use {
    time_stamp_protocol::{
        time_stamp_message_http, time_stamp_request_http, TimeStampError, TimeStampResponse,
    },
};

pub use {bcder::Oid, bytes::Bytes};

/// Encoder used for public ASN.1 variants whose representation is not implemented.
pub(crate) struct UnsupportedEncoder(pub(crate) &'static str);

impl bcder::encode::Values for UnsupportedEncoder {
    fn encoded_len(&self, _mode: bcder::Mode) -> usize {
        0
    }

    fn write_encoded<W: std::io::Write>(
        &self,
        _mode: bcder::Mode,
        _target: &mut W,
    ) -> Result<(), std::io::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            self.0,
        ))
    }
}

/// Re-emit captured ASN.1 only when it is structurally valid in the requested mode.
pub(crate) struct CapturedValues<'a>(pub(crate) &'a bcder::Captured);

fn validate_captured_values(data: &[u8], mode: bcder::Mode) -> Result<(), std::io::Error> {
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

impl bcder::encode::Values for CapturedValues<'_> {
    fn encoded_len(&self, _mode: bcder::Mode) -> usize {
        self.0.as_slice().len()
    }

    fn write_encoded<W: std::io::Write>(
        &self,
        mode: bcder::Mode,
        target: &mut W,
    ) -> Result<(), std::io::Error> {
        validate_captured_values(self.0.as_slice(), mode)?;
        std::io::Write::write_all(target, self.0.as_slice())
    }
}

use {
    crate::asn1::{
        rfc3161::{
            OID_CONTENT_TYPE_TST_INFO, OID_SIGNING_CERTIFICATE,
            OID_SIGNING_CERTIFICATE_V2, OID_TIME_STAMP_TOKEN, TstInfo,
        },
        rfc5652::{
            CertificateChoices, CmsVersion, SignerIdentifier, Time, OID_CONTENT_TYPE, OID_ID_DATA,
            OID_MESSAGE_DIGEST, OID_SIGNING_TIME,
        },
    },
    bcder::{decode::Constructed, ConstOid, Integer, Mode, OctetString},
    pem::PemError,
    std::{
        collections::HashSet,
        fmt::{Debug, Display, Formatter},
        ops::Deref,
    },
    subtle::ConstantTimeEq,
    x509_certificate::{
        rfc3280::Name, CapturedX509Certificate, Digest, DigestAlgorithm, KeyAlgorithm,
        SignatureAlgorithm, SignatureVerifier, X509Certificate, X509CertificateError,
    },
};

/// X.509 extended key usage extension.
const OID_EXTENDED_KEY_USAGE: ConstOid = Oid(&[85, 29, 37]);

/// X.509 subject key identifier extension.
const OID_SUBJECT_KEY_IDENTIFIER: ConstOid = Oid(&[85, 29, 14]);

/// id-kp-timeStamping extended key purpose.
const OID_KEY_PURPOSE_TIME_STAMPING: ConstOid = Oid(&[43, 6, 1, 5, 5, 7, 3, 8]);

#[derive(Debug)]
pub enum CmsError {
    /// An error occurred decoding ASN.1 data.
    DecodeErr(bcder::decode::DecodeError<std::convert::Infallible>),

    /// The content-type attribute is missing from the SignedAttributes structure.
    MissingSignedAttributeContentType,

    /// The content-type attribute in the SignedAttributes structure is malformed.
    MalformedSignedAttributeContentType,

    /// The message-digest attribute is missed from the SignedAttributes structure.
    MissingSignedAttributeMessageDigest,

    /// The message-digest attribute is malformed.
    MalformedSignedAttributeMessageDigest,

    /// The signing-time signed attribute is malformed.
    MalformedSignedAttributeSigningTime,

    /// A signed attribute occurs more than once.
    DuplicateSignedAttribute(Oid),

    /// A signed attribute has no values.
    EmptySignedAttributeValues(Oid),

    /// Two different sources were configured for the content digest.
    ConflictingDigestContent,

    /// An unsigned attribute occurs more than once.
    DuplicateUnsignedAttribute(Oid),

    /// A signed content-type attribute does not match the encapsulated content type.
    SignedAttributeContentTypeMismatch,

    /// A signer's digest algorithm is not declared by `SignedData`.
    SignerDigestAlgorithmNotDeclared(DigestAlgorithm),

    /// A digest algorithm occurs more than once in `SignedData`.
    DuplicateDigestAlgorithm(DigestAlgorithm),

    /// The SignerInfo digest and signature algorithms are inconsistent.
    SignatureDigestAlgorithmMismatch {
        signature_algorithm: SignatureAlgorithm,
        digest_algorithm: DigestAlgorithm,
    },

    /// The SignedData version is inconsistent with its content.
    SignedDataVersionMismatch {
        expected: CmsVersion,
        actual: CmsVersion,
    },

    /// A SignerInfo version is inconsistent with its signer identifier.
    SignerInfoVersionMismatch {
        expected: CmsVersion,
        actual: CmsVersion,
    },

    /// Signed attributes are required for this encapsulated content type.
    SignedAttributesRequired,

    /// The time-stamp token unsigned attribute is malformed.
    MalformedUnsignedAttributeTimeStampToken,

    /// A general I/O error occurred.
    Io(std::io::Error),

    /// An unknown signing key algorithm was encountered.
    UnknownKeyAlgorithm(Oid),

    /// An unknown message digest algorithm was encountered.
    UnknownDigestAlgorithm(Oid),

    /// An unknown signature algorithm was encountered.
    UnknownSignatureAlgorithm(Oid),

    /// An unknown certificate format was encountered.
    UnknownCertificateFormat,

    /// A certificate was not found.
    CertificateNotFound,

    /// A signing key does not correspond to its declared signing certificate.
    SigningKeyCertificateMismatch,

    /// Signature verification fail.
    SignatureVerificationError,

    /// No `SignedAttributes` were present when they should have been.
    NoSignedAttributes,

    /// Encapsulated content is absent and must be supplied explicitly.
    DetachedContentRequired,

    /// Two content digests were not equivalent.
    DigestNotEqual,

    /// A time-stamp token was structurally invalid.
    MalformedTimeStampToken(&'static str),

    /// A time-stamp token does not cover the signature to which it is attached.
    TimeStampMessageImprintMismatch,

    /// Error encoding/decoding PEM data.
    Pem(PemError),

    /// Error occurred when creating a signature.
    SignatureCreation(signature::Error),

    /// Attempted to use a `Certificate` but we couldn't find the backing data for it.
    CertificateMissingData,

    /// Error occurred parsing a distinguished name field in a certificate.
    DistinguishedNameParseError,

    #[cfg(feature = "http")]
    /// Error occurred in Time-Stamp Protocol.
    TimeStampProtocol(TimeStampError),

    /// Error occurred in the x509-certificate crate.
    X509Certificate(X509CertificateError),
}

impl std::error::Error for CmsError {}

impl Display for CmsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecodeErr(e) => std::fmt::Display::fmt(e, f),
            Self::MissingSignedAttributeContentType => {
                f.write_str("content-type attribute missing from SignedAttributes")
            }
            Self::MalformedSignedAttributeContentType => {
                f.write_str("content-type attribute in SignedAttributes is malformed")
            }
            Self::MissingSignedAttributeMessageDigest => {
                f.write_str("message-digest attribute missing from SignedAttributes")
            }
            Self::MalformedSignedAttributeMessageDigest => {
                f.write_str("message-digest attribute in SignedAttributes is malformed")
            }
            Self::MalformedSignedAttributeSigningTime => {
                f.write_str("signing-time attribute in SignedAttributes is malformed")
            }
            Self::DuplicateSignedAttribute(oid) => {
                f.write_fmt(format_args!("duplicate signed attribute: {}", oid))
            }
            Self::EmptySignedAttributeValues(oid) => {
                f.write_fmt(format_args!("signed attribute has no values: {}", oid))
            }
            Self::ConflictingDigestContent => {
                f.write_str("different content was configured for the CMS message digest")
            }
            Self::DuplicateUnsignedAttribute(oid) => {
                f.write_fmt(format_args!("duplicate unsigned attribute: {}", oid))
            }
            Self::SignedAttributeContentTypeMismatch => {
                f.write_str("signed content-type does not match encapsulated content type")
            }
            Self::SignerDigestAlgorithmNotDeclared(algorithm) => f.write_fmt(format_args!(
                "signer digest algorithm is not declared by SignedData: {:?}",
                algorithm
            )),
            Self::DuplicateDigestAlgorithm(algorithm) => f.write_fmt(format_args!(
                "duplicate SignedData digest algorithm: {:?}",
                algorithm
            )),
            Self::SignatureDigestAlgorithmMismatch {
                signature_algorithm,
                digest_algorithm,
            } => f.write_fmt(format_args!(
                "signature algorithm {} requires a different digest than {}",
                signature_algorithm, digest_algorithm
            )),
            Self::SignedDataVersionMismatch { expected, actual } => f.write_fmt(format_args!(
                "SignedData version mismatch: expected {:?}, got {:?}",
                expected, actual
            )),
            Self::SignerInfoVersionMismatch { expected, actual } => f.write_fmt(format_args!(
                "SignerInfo version mismatch: expected {:?}, got {:?}",
                expected, actual
            )),
            Self::SignedAttributesRequired => {
                f.write_str("signed attributes are required for non-id-data content")
            }
            Self::MalformedUnsignedAttributeTimeStampToken => {
                f.write_str("time-stamp token attribute in UnsignedAttributes is malformed")
            }
            Self::Io(e) => std::fmt::Display::fmt(e, f),
            Self::UnknownKeyAlgorithm(oid) => {
                f.write_fmt(format_args!("unknown signing key algorithm: {}", oid))
            }
            Self::UnknownDigestAlgorithm(oid) => {
                f.write_fmt(format_args!("unknown digest algorithm: {}", oid))
            }
            Self::UnknownSignatureAlgorithm(oid) => {
                f.write_fmt(format_args!("unknown signature algorithm: {}", oid))
            }
            Self::UnknownCertificateFormat => f.write_str("unknown certificate format"),
            Self::CertificateNotFound => f.write_str("certificate not found"),
            Self::SigningKeyCertificateMismatch => {
                f.write_str("signing key does not match the signing certificate")
            }
            Self::SignatureVerificationError => f.write_str("signature verification failed"),
            Self::NoSignedAttributes => f.write_str("SignedAttributes structure is missing"),
            Self::DetachedContentRequired => {
                f.write_str("detached CMS content must be supplied explicitly")
            }
            Self::DigestNotEqual => f.write_str("digests not equivalent"),
            Self::MalformedTimeStampToken(reason) => {
                f.write_fmt(format_args!("malformed time-stamp token: {}", reason))
            }
            Self::TimeStampMessageImprintMismatch => {
                f.write_str("time-stamp token does not cover the attached signature")
            }
            Self::Pem(e) => f.write_fmt(format_args!("PEM error: {}", e)),
            Self::SignatureCreation(e) => {
                f.write_fmt(format_args!("error during signature creation: {}", e))
            }
            Self::CertificateMissingData => f.write_str("certificate data not available"),
            Self::DistinguishedNameParseError => {
                f.write_str("could not parse distinguished name data")
            }
            #[cfg(feature = "http")]
            Self::TimeStampProtocol(e) => {
                f.write_fmt(format_args!("Time-Stamp Protocol error: {}", e))
            }
            Self::X509Certificate(e) => {
                f.write_fmt(format_args!("X.509 certificate error: {:?}", e))
            }
        }
    }
}

impl From<bcder::decode::DecodeError<std::convert::Infallible>> for CmsError {
    fn from(e: bcder::decode::DecodeError<std::convert::Infallible>) -> Self {
        Self::DecodeErr(e)
    }
}

impl From<std::io::Error> for CmsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<PemError> for CmsError {
    fn from(e: PemError) -> Self {
        Self::Pem(e)
    }
}

#[cfg(feature = "http")]
impl From<TimeStampError> for CmsError {
    fn from(e: TimeStampError) -> Self {
        Self::TimeStampProtocol(e)
    }
}

impl From<signature::Error> for CmsError {
    fn from(e: signature::Error) -> Self {
        Self::SignatureCreation(e)
    }
}

impl From<X509CertificateError> for CmsError {
    fn from(e: X509CertificateError) -> Self {
        Self::X509Certificate(e)
    }
}

fn validate_signature_digest_algorithms(
    signature_algorithm: SignatureAlgorithm,
    digest_algorithm: DigestAlgorithm,
) -> Result<(), CmsError> {
    let required_digest = match signature_algorithm {
        // RFC 8419 requires SHA-512 in SignerInfo when Ed25519 is used.
        SignatureAlgorithm::Ed25519 => DigestAlgorithm::Sha512,
        SignatureAlgorithm::NoSignature(algorithm) => algorithm,
        algorithm => algorithm
            .digest_algorithm()
            .ok_or(CmsError::SignatureDigestAlgorithmMismatch {
                signature_algorithm,
                digest_algorithm,
            })?,
    };

    if digest_algorithm == required_digest {
        Ok(())
    } else {
        Err(CmsError::SignatureDigestAlgorithmMismatch {
            signature_algorithm,
            digest_algorithm,
        })
    }
}

/// Represents a CMS SignedData structure.
///
/// This is the high-level type representing a CMS signature of some data.
/// It contains a description of what was signed, the cryptographic signature
/// of what was signed, and likely the X.509 certificate chain for the
/// signing key.
///
/// This is a high-level data structure that ultimately gets (de)serialized
/// from/to ASN.1. It exists to facilitate common interactions with the
/// low-level ASN.1 without exposing the complexity of ASN.1.
#[derive(Clone)]
pub struct SignedData {
    /// Content digest algorithms used.
    digest_algorithms: HashSet<DigestAlgorithm>,

    /// Type of the encapsulated content.
    content_type: Oid,

    /// Content that was signed.
    ///
    /// This is optional because signed content can also be articulated
    /// via signed attributes inside the `SignerInfo` structure.
    signed_content: Option<Vec<u8>>,

    /// Certificates embedded within the data structure.
    ///
    /// While not required, it is common for the SignedData data structure
    /// to embed the X.509 certificates used to sign the data within. This
    /// field holds those certificates.
    ///
    /// This is an ASN.1 SET OF, so certificate order has no semantic meaning.
    certificates: Option<Vec<CapturedX509Certificate>>,

    /// Describes content signatures.
    signers: Vec<SignerInfo>,
}

impl Debug for SignedData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SignedData");
        s.field("digest_algorithms", &self.digest_algorithms);
        s.field("content_type", &format_args!("{}", self.content_type));
        s.field(
            "signed_content",
            &format_args!("{:?}", self.signed_content.as_ref().map(hex::encode)),
        );
        s.field("certificates", &self.certificates);
        s.field("signers", &self.signers);
        s.finish()
    }
}

impl SignedData {
    /// Construct an instance by parsing BER data.
    pub fn parse_ber(data: &[u8]) -> Result<Self, CmsError> {
        Self::try_from(&crate::asn1::rfc5652::SignedData::decode_ber(data)?)
    }

    /// Compute the digest of the encapsulated content using a specified algorithm.
    ///
    /// The returned value is likely used as the `message-digest` attribute type
    /// for use within signed attributes.
    ///
    /// You can get the raw bytes of the digest by calling its `.as_ref()`.
    pub fn message_digest_with_algorithm(&self, alg: DigestAlgorithm) -> Digest {
        let mut hasher = alg.digester();

        if let Some(content) = &self.signed_content {
            hasher.update(content);
        }

        hasher.finish()
    }

    /// Obtain encapsulated content that was signed.
    ///
    /// This is the defined `encapContentInfo cContent` value.
    pub fn signed_content(&self) -> Option<&[u8]> {
        if let Some(content) = &self.signed_content {
            Some(content)
        } else {
            None
        }
    }

    /// Obtain the type of the encapsulated content.
    pub fn content_type(&self) -> &Oid {
        &self.content_type
    }

    pub fn certificates(&self) -> Box<dyn Iterator<Item = &CapturedX509Certificate> + '_> {
        match self.certificates.as_ref() {
            Some(certs) => Box::new(certs.iter()),
            None => Box::new(std::iter::empty()),
        }
    }

    /// Obtain signing information attached to this instance.
    ///
    /// Each iterated value represents an entity that cryptographically signed
    /// the content. Use these objects to validate the signed data.
    pub fn signers(&self) -> impl Iterator<Item = &SignerInfo> {
        self.signers.iter()
    }
}

impl TryFrom<&crate::asn1::rfc5652::SignedData> for SignedData {
    type Error = CmsError;

    fn try_from(raw: &crate::asn1::rfc5652::SignedData) -> Result<Self, Self::Error> {
        let expected_version = if raw.certificates.as_ref().is_some_and(|certificates| {
            certificates
                .iter()
                .any(|certificate| matches!(certificate, CertificateChoices::Other(_)))
        }) {
            CmsVersion::V5
        } else if raw.certificates.as_ref().is_some_and(|certificates| {
            certificates.iter().any(|certificate| {
                matches!(certificate, CertificateChoices::AttributeCertificateV2(_))
            })
        }) {
            CmsVersion::V4
        } else if raw.content_info.content_type != OID_ID_DATA
            || raw
                .signer_infos
                .iter()
                .any(|signer| signer.version == CmsVersion::V3)
        {
            CmsVersion::V3
        } else {
            CmsVersion::V1
        };

        if raw.version != expected_version {
            return Err(CmsError::SignedDataVersionMismatch {
                expected: expected_version,
                actual: raw.version,
            });
        }

        let mut digest_algorithms = HashSet::new();
        for raw_algorithm in raw.digest_algorithms.iter() {
            let algorithm = DigestAlgorithm::try_from(raw_algorithm)?;
            if !digest_algorithms.insert(algorithm) {
                return Err(CmsError::DuplicateDigestAlgorithm(algorithm));
            }
        }

        let signed_content = raw
            .content_info
            .content
            .as_ref()
            .map(|content| content.to_bytes().to_vec());

        let certificates = if let Some(certs) = &raw.certificates {
            Some(
                certs
                    .iter()
                    .map(|choice| match choice {
                        CertificateChoices::Certificate(cert) => {
                            // Doing the ASN.1 round-tripping here isn't ideal and may
                            // lead to correctness bugs.
                            let cert = X509Certificate::from(cert.deref().clone());
                            let cert_ber = cert.encode_ber()?;

                            Ok(CapturedX509Certificate::from_ber(cert_ber)?)
                        }
                        _ => Err(CmsError::UnknownCertificateFormat),
                    })
                    .collect::<Result<Vec<_>, CmsError>>()?,
            )
        } else {
            None
        };

        let signers = raw
            .signer_infos
            .iter()
            .map(SignerInfo::try_from)
            .collect::<Result<Vec<_>, CmsError>>()?;

        if signers
            .iter()
            .any(|signer| signer.signature_algorithm == SignatureAlgorithm::Ed25519)
            && raw.digest_algorithms.iter().any(|algorithm| {
                matches!(
                    DigestAlgorithm::try_from(algorithm),
                    Ok(DigestAlgorithm::Sha512)
                )
                    && algorithm.parameters.is_some()
            })
        {
            return Err(X509CertificateError::UnhandledDigestAlgorithmParameters(
                "SHA-512 parameters must be absent when used with Ed25519 CMS signatures",
            )
            .into());
        }

        if raw.content_info.content_type != OID_ID_DATA
            && signers
                .iter()
                .any(|signer| signer.signed_attributes.is_none())
        {
            return Err(CmsError::SignedAttributesRequired);
        }

        if let Some(signer) = signers
            .iter()
            .find(|signer| !digest_algorithms.contains(&signer.digest_algorithm))
        {
            return Err(CmsError::SignerDigestAlgorithmNotDeclared(
                signer.digest_algorithm,
            ));
        }

        Ok(Self {
            digest_algorithms,
            content_type: raw.content_info.content_type.clone(),
            signed_content,
            certificates,
            signers,
        })
    }
}

/// Represents a CMS SignerInfo structure.
///
/// This is a high-level interface to the SignerInfo ASN.1 type. It supports
/// performing common operations against that type.
///
/// Instances of this type are logically equivalent to a single
/// signed assertion within a `SignedData` payload. There can be multiple
/// signers per `SignedData`, which is why this type exists on its own.
#[derive(Clone)]
pub struct SignerInfo {
    /// The X.509 certificate issuer.
    issuer: Option<Name>,

    /// The X.509 certificate serial number.
    serial_number: Option<Integer>,

    /// The X.509 subject key identifier, for version 3 signer identifiers.
    subject_key_identifier: Option<Vec<u8>>,

    /// The algorithm used for digesting signed content.
    digest_algorithm: DigestAlgorithm,

    /// Algorithm used for signing the digest.
    signature_algorithm: SignatureAlgorithm,

    /// The cryptographic signature.
    signature: Vec<u8>,

    /// Parsed signed attributes.
    signed_attributes: Option<SignedAttributes>,

    /// Raw data constituting SignedAttributes that needs to be digested.
    digested_signed_attributes_data: Option<Vec<u8>>,

    /// Parsed unsigned attributes.
    unsigned_attributes: Option<UnsignedAttributes>,
}

impl Debug for SignerInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SignerInfo");
        s.field("issuer", &self.issuer);
        s.field("serial_number", &self.serial_number);
        s.field(
            "subject_key_identifier",
            &format_args!("{:?}", self.subject_key_identifier.as_ref().map(hex::encode)),
        );
        s.field("digest_algorithm", &self.digest_algorithm);
        s.field("signature_algorithm", &self.signature_algorithm);
        s.field(
            "signature",
            &format_args!("{}", hex::encode(&self.signature)),
        );
        s.field("signed_attributes", &self.signed_attributes);
        s.field(
            "digested_signed_attributes_data",
            &format_args!(
                "{:?}",
                self.digested_signed_attributes_data
                    .as_ref()
                    .map(hex::encode)
            ),
        );
        s.field("unsigned_attributes", &self.unsigned_attributes);
        s.finish()
    }
}

impl SignerInfo {
    /// Obtain the signing X.509 certificate's issuer name and its serial number.
    ///
    /// The returned value can be used to locate the certificate so
    /// verification can be performed.
    pub fn certificate_issuer_and_serial(&self) -> Option<(&Name, &Integer)> {
        self.issuer.as_ref().zip(self.serial_number.as_ref())
    }

    /// Obtain the subject key identifier used to locate the signing certificate.
    pub fn subject_key_identifier(&self) -> Option<&[u8]> {
        self.subject_key_identifier.as_deref()
    }

    /// Obtain the message digest algorithm used by this signer.
    pub fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }

    /// Obtain the cryptographic signing algorithm used by this signer.
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm
    }

    /// Obtain the raw bytes constituting the cryptographic signature.
    ///
    /// This is the signature that should be verified.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Obtain the `SignedAttributes` attached to this instance.
    pub fn signed_attributes(&self) -> Option<&SignedAttributes> {
        self.signed_attributes.as_ref()
    }

    /// Obtain the `UnsignedAttributes` attached to this instance.
    pub fn unsigned_attributes(&self) -> Option<&UnsignedAttributes> {
        self.unsigned_attributes.as_ref()
    }

    /// Verifies the signature defined by this signer given a [SignedData] instance.
    ///
    /// This function will perform cryptographic verification that the signature
    /// contained within this `SignerInfo` instance is valid for the content that
    /// was signed. The content that was signed is the encapsulated content from
    /// the `SignedData` instance (its `.signed_data()` value) combined with
    /// the `SignedAttributes` attached to this instance.
    ///
    /// # IMPORTANT SECURITY LIMITATIONS
    ///
    /// This method only performs signature verification. It:
    ///
    /// * DOES NOT verify the digest hash embedded within `SignedAttributes` (if present).
    /// * DOES NOT validate the signing certificate in any way.
    /// * DOES NOT validate that the cryptography used is appropriate.
    /// * DOES NOT verify the time stamp token, if present.
    ///
    /// See the crate's documentation for more on the security implications.
    pub fn verify_signature_with_signed_data(
        &self,
        signed_data: &SignedData,
    ) -> Result<(), CmsError> {
        if self.signed_attributes.is_none() && signed_data.signed_content().is_none() {
            return Err(CmsError::DetachedContentRequired);
        }

        let signed_content = self.signed_content_with_signed_data(signed_data);

        self.verify_signature_with_signed_data_and_content(signed_data, &signed_content)
    }

    /// Verify the cryptographic integrity of this signer and the encapsulated content.
    ///
    /// This verifies the signature and, when signed attributes are present, also verifies
    /// their `message-digest` and `content-type` values. It does not establish certificate
    /// trust, validate a certificate chain, enforce an algorithm policy, or verify an
    /// attached time-stamp token.
    pub fn verify_with_signed_data(&self, signed_data: &SignedData) -> Result<(), CmsError> {
        if signed_data.signed_content().is_none() {
            return Err(CmsError::DetachedContentRequired);
        }

        self.verify_signature_with_signed_data(signed_data)?;

        if self.signed_attributes.is_some() {
            self.verify_message_digest_with_signed_data(signed_data)?;
        }

        Ok(())
    }

    /// Verify this signer against explicitly supplied encapsulated content.
    ///
    /// Use this for detached CMS signatures. It chooses the correct signature input
    /// depending on whether signed attributes are present, and verifies the signed
    /// `message-digest` and `content-type` when applicable.
    ///
    /// Like [`Self::verify_with_signed_data`], this establishes integrity only and
    /// does not establish signer or certificate trust.
    pub fn verify_with_content(
        &self,
        signed_data: &SignedData,
        content: &[u8],
    ) -> Result<(), CmsError> {
        if let Some(attributes) = &self.signed_attributes {
            if attributes.content_type != signed_data.content_type {
                return Err(CmsError::SignedAttributeContentTypeMismatch);
            }
            self.verify_signature_with_signed_data(signed_data)?;
            self.verify_message_digest_with_content(content)
        } else {
            self.verify_signature_with_signed_data_and_content(signed_data, content)
        }
    }

    /// Verifies the signature defined by this signer given a [SignedData] and signed content.
    ///
    /// This function will perform cryptographic verification that the signature contained within
    /// this [SignerInfo] is valid for `signed_content`. Unlike
    /// [Self::verify_signature_with_signed_data()], the content that was signed is passed in
    /// explicitly instead of derived from [SignedData].
    ///
    /// This is a low-level API that bypasses the normal rules for deriving the raw content a
    /// cryptographic signature was made over. You probably want to use
    /// [Self::verify_signature_with_signed_data()] instead. Also note that `signed_content` here
    /// may or may not be the _encapsulated content_ which is ultimately signed.
    ///
    /// This method only performs cryptographic signature verification. It is therefore subject
    /// to the same limitations as [Self::verify_signature_with_signed_data()].
    pub fn verify_signature_with_signed_data_and_content(
        &self,
        signed_data: &SignedData,
        signed_content: &[u8],
    ) -> Result<(), CmsError> {
        let verifier = self.signature_verifier(signed_data.certificates())?;
        let signature = self.signature();

        verifier
            .verify(signed_content, signature)
            .map_err(|_| CmsError::SignatureVerificationError)
    }

    /// Verifies the digest stored in signed attributes matches that of content in a `SignedData`.
    ///
    /// If signed attributes are present on this instance, they must contain
    /// a `message-digest` attribute defining the digest of data that was
    /// signed. The specification says this digested data should come from
    /// the encapsulated content within `SignedData` (`SignedData.signed_content()`).
    ///
    /// Note that some utilities of CMS will not store a computed digest
    /// in `message-digest` that came from `SignedData` or is using
    /// the digest algorithm indicated by this `SignerInfo`. This is strictly
    /// in violation of the specification but it does occur.
    ///
    /// # IMPORTANT SECURITY LIMITATIONS
    ///
    /// This method only performs message digest verification. It:
    ///
    /// * DOES NOT verify the signature over the signed data or anything about
    ///   the signer.
    /// * DOES NOT validate that the digest algorithm is strong/appropriate.
    ///
    /// Digest values are compared in constant time.
    ///
    /// See the crate's documentation for more on the security implications.
    pub fn verify_message_digest_with_signed_data(
        &self,
        signed_data: &SignedData,
    ) -> Result<(), CmsError> {
        let signed_attributes = self
            .signed_attributes()
            .ok_or(CmsError::NoSignedAttributes)?;
        let content = signed_data
            .signed_content()
            .ok_or(CmsError::DetachedContentRequired)?;

        let wanted_digest: &[u8] = signed_attributes.message_digest.as_ref();
        let got_digest = self.compute_digest(Some(content));

        if signed_attributes.content_type != signed_data.content_type {
            return Err(CmsError::SignedAttributeContentTypeMismatch);
        }

        if bool::from(wanted_digest.ct_eq(got_digest.as_ref())) {
            Ok(())
        } else {
            Err(CmsError::DigestNotEqual)
        }
    }

    /// Verifies the message digest stored in signed attributes using explicit encapsulated content.
    ///
    /// Typically, the digest is computed over content stored in the [SignedData] instance.
    /// However, it is possible for the signed content to be external. This function
    /// allows you to define the source of that external content.
    ///
    /// Behavior is very similar to [SignerInfo::verify_message_digest_with_signed_data]
    /// except the original content that was digested is explicitly passed in. This
    /// content is appended with the signed attributes data on this [SignerInfo].
    ///
    /// The security limitations from [SignerInfo::verify_message_digest_with_signed_data]
    /// apply to this function as well.
    pub fn verify_message_digest_with_content(&self, data: &[u8]) -> Result<(), CmsError> {
        let signed_attributes = self
            .signed_attributes()
            .ok_or(CmsError::NoSignedAttributes)?;

        let wanted_digest: &[u8] = signed_attributes.message_digest.as_ref();
        let got_digest = self.compute_digest(Some(data));

        if bool::from(wanted_digest.ct_eq(got_digest.as_ref())) {
            Ok(())
        } else {
            Err(CmsError::DigestNotEqual)
        }
    }

    /// Obtain an entity for validating the signature described by this instance.
    ///
    /// This will attempt to locate the certificate used by this signing info
    /// structure in the passed iterable of certificates and then construct
    /// a signature verifier that can be used to verify content integrity.
    ///
    /// If the certificate referenced by this signing info could not be found,
    /// an error occurs.
    ///
    /// If the signing key's algorithm or signature algorithm aren't supported,
    /// an error occurs.
    ///
    /// The matching certificate is data supplied by the CMS object or caller. This
    /// method does not validate its chain, validity, revocation status, key usage, or
    /// trust anchor.
    pub fn signature_verifier<'a, C>(
        &self,
        certs: C,
    ) -> Result<SignatureVerifier<Vec<u8>>, CmsError>
    where
        C: Iterator<Item = &'a CapturedX509Certificate>,
    {
        let signing_cert = self.signing_certificate(certs)?;

        let key_algorithm = signing_cert.key_algorithm().ok_or_else(|| {
            CmsError::UnknownKeyAlgorithm(signing_cert.key_algorithm_oid().clone())
        })?;

        let verification_algorithm = self
            .signature_algorithm
            .resolve_verification_algorithm(key_algorithm)?;

        let public_key = SignatureVerifier::new(
            verification_algorithm,
            signing_cert.public_key_data().to_vec(),
        );

        Ok(public_key)
    }

    /// Locate the certificate identified by this signer.
    ///
    /// This performs exact issuer-and-serial matching only. It does not validate
    /// certificate trust or any other PKI property.
    pub fn signing_certificate<'a, C>(
        &self,
        mut certs: C,
    ) -> Result<&'a CapturedX509Certificate, CmsError>
    where
        C: Iterator<Item = &'a CapturedX509Certificate>,
    {
        certs
            .find(|cert| {
                if let Some((issuer, serial_number)) = self.certificate_issuer_and_serial() {
                    serial_number == cert.serial_number_asn1() && issuer == cert.issuer_name()
                } else if let Some(wanted_identifier) = self.subject_key_identifier() {
                    let mut extensions = cert
                        .iter_extensions()
                        .filter(|extension| extension.id == OID_SUBJECT_KEY_IDENTIFIER);
                    let Some(extension) = extensions.next() else {
                        return false;
                    };
                    if extensions.next().is_some() {
                        return false;
                    }

                    Constructed::decode(extension.value.to_bytes(), Mode::Der, OctetString::take_from)
                        .map(|identifier| identifier.to_bytes().as_ref() == wanted_identifier)
                        .unwrap_or(false)
                } else {
                    false
                }
            })
            .ok_or(CmsError::CertificateNotFound)
    }

    fn time_stamp_signing_certificate_digest(&self) -> Result<(DigestAlgorithm, Vec<u8>), CmsError> {
        let attributes = self
            .signed_attributes
            .as_ref()
            .ok_or(CmsError::SignedAttributesRequired)?
            .attributes();
        let v1 = attributes
            .iter()
            .find(|attribute| attribute.typ == OID_SIGNING_CERTIFICATE);
        let v2 = attributes
            .iter()
            .find(|attribute| attribute.typ == OID_SIGNING_CERTIFICATE_V2);

        let (attribute, is_v2) = match (v1, v2) {
            (Some(attribute), None) => (attribute, false),
            (None, Some(attribute)) => (attribute, true),
            (None, None) => {
                return Err(CmsError::MalformedTimeStampToken(
                    "SigningCertificate attribute is missing",
                ))
            }
            (Some(_), Some(_)) => {
                return Err(CmsError::MalformedTimeStampToken(
                    "multiple SigningCertificate attribute forms are present",
                ))
            }
        };

        if attribute.values.len() != 1 {
            return Err(CmsError::MalformedTimeStampToken(
                "SigningCertificate attribute must contain one value",
            ));
        }

        let (algorithm, hash) = attribute.values[0].deref().clone().decode(|cons| {
            cons.take_sequence(|cons| {
                let first = cons.take_sequence(|cons| {
                    cons.take_sequence(|cons| {
                        let algorithm = if is_v2 {
                            crate::asn1::rfc5652::DigestAlgorithmIdentifier::take_opt_from(cons)?
                        } else {
                            None
                        };
                        let hash = OctetString::take_from(cons)?.to_bytes().to_vec();
                        cons.capture_all()?;
                        Ok((algorithm, hash))
                    })
                })?;
                cons.capture_all()?;
                Ok(first)
            })
        })?;

        let algorithm = if is_v2 {
            algorithm
                .as_ref()
                .map(DigestAlgorithm::try_from)
                .transpose()?
                .unwrap_or(DigestAlgorithm::Sha256)
        } else {
            DigestAlgorithm::Sha1
        };

        Ok((algorithm, hash))
    }

    fn verify_time_stamp_signing_certificate(
        &self,
        signed_data: &SignedData,
    ) -> Result<(), CmsError> {
        if signed_data.content_type != OID_CONTENT_TYPE_TST_INFO {
            return Err(CmsError::MalformedTimeStampToken(
                "encapsulated content type is not TSTInfo",
            ));
        }

        let certificate = self.signing_certificate(signed_data.certificates())?;
        let (algorithm, wanted_hash) = self.time_stamp_signing_certificate_digest()?;
        let got_hash = algorithm.digest_data(certificate.constructed_data());

        if !bool::from(wanted_hash.as_slice().ct_eq(got_hash.as_slice())) {
            return Err(CmsError::MalformedTimeStampToken(
                "SigningCertificate hash does not match the TSA certificate",
            ));
        }

        let mut extended_key_usage = certificate
            .iter_extensions()
            .filter(|extension| extension.id == OID_EXTENDED_KEY_USAGE);
        let extension = extended_key_usage.next().ok_or(
            CmsError::MalformedTimeStampToken("TSA certificate has no extended key usage"),
        )?;
        if extended_key_usage.next().is_some() || extension.critical != Some(true) {
            return Err(CmsError::MalformedTimeStampToken(
                "TSA certificate must have one critical extended key usage",
            ));
        }

        let key_purposes = Constructed::decode(extension.value.to_bytes(), Mode::Der, |cons| {
            cons.take_sequence(|cons| {
                let mut purposes = Vec::new();
                while let Some(purpose) = Oid::take_opt_from(cons)? {
                    purposes.push(purpose);
                }
                Ok(purposes)
            })
        })?;
        if key_purposes.as_slice() != [OID_KEY_PURPOSE_TIME_STAMPING] {
            return Err(CmsError::MalformedTimeStampToken(
                "TSA certificate extended key usage is not exclusively timeStamping",
            ));
        }

        let tst_info_content = signed_data
            .signed_content()
            .ok_or(CmsError::MalformedTimeStampToken(
                "encapsulated TSTInfo content is missing",
            ))?;
        let tst_info = Constructed::decode(tst_info_content, Mode::Der, TstInfo::take_from)?;
        let generation_time = chrono::DateTime::from(tst_info.gen_time);
        if !certificate.time_constraints_valid(Some(generation_time)) {
            return Err(CmsError::MalformedTimeStampToken(
                "TSA certificate was not valid at the token generation time",
            ));
        }

        Ok(())
    }

    /// Resolve the time-stamp token [SignedData] for this signer.
    ///
    /// The time-stamp token is a SignedData ASN.1 structure embedded as an unsigned
    /// attribute. This is a convenience method to extract it and turn it into
    /// a [SignedData].
    ///
    /// Returns `Ok(Some)` on success, `Ok(None)` if there is no time-stamp token,
    /// and `Err` if there is a parsing error.
    pub fn time_stamp_token_signed_data(&self) -> Result<Option<SignedData>, CmsError> {
        if let Some(attrs) = self.unsigned_attributes() {
            if let Some(signed_data) = &attrs.time_stamp_token {
                Ok(Some(SignedData::try_from(signed_data)?))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Verify the time-stamp token in this instance.
    ///
    /// The time-stamp token is a SignedData ASN.1 structure embedded as an unsigned
    /// attribute. So this method reconstructs that data structure and effectively
    /// calls [SignerInfo::verify_signature_with_signed_data] and
    /// [SignerInfo::verify_message_digest_with_signed_data].
    ///
    /// Returns `Ok(None)` if there is no time-stamp token and `Ok(Some(()))` if
    /// there is and its cryptographic integrity and message-imprint binding validate.
    /// `Err` occurs on any parse or verification error.
    ///
    /// This does **not** establish a trusted time: the TSA certificate is embedded in
    /// the token and this method does not validate its chain, trust anchor, or revocation
    /// status. It does require the RFC 3161 time-stamping extended key usage and checks
    /// that the certificate was valid at the token's generation time.
    pub fn verify_time_stamp_token(&self) -> Result<Option<()>, CmsError> {
        let signed_data = match self.time_stamp_token_signed_data()? { Some(v) => {
            v
        } _ => {
            return Ok(None);
        }};

        if signed_data.signers.len() != 1 {
            return Err(CmsError::MalformedTimeStampToken(
                "token must contain exactly one signer",
            ));
        }

        if signed_data.content_type != OID_CONTENT_TYPE_TST_INFO {
            return Err(CmsError::MalformedTimeStampToken(
                "encapsulated content type is not TSTInfo",
            ));
        }

        let content = signed_data
            .signed_content()
            .ok_or(CmsError::MalformedTimeStampToken(
                "encapsulated TSTInfo content is missing",
            ))?;
        let tst_info = Constructed::decode(content, Mode::Der, TstInfo::take_from)?;

        if tst_info.version != Integer::from(1) {
            return Err(CmsError::MalformedTimeStampToken(
                "unsupported TSTInfo version",
            ));
        }

        let digest_algorithm =
            DigestAlgorithm::try_from(&tst_info.message_imprint.hash_algorithm)?;
        let got_imprint = digest_algorithm.digest_data(&self.signature);
        let wanted_imprint = tst_info.message_imprint.hashed_message.to_bytes();

        if !bool::from(wanted_imprint.as_ref().ct_eq(got_imprint.as_ref())) {
            return Err(CmsError::TimeStampMessageImprintMismatch);
        }

        let signer = &signed_data.signers[0];
        signer.verify_with_signed_data(&signed_data)?;
        signer.verify_time_stamp_signing_certificate(&signed_data)?;

        Ok(Some(()))
    }

    /// Obtain the raw bytes of content that was signed given a `SignedData`.
    ///
    /// This joins the encapsulated content from `SignedData` with `SignedAttributes`
    /// on this instance to produce a new blob. This new blob is the message
    /// that is signed and whose signature is embedded in `SignerInfo` instances.
    pub fn signed_content_with_signed_data(&self, signed_data: &SignedData) -> Vec<u8> {
        self.signed_content(signed_data.signed_content())
    }

    /// Obtain the raw bytes of content that were digested and signed.
    ///
    /// The returned value is the message that was signed and whose signature
    /// of which needs to be verified.
    ///
    /// The optional content argument is the `encapContentInfo eContent`
    /// field, typically the value of `SignedData.signed_content()`.
    pub fn signed_content(&self, content: Option<&[u8]>) -> Vec<u8> {
        // Per RFC 5652 Section 5.4:
        //
        //    The result of the message digest calculation process depends on
        //    whether the signedAttrs field is present.  When the field is absent,
        //    the result is just the message digest of the content as described
        //    above.  When the field is present, however, the result is the message
        //    digest of the complete DER encoding of the SignedAttrs value
        //    contained in the signedAttrs field.  Since the SignedAttrs value,
        //    when present, must contain the content-type and the message-digest
        //    attributes, those values are indirectly included in the result.  The
        //    content-type attribute MUST NOT be included in a countersignature
        //    unsigned attribute as defined in Section 11.4.  A separate encoding
        //    of the signedAttrs field is performed for message digest calculation.
        //    The IMPLICIT [0] tag in the signedAttrs is not used for the DER
        //    encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
        //    encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0]
        //    tag, MUST be included in the message digest calculation along with
        //    the length and content octets of the SignedAttributes value.

        if let Some(signed_attributes_data) = &self.digested_signed_attributes_data {
            signed_attributes_data.clone()
        } else if let Some(content) = content {
            content.to_vec()
        } else {
            vec![]
        }
    }

    /// Obtain the raw bytes constituting `SignerInfo.signedAttrs` as encoded for signatures.
    ///
    /// Cryptographic signatures in the `SignerInfo` ASN.1 type are made from the digest
    /// of the `EXPLICIT SET OF` DER encoding of `SignerInfo.signedAttrs`, if signed
    /// attributes are present. This function resolves the raw bytes that are used
    /// for digest computation and later signing.
    ///
    /// This should always be `Some` if the instance was constructed from an ASN.1
    /// value that had signed attributes.
    pub fn signed_attributes_data(&self) -> Option<&[u8]> {
        self.digested_signed_attributes_data
            .as_ref()
            .map(|x| x.as_ref())
    }

    /// Compute a message digest using a `SignedData` instance.
    ///
    /// This will obtain the encapsulated content blob from a `SignedData`
    /// and digest it using the algorithm configured on this instance.
    ///
    /// The resulting digest is typically stored in the `message-digest`
    /// attribute of `SignedData`.
    pub fn compute_digest_with_signed_data(&self, signed_data: &SignedData) -> Digest {
        self.compute_digest(signed_data.signed_content())
    }

    /// Compute a message digest using the configured algorithm.
    ///
    /// This method calls into `compute_digest_with_algorithm()` using the
    /// digest algorithm stored in this instance.
    pub fn compute_digest(&self, content: Option<&[u8]>) -> Digest {
        self.compute_digest_with_algorithm(content, self.digest_algorithm)
    }

    /// Compute a message digest using an explicit digest algorithm.
    ///
    /// This will compute the hash/digest of the passed in content.
    pub fn compute_digest_with_algorithm(
        &self,
        content: Option<&[u8]>,
        alg: DigestAlgorithm,
    ) -> Digest {
        let mut hasher = alg.digester();

        if let Some(content) = content {
            hasher.update(content);
        }

        hasher.finish()
    }
}

impl TryFrom<&crate::asn1::rfc5652::SignerInfo> for SignerInfo {
    type Error = CmsError;

    fn try_from(signer_info: &crate::asn1::rfc5652::SignerInfo) -> Result<Self, Self::Error> {
        let expected_version = match &signer_info.sid {
            SignerIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V1,
            SignerIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V3,
        };
        if signer_info.version != expected_version {
            return Err(CmsError::SignerInfoVersionMismatch {
                expected: expected_version,
                actual: signer_info.version,
            });
        }

        let (issuer, serial_number, subject_key_identifier) = match &signer_info.sid {
            SignerIdentifier::IssuerAndSerialNumber(issuer) => {
                (
                    Some(issuer.issuer.clone()),
                    Some(issuer.serial_number.clone()),
                    None,
                )
            }
            SignerIdentifier::SubjectKeyIdentifier(identifier) => {
                (None, None, Some(identifier.to_bytes().to_vec()))
            }
        };

        let digest_algorithm = DigestAlgorithm::try_from(&signer_info.digest_algorithm)?;

        // The "signature" algorithm can also be a key algorithm identifier. So we
        // attempt to resolve using the more robust mechanism.
        let signature_algorithm =
            if SignatureAlgorithm::try_from(&signer_info.signature_algorithm.algorithm).is_ok() {
                SignatureAlgorithm::try_from(&signer_info.signature_algorithm)?
            } else {
                let resolved = SignatureAlgorithm::from_oid_and_digest_algorithm(
                    &signer_info.signature_algorithm.algorithm,
                    digest_algorithm,
                )?;

                if matches!(resolved, SignatureAlgorithm::NoSignature(_)) {
                    if signer_info.signature_algorithm.parameters.is_some() {
                        return Err(X509CertificateError::UnhandledSignatureAlgorithmParameters(
                            "noSignature parameters must be absent",
                        )
                        .into());
                    }
                } else {
                    // A generic key-algorithm identifier is accepted here for
                    // compatibility, but its parameters still need to satisfy the
                    // key algorithm's ASN.1 requirements.
                    KeyAlgorithm::try_from(&signer_info.signature_algorithm)?;
                }

                resolved
            };

        validate_signature_digest_algorithms(signature_algorithm, digest_algorithm)?;
        if signature_algorithm == SignatureAlgorithm::Ed25519
            && signer_info.digest_algorithm.parameters.is_some()
        {
            return Err(X509CertificateError::UnhandledDigestAlgorithmParameters(
                "SHA-512 parameters must be absent when used with Ed25519 CMS signatures",
            )
            .into());
        }

        let signature = signer_info.signature.to_bytes().to_vec();

        let signed_attributes = if let Some(attributes) = &signer_info.signed_attributes {
            for (index, attribute) in attributes.iter().enumerate() {
                if attributes[..index]
                    .iter()
                    .any(|candidate| candidate.typ == attribute.typ)
                {
                    return Err(CmsError::DuplicateSignedAttribute(attribute.typ.clone()));
                }
            }

            // Content type attribute MUST be present.
            let content_type = attributes
                .iter()
                .find(|attr| attr.typ == OID_CONTENT_TYPE)
                .ok_or(CmsError::MissingSignedAttributeContentType)?;

            // Content type attribute MUST have exactly 1 value.
            let [content_type] = content_type.values.as_slice() else {
                return Err(CmsError::MalformedSignedAttributeContentType);
            };

            let content_type = content_type
                .deref()
                .clone()
                .decode(Oid::take_from)
                .map_err(|_| CmsError::MalformedSignedAttributeContentType)?;

            // Message digest attribute MUST be present.
            let message_digest = attributes
                .iter()
                .find(|attr| attr.typ == OID_MESSAGE_DIGEST)
                .ok_or(CmsError::MissingSignedAttributeMessageDigest)?;

            // Message digest attribute MUST have exactly 1 value.
            let [message_digest] = message_digest.values.as_slice() else {
                return Err(CmsError::MalformedSignedAttributeMessageDigest);
            };

            let message_digest = message_digest
                .deref()
                .clone()
                .decode(OctetString::take_from)
                .map_err(|_| CmsError::MalformedSignedAttributeMessageDigest)?
                .to_bytes()
                .to_vec();

            // Signing time is optional, but common. So we pull it out for convenience.
            let signing_time = attributes
                .iter()
                .find(|attr| attr.typ == OID_SIGNING_TIME)
                .map(|attr| {
                    let [value] = attr.values.as_slice() else {
                        return Err(CmsError::MalformedSignedAttributeSigningTime);
                    };
                    let time = value.deref().clone().decode(Time::take_from)?;

                    Ok(chrono::DateTime::from(time))
                })
                .transpose()?;

            Some(SignedAttributes {
                content_type,
                message_digest,
                signing_time,
                raw: attributes.clone(),
            })
        } else {
            None
        };

        let digested_signed_attributes_data = signer_info.signed_attributes_digested_content()?;

        let unsigned_attributes = if let Some(attributes) = &signer_info.unsigned_attributes {
            for (index, attribute) in attributes.iter().enumerate() {
                if attributes[..index]
                    .iter()
                    .any(|candidate| candidate.typ == attribute.typ)
                {
                    return Err(CmsError::DuplicateUnsignedAttribute(attribute.typ.clone()));
                }
            }

            let time_stamp_token = attributes
                .iter()
                .find(|attr| attr.typ == OID_TIME_STAMP_TOKEN)
                .map(|attr| {
                    let [value] = attr.values.as_slice() else {
                        return Err(CmsError::MalformedUnsignedAttributeTimeStampToken);
                    };
                    Ok(value
                        .deref()
                        .clone()
                        .decode(crate::asn1::rfc5652::SignedData::decode)?)
                })
                .transpose()?;

            Some(UnsignedAttributes { time_stamp_token })
        } else {
            None
        };

        Ok(SignerInfo {
            issuer,
            serial_number,
            subject_key_identifier,
            digest_algorithm,
            signature_algorithm,
            signature,
            signed_attributes,
            digested_signed_attributes_data,
            unsigned_attributes,
        })
    }
}

/// Represents the contents of a CMS SignedAttributes structure.
///
/// This is a high-level interface to the SignedAttributes ASN.1 type.
#[derive(Clone)]
pub struct SignedAttributes {
    /// The content type of the value being signed.
    ///
    /// This is often `OID_ID_DATA`.
    content_type: Oid,

    /// Holds the digest of the content that was signed.
    message_digest: Vec<u8>,

    /// The time the signature was created.
    signing_time: Option<chrono::DateTime<chrono::Utc>>,

    /// The raw ASN.1 signed attributes.
    raw: crate::asn1::rfc5652::SignedAttributes,
}

impl SignedAttributes {
    pub fn content_type(&self) -> &Oid {
        &self.content_type
    }

    pub fn message_digest(&self) -> &[u8] {
        &self.message_digest
    }

    pub fn signing_time(&self) -> Option<&chrono::DateTime<chrono::Utc>> {
        self.signing_time.as_ref()
    }

    pub fn attributes(&self) -> &crate::asn1::rfc5652::SignedAttributes {
        &self.raw
    }
}

impl Debug for SignedAttributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SignedAttributes");
        s.field("content_type", &format_args!("{}", self.content_type));
        s.field(
            "message_digest",
            &format_args!("{}", hex::encode(&self.message_digest)),
        );
        s.field("signing_time", &self.signing_time);
        s.finish()
    }
}

#[derive(Clone, Debug)]
pub struct UnsignedAttributes {
    /// Time-Stamp Token from a Time-Stamp Protocol server.
    time_stamp_token: Option<crate::asn1::rfc5652::SignedData>,
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        bcder::{encode::Values, Mode},
    };

    // This signature was extracted from the Firefox.app/Contents/MacOS/firefox
    // Mach-O executable on a aarch64 machine.
    const FIREFOX_SIGNATURE: &[u8] = include_bytes!("testdata/firefox.ber");

    const FIREFOX_CODE_DIRECTORY: &[u8] = include_bytes!("testdata/firefox-code-directory");

    #[test]
    fn parse_firefox() {
        let raw = crate::asn1::rfc5652::SignedData::decode_ber(FIREFOX_SIGNATURE).unwrap();

        // Try to round trip it.
        let mut buffer = Vec::new();
        raw.encode_ref()
            .write_encoded(Mode::Ber, &mut buffer)
            .unwrap();

        // The bytes aren't identical because we use definite length encoding, so we can't
        // compare that. But we can compare the parsed objects for equivalence.

        let raw2 = crate::asn1::rfc5652::SignedData::decode_ber(&buffer).unwrap();
        assert_eq!(raw, raw2, "BER round tripping is identical");
    }

    #[test]
    fn verify_firefox() {
        let signed_data = SignedData::parse_ber(FIREFOX_SIGNATURE).unwrap();

        for signer in signed_data.signers.iter() {
            signer
                .verify_signature_with_signed_data(&signed_data)
                .unwrap();

            // The message-digest does NOT match the encapsulated data in Apple code
            // signature's use of CMS. So digest verification will fail.
            signer
                .verify_message_digest_with_signed_data(&signed_data)
                .unwrap_err();

            // But we know what that value is. So plug it in to verify.
            signer
                .verify_message_digest_with_content(FIREFOX_CODE_DIRECTORY)
                .unwrap();

            // Now verify the time-stamp token embedded as an unsigned attribute.
            let tst_signed_data = signer.time_stamp_token_signed_data().unwrap().unwrap();

            for signer in tst_signed_data.signers() {
                signer
                    .verify_message_digest_with_signed_data(&tst_signed_data)
                    .unwrap();
                signer
                    .verify_signature_with_signed_data(&tst_signed_data)
                    .unwrap();
            }

            assert!(signer.verify_time_stamp_token().unwrap().is_some());

            let mut altered_signer = signer.clone();
            altered_signer.signature[0] ^= 1;
            assert!(matches!(
                altered_signer.verify_time_stamp_token(),
                Err(CmsError::TimeStampMessageImprintMismatch)
            ));
        }
    }

    #[test]
    fn parse_no_certificate_version() {
        let signed = SignedData::parse_ber(include_bytes!("testdata/no-cert-version.ber")).unwrap();

        let cert_orig = signed.certificates().collect::<Vec<_>>()[0].clone();
        let cert = CapturedX509Certificate::from_der(cert_orig.encode_ber().unwrap()).unwrap();

        assert_eq!(
            hex::encode(cert.sha256_fingerprint().unwrap()),
            "b7c2eefd8dac7806af67dfcd92eb18126bc08312a7f2d6f3862e46013c7a6135"
        );
    }

    const IZZYSOFT_SIGNED_DATA: &[u8] = include_bytes!("testdata/izzysoft-signeddata");
    const IZZYSOFT_DATA: &[u8] = include_bytes!("testdata/izzysoft-data");

    #[test]
    fn verify_izzysoft() {
        let signed = SignedData::parse_ber(IZZYSOFT_SIGNED_DATA).unwrap();
        let cert = signed.certificates().next().unwrap();

        for signer in signed.signers() {
            // The signed data is external. So this method will fail since it isn't looking at
            // the correct source data.
            assert!(matches!(
                signer.verify_signature_with_signed_data(&signed),
                Err(CmsError::DetachedContentRequired)
            ));

            // There are no signed attributes. So this should error for that reason.
            assert!(matches!(
                signer.verify_message_digest_with_signed_data(&signed),
                Err(CmsError::NoSignedAttributes)
            ));

            assert!(matches!(
                signer.verify_message_digest_with_signed_data(&signed),
                Err(CmsError::NoSignedAttributes)
            ));

            // The certificate advertises SHA-256 for digests but the signature was made with
            // SHA-1. This deprecated convenience method therefore chooses incorrectly.
            #[allow(deprecated)]
            let inferred_algorithm_result =
                cert.verify_signed_data(IZZYSOFT_DATA, signer.signature());
            assert!(matches!(
                inferred_algorithm_result,
                Err(X509CertificateError::CertificateSignatureVerificationFailed)
            ));

            // But it verifies when SHA-1 digests are forced!
            cert.verify_signed_data_with_algorithm(
                IZZYSOFT_DATA,
                signer.signature(),
                SignatureAlgorithm::RsaSha1
                    .resolve_verification_algorithm(x509_certificate::KeyAlgorithm::Rsa)
                    .unwrap(),
            )
            .unwrap();

            signer
                .verify_signature_with_signed_data_and_content(&signed, IZZYSOFT_DATA)
                .unwrap();
            signer.verify_with_content(&signed, IZZYSOFT_DATA).unwrap();

            let verifier = signer.signature_verifier(signed.certificates()).unwrap();
            verifier.verify(IZZYSOFT_DATA, signer.signature()).unwrap();
        }
    }
}
