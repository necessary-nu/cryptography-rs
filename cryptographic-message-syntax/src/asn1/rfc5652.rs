// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*! ASN.1 data structures defined by RFC 5652.

The types defined in this module are intended to be extremely low-level
and only to be used for (de)serialization. See types outside the
`asn1` module tree for higher-level functionality.

Some RFC 5652 types are defined in the `x509-certificate` crate, which
this crate relies on for certificate parsing functionality.
*/

use {
    crate::asn1::rfc3281::AttributeCertificate,
    bcder::{
        decode::{Constructed, DecodeError, Source},
        encode,
        encode::{PrimitiveContent, Values},
        BitString, Captured, ConstOid, Integer, Mode, OctetString, Oid, Tag,
    },
    std::{
        fmt::{Debug, Formatter},
        io::Write,
        ops::{Deref, DerefMut},
    },
    x509_certificate::{asn1time::*, rfc3280::*, rfc5280::*, rfc5652::*},
};

/// The data content type.
///
/// `id-data` in the specification.
///
/// 1.2.840.113549.1.7.1
pub const OID_ID_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 1]);

/// The signed-data content type.
///
/// 1.2.840.113549.1.7.2
pub const OID_ID_SIGNED_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 2]);

/// Enveloped data content type.
///
/// 1.2.840.113549.1.7.3
pub const OID_ENVELOPE_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 3]);

/// Digested-data content type.
///
/// 1.2.840.113549.1.7.5
pub const OID_DIGESTED_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 5]);

/// Encrypted-data content type.
///
/// 1.2.840.113549.1.7.6
pub const OID_ENCRYPTED_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 6]);

/// Authenticated-data content type.
///
/// 1.2.840.113549.1.9.16.1.2
pub const OID_AUTHENTICATED_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 2]);

/// Identifies the content-type attribute.
///
/// 1.2.840.113549.1.9.3
pub const OID_CONTENT_TYPE: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 3]);

/// Identifies the message-digest attribute.
///
/// 1.2.840.113549.1.9.4
pub const OID_MESSAGE_DIGEST: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 4]);

/// Identifies the signing-time attribute.
///
/// 1.2.840.113549.1.9.5
pub const OID_SIGNING_TIME: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 5]);

/// Identifies the countersignature attribute.
///
/// 1.2.840.113549.1.9.6
pub const OID_COUNTER_SIGNATURE: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 6]);

/// Content info.
///
/// ```ASN.1
/// ContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   content [0] EXPLICIT ANY DEFINED BY contentType }
/// ```
#[derive(Clone, Debug)]
pub struct ContentInfo {
    pub content_type: ContentType,
    pub content: Captured,
}

impl PartialEq for ContentInfo {
    fn eq(&self, other: &Self) -> bool {
        self.content_type == other.content_type
            && self.content.as_slice() == other.content.as_slice()
    }
}

impl Eq for ContentInfo {}

impl ContentInfo {
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| Self::from_sequence(cons))
    }

    pub fn from_sequence<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let content_type = ContentType::take_from(cons)?;
        let content = cons.take_constructed_if(Tag::CTX_0, |cons| cons.capture_one())?;

        Ok(Self {
            content_type,
            content,
        })
    }
}

impl Values for ContentInfo {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

impl ContentInfo {
    fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.content_type.encode_ref(),
            encode::Constructed::new(Tag::CTX_0, crate::CapturedValues(&self.content)),
        ))
    }
}

/// Represents signed data.
///
/// ASN.1 type specification:
///
/// ```ASN.1
/// SignedData ::= SEQUENCE {
///   version CMSVersion,
///   digestAlgorithms DigestAlgorithmIdentifiers,
///   encapContentInfo EncapsulatedContentInfo,
///   certificates [0] IMPLICIT CertificateSet OPTIONAL,
///   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///   signerInfos SignerInfos }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedData {
    pub version: CmsVersion,
    pub digest_algorithms: DigestAlgorithmIdentifiers,
    pub content_info: EncapsulatedContentInfo,
    pub certificates: Option<CertificateSet>,
    pub crls: Option<RevocationInfoChoices>,
    pub signer_infos: SignerInfos,
}

impl SignedData {
    /// Attempt to decode BER encoded bytes to a parsed data structure.
    pub fn decode_ber(data: &[u8]) -> Result<Self, DecodeError<std::convert::Infallible>> {
        Constructed::decode(data, bcder::Mode::Ber, Self::decode)
    }

    pub fn decode<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let oid = Oid::take_from(cons)?;

            if oid != OID_ID_SIGNED_DATA {
                return Err(cons.content_err("expected signed data OID"));
            }

            cons.take_constructed_if(Tag::CTX_0, Self::take_from)
        })
    }

    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let version = CmsVersion::take_from(cons)?;
            let digest_algorithms = DigestAlgorithmIdentifiers::take_from(cons)?;
            let content_info = EncapsulatedContentInfo::take_from(cons)?;
            let certificates =
                cons.take_opt_constructed_if(Tag::CTX_0, |cons| CertificateSet::take_from(cons))?;
            let crls = cons.take_opt_constructed_if(Tag::CTX_1, |cons| {
                RevocationInfoChoices::take_from(cons)
            })?;
            let signer_infos = SignerInfos::take_from(cons)?;

            Ok(Self {
                version,
                digest_algorithms,
                content_info,
                certificates,
                crls,
                signer_infos,
            })
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            OID_ID_SIGNED_DATA.encode_ref(),
            encode::sequence_as(
                Tag::CTX_0,
                encode::sequence((
                    self.version.encode(),
                    self.digest_algorithms.encode_ref(),
                    self.content_info.encode_ref(),
                    self.certificates
                        .as_ref()
                        .map(|certs| certs.encode_ref_as(Tag::CTX_0)),
                    self.crls.as_ref().map(|_| {
                        crate::UnsupportedEncoder(
                            "encoding SignedData revocation info is not implemented",
                        )
                    }),
                    self.signer_infos.encode_ref(),
                )),
            ),
        ))
    }
}

/// Digest algorithm identifiers.
///
/// ```ASN.1
/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DigestAlgorithmIdentifiers(Vec<DigestAlgorithmIdentifier>);

impl Deref for DigestAlgorithmIdentifiers {
    type Target = Vec<DigestAlgorithmIdentifier>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DigestAlgorithmIdentifiers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl DigestAlgorithmIdentifiers {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_set(|cons| {
            let mut identifiers = Vec::new();

            while let Some(identifier) = AlgorithmIdentifier::take_opt_from(cons)? {
                identifiers.push(identifier);
            }

            Ok(Self(identifiers))
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::set(&self.0)
    }
}

pub type DigestAlgorithmIdentifier = AlgorithmIdentifier;

/// Signer infos.
///
/// ```ASN.1
/// SignerInfos ::= SET OF SignerInfo
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignerInfos(Vec<SignerInfo>);

impl Deref for SignerInfos {
    type Target = Vec<SignerInfo>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SignerInfos {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl SignerInfos {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_set(|cons| {
            let mut infos = Vec::new();

            while let Some(info) = SignerInfo::take_opt_from(cons)? {
                infos.push(info);
            }

            Ok(Self(infos))
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::set(&self.0)
    }
}

/// Encapsulated content info.
///
/// ```ASN.1
/// EncapsulatedContentInfo ::= SEQUENCE {
///   eContentType ContentType,
///   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct EncapsulatedContentInfo {
    pub content_type: ContentType,
    pub content: Option<OctetString>,
}

impl Debug for EncapsulatedContentInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("EncapsulatedContentInfo");
        s.field("content_type", &format_args!("{}", self.content_type));
        s.field(
            "content",
            &format_args!(
                "{:?}",
                self.content
                    .as_ref()
                    .map(|x| hex::encode(x.clone().to_bytes().as_ref()))
            ),
        );
        s.finish()
    }
}

impl EncapsulatedContentInfo {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let content_type = ContentType::take_from(cons)?;
            let content =
                cons.take_opt_constructed_if(Tag::CTX_0, |cons| OctetString::take_from(cons))?;

            Ok(Self {
                content_type,
                content,
            })
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.content_type.encode_ref(),
            self.content
                .as_ref()
                .map(|content| encode::sequence_as(Tag::CTX_0, content.encode_ref())),
        ))
    }
}

/// Per-signer information.
///
/// ```ASN.1
/// SignerInfo ::= SEQUENCE {
///   version CMSVersion,
///   sid SignerIdentifier,
///   digestAlgorithm DigestAlgorithmIdentifier,
///   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///   signatureAlgorithm SignatureAlgorithmIdentifier,
///   signature SignatureValue,
///   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct SignerInfo {
    pub version: CmsVersion,
    pub sid: SignerIdentifier,
    pub digest_algorithm: DigestAlgorithmIdentifier,
    pub signed_attributes: Option<SignedAttributes>,
    pub signature_algorithm: SignatureAlgorithmIdentifier,
    pub signature: SignatureValue,
    pub unsigned_attributes: Option<UnsignedAttributes>,

    /// Raw bytes backing signed attributes data.
    ///
    /// Does not include constructed tag or length bytes.
    pub signed_attributes_data: Option<Vec<u8>>,
}

fn der_set_from_contents(contents: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(contents.len() + 1 + std::mem::size_of::<usize>());
    encoded.push(0x31);

    if contents.len() < 0x80 {
        encoded.push(contents.len() as u8);
    } else {
        let length_bytes = contents.len().to_be_bytes();
        let first = length_bytes
            .iter()
            .position(|value| *value != 0)
            .unwrap_or(length_bytes.len() - 1);
        encoded.push(0x80 | (length_bytes.len() - first) as u8);
        encoded.extend_from_slice(&length_bytes[first..]);
    }

    encoded.extend_from_slice(contents);
    encoded
}

impl SignerInfo {
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| Self::from_sequence(cons))
    }

    pub fn from_sequence<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let version = CmsVersion::take_from(cons)?;
        let sid = SignerIdentifier::take_from(cons)?;
        let digest_algorithm = DigestAlgorithmIdentifier::take_from(cons)?;
        let signed_attributes = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
            // RFC 5652 Section 5.3: SignedAttributes MUST be DER encoded, even if the
            // rest of the structure is BER encoded. So buffer all data so we can
            // feed into a new decoder.
            let der = cons.capture_all()?;

            // But wait there's more! The raw data constituting the signed
            // attributes is also digested and used for content/signature
            // verification. Because our DER serialization may not roundtrip
            // losslessly, we stash away a copy of these bytes so they may be
            // referenced as part of verification.
            let der_data = der.as_slice().to_vec();

            let attributes = Constructed::decode(der.as_slice(), bcder::Mode::Der, |cons| {
                SignedAttributes::take_from_set(cons)
            })
            .map_err(|e| e.convert())?;

            let canonical_attributes = attributes
                .as_sorted()
                .map_err(|error| cons.content_err(error.to_string()))?;
            let mut canonical_der = Vec::new();
            canonical_attributes
                .write_encoded(Mode::Der, &mut canonical_der)
                .map_err(|error| cons.content_err(error.to_string()))?;
            if canonical_der != der_set_from_contents(&der_data) {
                return Err(cons.content_err("signed attributes are not canonical DER"));
            }

            Ok((attributes, der_data))
        })?;

        let (signed_attributes, signed_attributes_data) = if let Some((x, y)) = signed_attributes {
            (Some(x), Some(y))
        } else {
            (None, None)
        };

        let signature_algorithm = SignatureAlgorithmIdentifier::take_from(cons)?;
        let signature = SignatureValue::take_from(cons)?;
        let unsigned_attributes = cons
            .take_opt_constructed_if(Tag::CTX_1, |cons| UnsignedAttributes::take_from_set(cons))?;

        Ok(Self {
            version,
            sid,
            digest_algorithm,
            signed_attributes,
            signature_algorithm,
            signature,
            unsigned_attributes,
            signed_attributes_data,
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            u8::from(self.version).encode(),
            &self.sid,
            &self.digest_algorithm,
            // Always write signed attributes with DER encoding per RFC 5652.
            self.signed_attributes
                .as_ref()
                .map(|attrs| SignedAttributesDer::new(attrs.clone(), Some(Tag::CTX_0))),
            &self.signature_algorithm,
            self.signature.encode_ref(),
            self.unsigned_attributes
                .as_ref()
                .map(|attrs| attrs.encode_ref_as(Tag::CTX_1)),
        ))
    }

    /// Obtain content representing the signed attributes data to be digested.
    ///
    /// Computing the content to go into the digest calculation is nuanced.
    /// From RFC 5652:
    ///
    ///    The result of the message digest calculation process depends on
    ///    whether the signedAttrs field is present.  When the field is absent,
    ///    the result is just the message digest of the content as described
    ///    above.  When the field is present, however, the result is the message
    ///    digest of the complete DER encoding of the SignedAttrs value
    ///    contained in the signedAttrs field.  Since the SignedAttrs value,
    ///    when present, must contain the content-type and the message-digest
    ///    attributes, those values are indirectly included in the result.  The
    ///    content-type attribute MUST NOT be included in a countersignature
    ///    unsigned attribute as defined in Section 11.4.  A separate encoding
    ///    of the signedAttrs field is performed for message digest calculation.
    ///    The `IMPLICIT [0]` tag in the signedAttrs is not used for the DER
    ///    encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
    ///    encoding of the EXPLICIT SET OF tag, rather than of the `IMPLICIT [0]`
    ///    tag, MUST be included in the message digest calculation along with
    ///    the length and content octets of the SignedAttributes value.
    ///
    /// A few things to note here:
    ///
    /// * We must ensure DER (not BER) encoding of the entire SignedAttrs values.
    /// * The SignedAttr tag must use `EXPLICIT SET OF` instead of `IMPLICIT [0]`,
    ///   so default encoding is not appropriate.
    /// * If this instance came into existence via a parse, we stashed away the
    ///   raw bytes constituting SignedAttributes to ensure we can do a lossless
    ///   copy.
    pub fn signed_attributes_digested_content(&self) -> Result<Option<Vec<u8>>, std::io::Error> {
        if let Some(signed_attributes) = &self.signed_attributes {
            if let Some(existing_data) = &self.signed_attributes_data {
                Ok(Some(der_set_from_contents(existing_data)))
            } else {
                // No existing copy present. Serialize from raw data structures.
                // But we obtain a sorted instance of those attributes first, because
                // bcder doesn't appear to follow DER encoding rules for sets.
                let signed_attributes = signed_attributes.as_sorted()?;
                let mut der = Vec::new();
                // The mode argument here is actually ignored.
                signed_attributes.write_encoded(Mode::Der, &mut der)?;

                Ok(Some(der))
            }
        } else {
            Ok(None)
        }
    }
}

impl Debug for SignerInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SignerInfo");

        s.field("version", &self.version);
        s.field("sid", &self.sid);
        s.field("digest_algorithm", &self.digest_algorithm);
        s.field("signed_attributes", &self.signed_attributes);
        s.field("signature_algorithm", &self.signature_algorithm);
        s.field(
            "signature",
            &format_args!(
                "{}",
                hex::encode(self.signature.clone().into_bytes().as_ref())
            ),
        );
        s.field("unsigned_attributes", &self.unsigned_attributes);
        s.field(
            "signed_attributes_data",
            &format_args!(
                "{:?}",
                self.signed_attributes_data.as_ref().map(hex::encode)
            ),
        );
        s.finish()
    }
}

impl Values for SignerInfo {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

/// Identifies the signer.
///
/// ```ASN.1
/// SignerIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier [0] SubjectKeyIdentifier }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignerIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

impl SignerIdentifier {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        match cons.take_opt_value_if(Tag::CTX_0, SubjectKeyIdentifier::from_content)? { Some(identifier) => {
            Ok(Self::SubjectKeyIdentifier(identifier))
        } _ => {
            Ok(Self::IssuerAndSerialNumber(
                IssuerAndSerialNumber::take_from(cons)?,
            ))
        }}
    }
}

impl Values for SignerIdentifier {
    fn encoded_len(&self, mode: Mode) -> usize {
        match self {
            Self::IssuerAndSerialNumber(v) => v.encode_ref().encoded_len(mode),
            Self::SubjectKeyIdentifier(v) => v.encode_ref_as(Tag::CTX_0).encoded_len(mode),
        }
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        match self {
            Self::IssuerAndSerialNumber(v) => v.encode_ref().write_encoded(mode, target),
            Self::SubjectKeyIdentifier(v) => {
                v.encode_ref_as(Tag::CTX_0).write_encoded(mode, target)
            }
        }
    }
}

/// Signed attributes.
///
/// ```ASN.1
/// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignedAttributes(Vec<Attribute>);

impl Deref for SignedAttributes {
    type Target = Vec<Attribute>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SignedAttributes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl SignedAttributes {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_set(|cons| Self::take_from_set(cons))
    }

    pub fn take_from_set<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let mut attributes = Vec::new();

        while let Some(attribute) = Attribute::take_opt_from(cons)? {
            attributes.push(attribute);
        }

        Ok(Self(attributes))
    }

    /// Obtain an instance where the attributes are sorted according to DER
    /// rules. See the comment in [SignerInfo::signed_attributes_digested_content].
    pub fn as_sorted(&self) -> Result<Self, std::io::Error> {
        // Sorted is based on encoding of each Attribute, per DER encoding rules.
        // The encoding is supported to be padded with 0s. But Rust will sort a
        // shorter value with a prefix match against a longer value as less than,
        // so we can avoid the padding.

        let mut normalized = self.0.clone();
        for attribute in &mut normalized {
            let mut values = attribute
                .values
                .drain(..)
                .map(|value| {
                    let mut encoded = Vec::new();
                    value.write_encoded(Mode::Der, &mut encoded)?;
                    Ok((encoded, value))
                })
                .collect::<Result<Vec<_>, std::io::Error>>()?;
            values.sort_by(|(left, _), (right, _)| left.cmp(right));
            attribute.values = values.into_iter().map(|(_, value)| value).collect();
        }

        let mut attributes = normalized
            .into_iter()
            .map(|attribute| {
                let mut encoded = vec![];
                // See (https://github.com/indygreg/cryptography-rs/issues/16)
                // The entire attribute must be encoded in order to be compared
                // to a sibling attribute
                attribute
                    .encode_ref()
                    .write_encoded(Mode::Der, &mut encoded)?;

                Ok((encoded, attribute))
            })
            .collect::<Result<Vec<(_, _)>, std::io::Error>>()?;

        attributes.sort_by(|(a, _), (b, _)| a.cmp(b));

        Ok(Self(
            attributes.into_iter().map(|(_, x)| x).collect::<Vec<_>>(),
        ))
    }

    fn encode_ref(&self) -> impl Values + '_ {
        encode::set(encode::slice(&self.0, |x| x.clone().encode()))
    }

    fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::set_as(tag, encode::slice(&self.0, |x| x.clone().encode()))
    }
}

impl Values for SignedAttributes {
    // SignedAttributes are always written as DER encoded.
    fn encoded_len(&self, _: Mode) -> usize {
        self.encode_ref().encoded_len(Mode::Der)
    }

    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(Mode::Der, target)
    }
}

pub struct SignedAttributesDer(SignedAttributes, Option<Tag>);

impl SignedAttributesDer {
    pub fn new(sa: SignedAttributes, tag: Option<Tag>) -> Self {
        Self(sa, tag)
    }
}

impl Values for SignedAttributesDer {
    fn encoded_len(&self, _: Mode) -> usize {
        if let Some(tag) = &self.1 {
            self.0.encode_ref_as(*tag).encoded_len(Mode::Der)
        } else {
            self.0.encode_ref().encoded_len(Mode::Der)
        }
    }

    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        if let Some(tag) = &self.1 {
            self.0.encode_ref_as(*tag).write_encoded(Mode::Der, target)
        } else {
            self.0.encode_ref().write_encoded(Mode::Der, target)
        }
    }
}

/// Unsigned attributes.
///
/// ```ASN.1
/// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnsignedAttributes(Vec<Attribute>);

impl Deref for UnsignedAttributes {
    type Target = Vec<Attribute>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for UnsignedAttributes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl UnsignedAttributes {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_set(|cons| Self::take_from_set(cons))
    }

    pub fn take_from_set<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let mut attributes = Vec::new();

        while let Some(attribute) = Attribute::take_opt_from(cons)? {
            attributes.push(attribute);
        }

        Ok(Self(attributes))
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::set_as(tag, encode::slice(&self.0, |x| x.clone().encode()))
    }
}

pub type SignatureValue = OctetString;

/// Enveloped-data content type.
///
/// ```ASN.1
/// EnvelopedData ::= SEQUENCE {
///   version CMSVersion,
///   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///   recipientInfos RecipientInfos,
///   encryptedContentInfo EncryptedContentInfo,
///   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopedData {
    pub version: CmsVersion,
    pub originator_info: Option<OriginatorInfo>,
    pub recipient_infos: RecipientInfos,
    pub encrypted_content_info: EncryptedContentInfo,
    pub unprotected_attributes: Option<UnprotectedAttributes>,
}

/// Originator info.
///
/// ```ASN.1
/// OriginatorInfo ::= SEQUENCE {
///   certs [0] IMPLICIT CertificateSet OPTIONAL,
///   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginatorInfo {
    pub certs: Option<CertificateSet>,
    pub crls: Option<RevocationInfoChoices>,
}

pub type RecipientInfos = Vec<RecipientInfo>;

/// Encrypted content info.
///
/// ```ASN.1
/// EncryptedContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
///   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedContentInfo {
    pub content_type: ContentType,
    pub content_encryption_algorithms: ContentEncryptionAlgorithmIdentifier,
    pub encrypted_content: Option<EncryptedContent>,
}

pub type EncryptedContent = OctetString;

pub type UnprotectedAttributes = Vec<Attribute>;

/// Recipient info.
///
/// ```ASN.1
/// RecipientInfo ::= CHOICE {
///   ktri KeyTransRecipientInfo,
///   kari [1] KeyAgreeRecipientInfo,
///   kekri [2] KEKRecipientInfo,
///   pwri [3] PasswordRecipientinfo,
///   ori [4] OtherRecipientInfo }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecipientInfo {
    KeyTransRecipientInfo(KeyTransRecipientInfo),
    KeyAgreeRecipientInfo(KeyAgreeRecipientInfo),
    KekRecipientInfo(KekRecipientInfo),
    PasswordRecipientInfo(PasswordRecipientInfo),
    OtherRecipientInfo(OtherRecipientInfo),
}

pub type EncryptedKey = OctetString;

/// Key trans recipient info.
///
/// ```ASN.1
/// KeyTransRecipientInfo ::= SEQUENCE {
///   version CMSVersion,  -- always set to 0 or 2
///   rid RecipientIdentifier,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   encryptedKey EncryptedKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyTransRecipientInfo {
    pub version: CmsVersion,
    pub rid: RecipientIdentifier,
    pub key_encryption_algorithm: KeyEncryptionAlgorithmIdentifier,
    pub encrypted_key: EncryptedKey,
}

/// Recipient identifier.
///
/// ```ASN.1
/// RecipientIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier [0] SubjectKeyIdentifier }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecipientIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

/// Key agreement recipient info.
///
/// ```ASN.1
/// KeyAgreeRecipientInfo ::= SEQUENCE {
///   version CMSVersion,  -- always set to 3
///   originator [0] EXPLICIT OriginatorIdentifierOrKey,
///   ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   recipientEncryptedKeys RecipientEncryptedKeys }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyAgreeRecipientInfo {
    pub version: CmsVersion,
    pub originator: OriginatorIdentifierOrKey,
    pub ukm: Option<UserKeyingMaterial>,
    pub key_encryption_algorithm: KeyEncryptionAlgorithmIdentifier,
    pub recipient_encrypted_keys: RecipientEncryptedKeys,
}

/// Originator identifier or key.
///
/// ```ASN.1
/// OriginatorIdentifierOrKey ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier [0] SubjectKeyIdentifier,
///   originatorKey [1] OriginatorPublicKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OriginatorIdentifierOrKey {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    SubjectKeyIdentifier(SubjectKeyIdentifier),
    OriginatorKey(OriginatorPublicKey),
}

/// Originator public key.
///
/// ```ASN.1
/// OriginatorPublicKey ::= SEQUENCE {
///   algorithm AlgorithmIdentifier,
///   publicKey BIT STRING }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginatorPublicKey {
    pub algorithm: AlgorithmIdentifier,
    pub public_key: BitString,
}

/// SEQUENCE of RecipientEncryptedKey.
type RecipientEncryptedKeys = Vec<RecipientEncryptedKey>;

/// Recipient encrypted key.
///
/// ```ASN.1
/// RecipientEncryptedKey ::= SEQUENCE {
///   rid KeyAgreeRecipientIdentifier,
///   encryptedKey EncryptedKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientEncryptedKey {
    pub rid: KeyAgreeRecipientInfo,
    pub encrypted_key: EncryptedKey,
}

/// Key agreement recipient identifier.
///
/// ```ASN.1
/// KeyAgreeRecipientIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   rKeyId [0] IMPLICIT RecipientKeyIdentifier }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyAgreeRecipientIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    RKeyId(RecipientKeyIdentifier),
}

/// Recipient key identifier.
///
/// ```ASN.1
/// RecipientKeyIdentifier ::= SEQUENCE {
///   subjectKeyIdentifier SubjectKeyIdentifier,
///   date GeneralizedTime OPTIONAL,
///   other OtherKeyAttribute OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientKeyIdentifier {
    pub subject_key_identifier: SubjectKeyIdentifier,
    pub date: Option<GeneralizedTime>,
    pub other: Option<OtherKeyAttribute>,
}

type SubjectKeyIdentifier = OctetString;

/// Key encryption key recipient info.
///
/// ```ASN.1
/// KEKRecipientInfo ::= SEQUENCE {
///   version CMSVersion,  -- always set to 4
///   kekid KEKIdentifier,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   encryptedKey EncryptedKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KekRecipientInfo {
    pub version: CmsVersion,
    pub kek_id: KekIdentifier,
    pub kek_encryption_algorithm: KeyEncryptionAlgorithmIdentifier,
    pub encrypted_key: EncryptedKey,
}

/// Key encryption key identifier.
///
/// ```ASN.1
/// KEKIdentifier ::= SEQUENCE {
///   keyIdentifier OCTET STRING,
///   date GeneralizedTime OPTIONAL,
///   other OtherKeyAttribute OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KekIdentifier {
    pub key_identifier: OctetString,
    pub date: Option<GeneralizedTime>,
    pub other: Option<OtherKeyAttribute>,
}

/// Password recipient info.
///
/// ```ASN.1
/// PasswordRecipientInfo ::= SEQUENCE {
///   version CMSVersion,   -- Always set to 0
///   keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
///                                OPTIONAL,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   encryptedKey EncryptedKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordRecipientInfo {
    pub version: CmsVersion,
    pub key_derivation_algorithm: Option<KeyDerivationAlgorithmIdentifier>,
    pub key_encryption_algorithm: KeyEncryptionAlgorithmIdentifier,
    pub encrypted_key: EncryptedKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtherRecipientInfo {
    pub ori_type: Oid,
    // TODO Any
    pub ori_value: Option<()>,
}

/// Digested data.
///
/// ```ASN.1
/// DigestedData ::= SEQUENCE {
///   version CMSVersion,
///   digestAlgorithm DigestAlgorithmIdentifier,
///   encapContentInfo EncapsulatedContentInfo,
///   digest Digest }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestedData {
    pub version: CmsVersion,
    pub digest_algorithm: DigestAlgorithmIdentifier,
    pub content_type: EncapsulatedContentInfo,
    pub digest: Digest,
}

pub type Digest = OctetString;

/// Encrypted data.
///
/// ```ASN.1
/// EncryptedData ::= SEQUENCE {
///   version CMSVersion,
///   encryptedContentInfo EncryptedContentInfo,
///   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedData {
    pub version: CmsVersion,
    pub encrypted_content_info: EncryptedContentInfo,
    pub unprotected_attributes: Option<UnprotectedAttributes>,
}

/// Authenticated data.
///
/// ```ASN.1
/// AuthenticatedData ::= SEQUENCE {
///   version CMSVersion,
///   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///   recipientInfos RecipientInfos,
///   macAlgorithm MessageAuthenticationCodeAlgorithm,
///   digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
///   encapContentInfo EncapsulatedContentInfo,
///   authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
///   mac MessageAuthenticationCode,
///   unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedData {
    pub version: CmsVersion,
    pub originator_info: Option<OriginatorInfo>,
    pub recipient_infos: RecipientInfos,
    pub mac_algorithm: MessageAuthenticationCodeAlgorithm,
    pub digest_algorithm: Option<DigestAlgorithmIdentifier>,
    pub content_info: EncapsulatedContentInfo,
    pub authenticated_attributes: Option<AuthAttributes>,
    pub mac: MessageAuthenticationCode,
    pub unauthenticated_attributes: Option<UnauthAttributes>,
}

pub type AuthAttributes = Vec<Attribute>;

pub type UnauthAttributes = Vec<Attribute>;

pub type MessageAuthenticationCode = OctetString;

pub type SignatureAlgorithmIdentifier = AlgorithmIdentifier;

pub type KeyEncryptionAlgorithmIdentifier = AlgorithmIdentifier;

pub type ContentEncryptionAlgorithmIdentifier = AlgorithmIdentifier;

pub type MessageAuthenticationCodeAlgorithm = AlgorithmIdentifier;

pub type KeyDerivationAlgorithmIdentifier = AlgorithmIdentifier;

/// Revocation info choices.
///
/// ```ASN.1
/// RevocationInfoChoices ::= SET OF RevocationInfoChoice
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationInfoChoices(Vec<RevocationInfoChoice>);

impl RevocationInfoChoices {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        Err(cons.content_err("RevocationInfoChoices parsing not implemented"))
    }
}

/// Revocation info choice.
///
/// ```ASN.1
/// RevocationInfoChoice ::= CHOICE {
///   crl CertificateList,
///   other [1] IMPLICIT OtherRevocationInfoFormat }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationInfoChoice {
    Crl(Box<CertificateList>),
    Other(OtherRevocationInfoFormat),
}

/// Other revocation info format.
///
/// ```ASN.1
/// OtherRevocationInfoFormat ::= SEQUENCE {
///   otherRevInfoFormat OBJECT IDENTIFIER,
///   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtherRevocationInfoFormat {
    pub other_rev_info_info_format: Oid,
    // TODO Any
    pub other_rev_info: Option<()>,
}

/// Certificate choices.
///
/// ```ASN.1
/// CertificateChoices ::= CHOICE {
///   certificate Certificate,
///   extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
///   v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
///   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
///   other [3] IMPLICIT OtherCertificateFormat }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateChoices {
    Certificate(Box<Certificate>),
    // ExtendedCertificate(ExtendedCertificate),
    // AttributeCertificateV1(AttributeCertificateV1),
    AttributeCertificateV2(Box<AttributeCertificateV2>),
    Other(Box<OtherCertificateFormat>),
}

impl CertificateChoices {
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_constructed_if(Tag::CTX_0, |cons| -> Result<(), DecodeError<S::Error>> {
            Err(cons.content_err("ExtendedCertificate parsing not implemented"))
        })?;
        cons.take_opt_constructed_if(Tag::CTX_1, |cons| -> Result<(), DecodeError<S::Error>> {
            Err(cons.content_err("AttributeCertificateV1 parsing not implemented"))
        })?;

        // TODO these first 2 need methods that parse an already entered SEQUENCE.
        match cons
            .take_opt_constructed_if(Tag::CTX_2, |cons| AttributeCertificateV2::take_from(cons))?
        { Some(certificate) => {
            Ok(Some(Self::AttributeCertificateV2(Box::new(certificate))))
        } _ => { match cons
            .take_opt_constructed_if(Tag::CTX_3, |cons| OtherCertificateFormat::take_from(cons))?
        { Some(certificate) => {
            Ok(Some(Self::Other(Box::new(certificate))))
        } _ => { match cons.take_opt_constructed(|_, cons| Certificate::from_sequence(cons))?
        { Some(certificate) => {
            Ok(Some(Self::Certificate(Box::new(certificate))))
        } _ => {
            Ok(None)
        }}}}}}
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        match self {
            Self::Certificate(cert) => (Some(cert.encode_ref()), None),
            Self::AttributeCertificateV2(_) | Self::Other(_) => (
                None,
                Some(crate::UnsupportedEncoder(
                    "encoding this CertificateChoices variant is not implemented",
                )),
            ),
        }
    }
}

impl Values for CertificateChoices {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

/// Other certificate format.
///
/// ```ASN.1
/// OtherCertificateFormat ::= SEQUENCE {
///   otherCertFormat OBJECT IDENTIFIER,
///   otherCert ANY DEFINED BY otherCertFormat }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtherCertificateFormat {
    pub other_cert_format: Oid,
    // TODO Any
    pub other_cert: Option<()>,
}

impl OtherCertificateFormat {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        Err(cons.content_err("OtherCertificateFormat parsing not implemented"))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CertificateSet(Vec<CertificateChoices>);

impl Deref for CertificateSet {
    type Target = Vec<CertificateChoices>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CertificateSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl CertificateSet {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        let mut certs = Vec::new();

        while let Some(cert) = CertificateChoices::take_opt_from(cons)? {
            certs.push(cert);
        }

        Ok(Self(certs))
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::set_as(tag, &self.0)
    }
}

/// Issuer and serial number.
///
/// ```ASN.1
/// IssuerAndSerialNumber ::= SEQUENCE {
///   issuer Name,
///   serialNumber CertificateSerialNumber }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerAndSerialNumber {
    pub issuer: Name,
    pub serial_number: CertificateSerialNumber,
}

impl IssuerAndSerialNumber {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let issuer = Name::take_from(cons)?;
            let serial_number = Integer::take_from(cons)?;

            Ok(Self {
                issuer,
                serial_number,
            })
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((self.issuer.encode_ref(), (&self.serial_number).encode()))
    }
}

pub type CertificateSerialNumber = Integer;

/// Version number.
///
/// ```ASN.1
/// CMSVersion ::= INTEGER
///                { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CmsVersion {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
}

impl CmsVersion {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        match cons.take_primitive_if(Tag::INTEGER, Integer::i8_from_primitive)? {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            5 => Ok(Self::V5),
            _ => Err(cons.content_err("unexpected CMSVersion")),
        }
    }

    pub fn encode(self) -> impl Values {
        u8::from(self).encode()
    }
}

impl From<CmsVersion> for u8 {
    fn from(v: CmsVersion) -> u8 {
        match v {
            CmsVersion::V0 => 0,
            CmsVersion::V1 => 1,
            CmsVersion::V2 => 2,
            CmsVersion::V3 => 3,
            CmsVersion::V4 => 4,
            CmsVersion::V5 => 5,
        }
    }
}

pub type UserKeyingMaterial = OctetString;

/// Other key attribute.
///
/// ```ASN.1
/// OtherKeyAttribute ::= SEQUENCE {
///   keyAttrId OBJECT IDENTIFIER,
///   keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtherKeyAttribute {
    pub key_attribute_id: Oid,
    // TODO Any
    pub key_attribute: Option<()>,
}

pub type ContentType = Oid;

pub type MessageDigest = OctetString;

pub type SigningTime = Time;

/// Time variant.
///
/// ```ASN.1
/// Time ::= CHOICE {
///   utcTime UTCTime,
///   generalizedTime GeneralizedTime }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Time {
    UtcTime(UtcTime),
    GeneralizedTime(GeneralizedTime),
}

impl Time {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        if let Some(utc) =
            cons.take_opt_primitive_if(Tag::UTC_TIME, |prim| UtcTime::from_primitive(prim))?
        {
            Ok(Self::UtcTime(utc))
        } else if let Some(generalized) = cons
            .take_opt_primitive_if(Tag::GENERALIZED_TIME, |prim| {
                GeneralizedTime::from_primitive_no_fractional_or_timezone_offsets(prim)
            })?
        {
            Ok(Self::GeneralizedTime(generalized))
        } else {
            Err(cons.content_err("invalid Time value"))
        }
    }
}

impl From<Time> for jiff::Timestamp {
    fn from(t: Time) -> Self {
        match t {
            Time::UtcTime(utc) => *utc,
            Time::GeneralizedTime(gt) => gt.into(),
        }
    }
}

pub type CounterSignature = SignerInfo;

pub type AttributeCertificateV2 = AttributeCertificate;

#[cfg(test)]
mod tests {
    use {
        super::*,
        bytes::Bytes,
        x509_certificate::{DigestAlgorithm, SignatureAlgorithm, rfc5652::AttributeValue},
    };

    const CONTENT_INFO: &[u8] = &[
        0x30, 0x0b, 0x06, 0x03, 0x2a, 0x03, 0x04, 0xa0, 0x04, 0x04, 0x02, 0x01, 0x02,
    ];

    #[test]
    fn content_info_preserves_explicit_content_tag() {
        // Parse in BER mode to exercise safe conversion of captured content to DER.
        let parsed = Constructed::decode(CONTENT_INFO, Mode::Ber, |cons| {
            cons.take_sequence(ContentInfo::from_sequence)
        })
        .unwrap();

        let mut encoded = Vec::new();
        parsed.write_encoded(Mode::Der, &mut encoded).unwrap();
        assert_eq!(encoded, CONTENT_INFO);
    }

    #[test]
    fn content_info_rejects_multiple_explicit_values() {
        let malformed = [
            0x30, 0x0d, 0x06, 0x03, 0x2a, 0x03, 0x04, 0xa0, 0x06, 0x04, 0x02, 0x01, 0x02,
            0x05, 0x00,
        ];
        assert!(Constructed::decode(malformed.as_slice(), Mode::Der, |cons| {
            cons.take_sequence(ContentInfo::from_sequence)
        })
        .is_err());
    }

    #[test]
    fn signer_info_rejects_noncanonical_signed_attribute_sets() {
        let value = |number: u8| {
            AttributeValue::new(Captured::from_values(Mode::Der, number.encode()))
        };
        let signer_info = SignerInfo {
            version: CmsVersion::V3,
            sid: SignerIdentifier::SubjectKeyIdentifier(OctetString::new(Bytes::from_static(
                b"key-id",
            ))),
            digest_algorithm: DigestAlgorithm::Sha256.into(),
            signed_attributes: Some(SignedAttributes(vec![
                Attribute {
                    typ: Oid(Bytes::from_static(&[42, 4])),
                    values: vec![value(4), value(3)],
                },
                Attribute {
                    typ: Oid(Bytes::from_static(&[42, 3])),
                    values: vec![value(2), value(1)],
                },
            ])),
            signature_algorithm: SignatureAlgorithm::Ed25519.into(),
            signature: OctetString::new(Bytes::new()),
            unsigned_attributes: None,
            signed_attributes_data: None,
        };
        let mut encoded = Vec::new();
        signer_info
            .write_encoded(Mode::Der, &mut encoded)
            .unwrap();

        assert!(Constructed::decode(encoded.as_slice(), Mode::Der, |cons| {
            cons.take_sequence(SignerInfo::from_sequence)
        })
        .is_err());
    }
}
