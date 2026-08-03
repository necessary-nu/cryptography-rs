// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*! ASN.1 types defined RFC 5280. */

use {
    crate::{asn1time::*, rfc3280::*},
    bcder::{
        decode::{BytesSource, Constructed, DecodeError, IntoSource, Source},
        encode,
        encode::{PrimitiveContent, Values},
        BitString, Captured, ConstOid, Integer, Mode, OctetString, Oid, Tag,
    },
    bytes::Bytes,
    std::{
        fmt::{Debug, Formatter},
        io::Write,
        ops::{Deref, DerefMut},
    },
};

/// Subject Alternative Name X.509 extension.
///
/// 2.5.29.17
const OID_EXTENSION_SUBJECT_ALT_NAME: ConstOid = Oid(&[85, 29, 17]);

/// Algorithm identifier.
///
/// ```ASN.1
/// AlgorithmIdentifier  ::=  SEQUENCE  {
///   algorithm               OBJECT IDENTIFIER,
///   parameters              ANY DEFINED BY algorithm OPTIONAL  }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct AlgorithmIdentifier {
    pub algorithm: Oid,
    pub parameters: Option<AlgorithmParameter>,
}

impl Debug for AlgorithmIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("AlgorithmIdentifier");
        s.field("algorithm", &format_args!("{}", self.algorithm));
        s.field("parameters", &self.parameters);
        s.finish()
    }
}

impl AlgorithmIdentifier {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| Self::take_sequence(cons))
    }

    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| Self::take_sequence(cons))
    }

    fn take_sequence<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        let algorithm = Oid::take_from(cons)?;
        let parameters = cons.capture(|cons| {
            cons.skip_opt(|_, _, _| Ok(()))?;
            Ok(())
        })?;

        let parameters = if parameters.is_empty() {
            None
        } else {
            Some(AlgorithmParameter(parameters))
        };

        Ok(Self {
            algorithm,
            parameters,
        })
    }

    fn encoded_values(&self, _mode: Mode) -> impl Values + '_ {
        encode::sequence((self.algorithm.clone().encode(), self.parameters.as_ref()))
    }
}

impl Values for AlgorithmIdentifier {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encoded_values(mode).encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encoded_values(mode).write_encoded(mode, target)
    }
}

/// A parameter for an algorithm.
///
/// This type doesn't exist in the ASN.1. We've implemented it to
/// make (de)serialization simpler.
#[derive(Clone, Debug)]
pub struct AlgorithmParameter(Captured);

impl AlgorithmParameter {
    pub fn from_captured(captured: Captured) -> Self {
        Self(captured)
    }

    /// Construct a new instance consisting of a single OID.
    pub fn from_oid(oid: Oid) -> Self {
        let captured = Captured::from_values(Mode::Der, oid.encode());

        Self(captured)
    }

    /// Construct a new instance containing ASN.1 `NULL`.
    pub fn null() -> Self {
        Self(Captured::from_values(
            Mode::Der,
            ().encode_as(Tag::NULL),
        ))
    }

    /// Whether this parameter is exactly an ASN.1 `NULL` value.
    pub fn is_null(&self) -> bool {
        self.0.as_slice() == [0x05, 0x00]
    }

    /// Attempt to decode a single OID from the captured value.
    pub fn decode_oid(&self) -> Result<Oid, DecodeError<<BytesSource as Source>::Error>> {
        let source = BytesSource::new(Bytes::copy_from_slice(self.0.as_slice()));

        Constructed::decode(source, Mode::Der, Oid::take_from)
    }
}

impl Deref for AlgorithmParameter {
    type Target = Captured;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AlgorithmParameter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialEq for AlgorithmParameter {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for AlgorithmParameter {}

impl Values for AlgorithmParameter {
    fn encoded_len(&self, mode: Mode) -> usize {
        crate::CapturedValues(&self.0).encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        crate::CapturedValues(&self.0).write_encoded(mode, target)
    }
}

/// An X.509 certificate.
///
/// This is the main data structure representing an X.509 certificate.
///
/// ```ASN.1
/// Certificate  ::=  SEQUENCE  {
///   tbsCertificate       TBSCertificate,
///   signatureAlgorithm   AlgorithmIdentifier,
///   signature            BIT STRING  }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct Certificate {
    pub tbs_certificate: TbsCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: BitString,
}

impl Debug for Certificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Certificate");
        s.field("tbs_certificate", &self.tbs_certificate);
        s.field("signature_algorithm", &self.signature_algorithm);
        s.field(
            "signature",
            &format_args!(
                "{} (unused {})",
                hex::encode(self.signature.octet_bytes()),
                self.signature.unused()
            ),
        );
        s.finish()
    }
}

impl Certificate {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| Self::from_sequence(cons))
    }

    pub fn from_sequence<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let tbs_certificate = TbsCertificate::take_from(cons)?;
        let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;
        let signature = BitString::take_from(cons)?;

        Ok(Self {
            tbs_certificate,
            signature_algorithm,
            signature,
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.tbs_certificate.encode_ref(),
            &self.signature_algorithm,
            self.signature.encode_ref(),
        ))
    }

    /// Iterate over extensions defined on this certificate.
    pub fn iter_extensions(&self) -> impl Iterator<Item = &Extension> {
        self.tbs_certificate
            .extensions
            .iter()
            .flat_map(|x| x.iter())
    }
}

/// TBS Certificate.
///
/// This holds most of the metadata within an X.509 certificate.
///
/// ```ASN.1
/// TBSCertificate  ::=  SEQUENCE  {
///      version         [0]  Version DEFAULT v1,
///      serialNumber         CertificateSerialNumber,
///      signature            AlgorithmIdentifier,
///      issuer               Name,
///      validity             Validity,
///      subject              Name,
///      subjectPublicKeyInfo SubjectPublicKeyInfo,
///      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                           -- If present, version MUST be v2 or v3
///      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                           -- If present, version MUST be v2 or v3
///      extensions      [3]  Extensions OPTIONAL
///                           -- If present, version MUST be v3 --  }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct TbsCertificate {
    pub version: Option<Version>,
    pub serial_number: CertificateSerialNumber,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub issuer_unique_id: Option<UniqueIdentifier>,
    pub subject_unique_id: Option<UniqueIdentifier>,
    pub extensions: Option<Extensions>,

    /// Raw bytes this instance was constructed from.
    ///
    /// This is what signature verification should be performed against.
    pub raw_data: Option<Vec<u8>>,
}

impl Debug for TbsCertificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("TbsCertificate");
        s.field("version", &self.version);
        s.field("serial_number", &self.serial_number);
        s.field("signature", &self.signature);
        s.field("issuer", &self.issuer);
        s.field("validity", &self.validity);
        s.field("subject", &self.subject);
        s.field("subject_public_key_info", &self.subject_public_key_info);
        s.field("issuer_unique_id", &self.issuer_unique_id);
        s.field("subject_unique_id", &self.subject_unique_id);
        s.field("extensions", &self.extensions);
        s.field(
            "raw_data",
            &format_args!("{:?}", self.raw_data.as_ref().map(hex::encode)),
        );
        s.finish()
    }
}

impl TbsCertificate {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        // The TbsCertificate data is what's signed by the issuing certificate. To
        // facilitate signature verification, we stash away the raw data so they
        // can be accessed later.
        let mut res = None;

        let captured = cons.capture(|cons| {
            cons.take_sequence(|cons| {
                let version = cons.take_opt_constructed_if(Tag::CTX_0, Version::take_from)?;
                let serial_number = CertificateSerialNumber::take_from(cons)?;
                let signature = AlgorithmIdentifier::take_from(cons)?;
                let issuer = Name::take_from(cons)?;
                if issuer.iter_attributes().next().is_none() {
                    return Err(cons.content_err("certificate issuer must not be empty"));
                }
                let validity = Validity::take_from(cons)?;
                let not_before: chrono::DateTime<chrono::Utc> =
                    validity.not_before.clone().into();
                let not_after: chrono::DateTime<chrono::Utc> = validity.not_after.clone().into();
                if not_after < not_before {
                    return Err(cons.content_err("certificate validity range is reversed"));
                }
                let subject = Name::take_from(cons)?;
                let subject_public_key_info = SubjectPublicKeyInfo::take_from(cons)?;
                if subject_public_key_info.subject_public_key.unused() != 0 {
                    return Err(cons.content_err("subject public key has unused bits"));
                }
                let issuer_unique_id =
                    cons.take_opt_value_if(Tag::CTX_1, UniqueIdentifier::from_content)?;
                let subject_unique_id =
                    cons.take_opt_value_if(Tag::CTX_2, UniqueIdentifier::from_content)?;
                let extensions =
                    cons.take_opt_constructed_if(Tag::CTX_3, Extensions::take_from)?;

                let effective_version = version.unwrap_or(Version::V1);
                if effective_version == Version::V1
                    && (issuer_unique_id.is_some() || subject_unique_id.is_some())
                {
                    return Err(cons.content_err("unique identifiers require version v2 or v3"));
                }
                if extensions.is_some() && effective_version != Version::V3 {
                    return Err(cons.content_err("certificate extensions require version v3"));
                }
                if subject.iter_attributes().next().is_none() {
                    let subject_alt_name = extensions
                        .as_ref()
                        .and_then(|extensions| {
                            extensions
                                .iter()
                                .find(|extension| extension.id == OID_EXTENSION_SUBJECT_ALT_NAME)
                        })
                        .filter(|extension| extension.critical == Some(true))
                        .ok_or_else(|| {
                            cons.content_err(
                                "an empty subject requires a critical subjectAltName extension",
                            )
                        })?;
                    let has_name = Constructed::decode(
                        subject_alt_name.value.to_bytes(),
                        Mode::Der,
                        |cons| {
                            cons.take_sequence(|cons| {
                                let mut has_name = false;
                                while GeneralName::take_opt_from(cons)?.is_some() {
                                    has_name = true;
                                }
                                Ok(has_name)
                            })
                        },
                    )
                    .map_err(|error| cons.content_err(error.to_string()))?;
                    if !has_name {
                        return Err(cons.content_err("subjectAltName must not be empty"));
                    }
                }

                res = Some(Self {
                    version,
                    serial_number,
                    signature,
                    issuer,
                    validity,
                    subject,
                    subject_public_key_info,
                    issuer_unique_id,
                    subject_unique_id,
                    extensions,
                    raw_data: None,
                });

                Ok(())
            })
        })?;

        let mut res = res.ok_or_else(|| cons.content_err("TBSCertificate was not decoded"))?;
        res.raw_data = Some(captured.to_vec());

        Ok(res)
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.version
                .filter(|version| *version != Version::V1)
                .map(|version| {
                    encode::Constructed::new(Tag::CTX_0, u8::from(version).encode())
                }),
            (&self.serial_number).encode(),
            &self.signature,
            self.issuer.encode_ref(),
            self.validity.encode_ref(),
            self.subject.encode_ref(),
            self.subject_public_key_info.encode_ref(),
            self.issuer_unique_id
                .as_ref()
                .map(|id| id.encode_ref_as(Tag::CTX_1)),
            self.subject_unique_id
                .as_ref()
                .map(|id| id.encode_ref_as(Tag::CTX_2)),
            self.extensions
                .as_ref()
                .map(|extensions| encode::Constructed::new(Tag::CTX_3, extensions.encode_ref())),
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    V1 = 0,
    V2 = 1,
    V3 = 2,
}

impl Version {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        match cons.take_primitive_if(Tag::INTEGER, Integer::i8_from_primitive)? {
            0 => Ok(Self::V1),
            1 => Ok(Self::V2),
            2 => Ok(Self::V3),
            _ => Err(cons.content_err("unexpected Version value")),
        }
    }

    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        match cons.take_opt_primitive_if(Tag::INTEGER, Integer::i8_from_primitive)? {
            None => Ok(None),
            Some(0) => Ok(Some(Self::V1)),
            Some(1) => Ok(Some(Self::V2)),
            Some(2) => Ok(Some(Self::V3)),
            _ => Err(cons.content_err("unexpected Version value")),
        }
    }

    pub fn encode(self) -> impl Values {
        u8::from(self).encode()
    }
}

impl From<Version> for u8 {
    fn from(v: Version) -> Self {
        match v {
            Version::V1 => 0,
            Version::V2 => 1,
            Version::V3 => 2,
        }
    }
}

pub type CertificateSerialNumber = Integer;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Validity {
    pub not_before: Time,
    pub not_after: Time,
}

impl Validity {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let not_before = Time::take_from(cons)?;
            let not_after = Time::take_from(cons)?;

            Ok(Self {
                not_before,
                not_after,
            })
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((self.not_before.encode_ref(), self.not_after.encode_ref()))
    }
}

pub type UniqueIdentifier = BitString;

/// Subject public key info.
///
/// ```ASN.1
/// SubjectPublicKeyInfo  ::=  SEQUENCE  {
///   algorithm            AlgorithmIdentifier,
///   subjectPublicKey     BIT STRING  }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitString,
}

impl Debug for SubjectPublicKeyInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SubjectPublicKeyInfo");
        s.field("algorithm", &self.algorithm);
        s.field(
            "subject_public_key",
            &format_args!(
                "{} (unused {})",
                hex::encode(self.subject_public_key.octet_bytes().as_ref()),
                self.subject_public_key.unused()
            ),
        );
        s.finish()
    }
}

impl SubjectPublicKeyInfo {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let algorithm = AlgorithmIdentifier::take_from(cons)?;
            let subject_public_key = BitString::take_from(cons)?;

            Ok(Self {
                algorithm,
                subject_public_key,
            })
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((&self.algorithm, self.subject_public_key.encode_ref()))
    }
}

/// Extensions
///
/// ```ASN.1
/// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Extensions(Vec<Extension>);

impl Extensions {
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| Self::from_sequence(cons))
    }

    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| Self::from_sequence(cons))
    }

    pub fn from_sequence<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let mut extensions = Vec::new();

        while let Some(extension) = Extension::take_opt_from(cons)? {
            if extensions
                .iter()
                .any(|candidate: &Extension| candidate.id == extension.id)
            {
                return Err(cons.content_err("duplicate certificate extension"));
            }
            extensions.push(extension);
        }

        if extensions.is_empty() {
            return Err(cons.content_err("Extensions must contain at least one value"));
        }

        Ok(Self(extensions))
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence(&self.0)
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::sequence_as(tag, &self.0)
    }
}

impl Deref for Extensions {
    type Target = Vec<Extension>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Extensions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Extension.
///
/// ```ASN.1
/// Extension  ::=  SEQUENCE  {
///      extnID      OBJECT IDENTIFIER,
///      critical    BOOLEAN DEFAULT FALSE,
///      extnValue   OCTET STRING
///                  -- contains the DER encoding of an ASN.1 value
///                  -- corresponding to the extension type identified
///                  -- by extnID
///      }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct Extension {
    pub id: Oid,
    pub critical: Option<bool>,
    pub value: OctetString,
}

impl Debug for Extension {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Extension");
        s.field("id", &format_args!("{}", self.id));
        s.field("critical", &self.critical);
        s.field(
            "value",
            &format_args!("{}", hex::encode(self.value.clone().into_bytes().as_ref())),
        );
        s.finish()
    }
}

impl Extension {
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| Self::from_sequence(cons))
    }

    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| Self::from_sequence(cons))
    }

    fn from_sequence<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        let id = Oid::take_from(cons)?;
        let critical = cons.take_opt_bool()?;
        let value = OctetString::take_from(cons)?;

        Ok(Self {
            id,
            critical,
            value,
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.id.encode_ref(),
            if self.critical == Some(true) {
                Some(true.encode())
            } else {
                None
            },
            self.value.encode_ref(),
        ))
    }

    /// Attempt to decode a single OID present in an outer sequence.
    ///
    /// If this works, we return Some. Else None.
    pub fn try_decode_sequence_single_oid(&self) -> Option<Oid> {
        Constructed::decode(self.value.clone().into_source(), Mode::Der, |cons| {
            cons.take_sequence(Oid::take_from)
        })
        .ok()
    }
}

impl Values for Extension {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

/// Certificate list.
///
/// ```ASN.1
/// CertificateList  ::=  SEQUENCE  {
///      tbsCertList          TBSCertList,
///      signatureAlgorithm   AlgorithmIdentifier,
///      signature            BIT STRING  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateList {
    pub tbs_cert_list: TbsCertList,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: BitString,
}

impl CertificateList {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| Self::from_sequence(cons))
    }

    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| Self::from_sequence(cons))
    }

    pub fn from_sequence<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let tbs_cert_list = TbsCertList::take_from(cons)?;
        let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;
        let signature = BitString::take_from(cons)?;

        Ok(Self {
            tbs_cert_list,
            signature_algorithm,
            signature,
        })
    }
}

/// Tbs Certificate list.
///
/// ```ASN.1
/// TBSCertList  ::=  SEQUENCE  {
///   version                 Version OPTIONAL,
///     -- if present, MUST be v2
///   signature               AlgorithmIdentifier,
///   issuer                  Name,
///   thisUpdate              Time,
///   nextUpdate              Time OPTIONAL,
///   revokedCertificates     SEQUENCE OF SEQUENCE  {
///     userCertificate         CertificateSerialNumber,
///     revocationDate          Time,
///     crlEntryExtensions      Extensions OPTIONAL
///                                 -- if present, MUST be v2
///  }  OPTIONAL,
///  crlExtensions           [0] Extensions OPTIONAL }
///                                -- if present, MUST be v2
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TbsCertList {
    pub version: Option<Version>,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name,
    pub this_update: Time,
    pub next_update: Option<Time>,
    pub revoked_certificates: Vec<(CertificateSerialNumber, Time, Option<Extensions>)>,
    pub crl_extensions: Option<Extensions>,
}

impl TbsCertList {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let version = Version::take_opt_from(cons)?;
            if version.is_some_and(|version| version != Version::V2) {
                return Err(cons.content_err("CRL version, when present, must be v2"));
            }

            let signature = AlgorithmIdentifier::take_from(cons)?;
            let issuer = Name::take_from(cons)?;
            let this_update = Time::take_from(cons)?;
            let next_update = Time::take_opt_from(cons)?;
            let revoked_certificates = cons
                .take_opt_sequence(|cons| {
                    let mut revoked = Vec::new();

                    while let Some(entry) = cons.take_opt_sequence(|cons| {
                        let serial_number = CertificateSerialNumber::take_from(cons)?;
                        let revocation_date = Time::take_from(cons)?;
                        let extensions = Extensions::take_opt_from(cons)?;

                        Ok((serial_number, revocation_date, extensions))
                    })? {
                        revoked.push(entry);
                    }

                    Ok(revoked)
                })?
                .unwrap_or_default();
            let crl_extensions = cons
                .take_opt_constructed_if(Tag::CTX_0, |cons| Extensions::take_from(cons))?;

            if version != Some(Version::V2)
                && (crl_extensions.is_some()
                    || revoked_certificates
                        .iter()
                        .any(|(_, _, extensions)| extensions.is_some()))
            {
                return Err(cons.content_err("CRL extensions require version v2"));
            }

            Ok(Self {
                version,
                signature,
                issuer,
                this_update,
                next_update,
                revoked_certificates,
                crl_extensions,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_version_can_be_absent() {
        assert_eq!(
            Constructed::decode(&[][..], Mode::Der, Version::take_opt_from).unwrap(),
            None
        );
    }

    #[test]
    fn algorithm_identifier_rejects_multiple_parameter_values() {
        let der = [
            0x30, 0x08, 0x06, 0x02, 0x2a, 0x03, 0x05, 0x00, 0x05, 0x00,
        ];
        assert!(Constructed::decode(
            der.as_slice(),
            Mode::Der,
            AlgorithmIdentifier::take_from,
        )
        .is_err());
    }
}
