// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*! Functionality for signing data. */

use {
    crate::{
        asn1::{
            rfc5652::{
                CertificateChoices, CertificateSet, CmsVersion, DigestAlgorithmIdentifier,
                DigestAlgorithmIdentifiers, EncapsulatedContentInfo, IssuerAndSerialNumber,
                SignatureValue, SignedAttributes, SignedData, SignerIdentifier, SignerInfo,
                SignerInfos, OID_CONTENT_TYPE, OID_ID_DATA, OID_MESSAGE_DIGEST, OID_SIGNING_TIME,
            },
        },
        validate_signature_digest_algorithms, CmsError,
    },
    bcder::{
        encode::{PrimitiveContent, Values},
        Captured, Mode, OctetString, Oid,
    },
    bytes::Bytes,
    std::collections::HashSet,
    x509_certificate::{
        asn1time::UtcTime,
        rfc5652::{Attribute, AttributeValue},
        CapturedX509Certificate, DigestAlgorithm, KeyInfoSigner, SignatureAlgorithm,
    },
};

#[cfg(feature = "http")]
use {
    crate::{
        asn1::{rfc3161::OID_TIME_STAMP_TOKEN, rfc5652::UnsignedAttributes},
        time_stamp_protocol::{time_stamp_message_http, TimeStampError},
    },
    reqwest::IntoUrl,
};

/// Builder type to construct an entity that will sign some data.
///
/// Instances will be attached to `SignedDataBuilder` instances where they
/// will sign data using configured settings.
#[derive(Clone)]
pub struct SignerBuilder<'a> {
    /// The cryptographic key pair used for signing content.
    signing_key: &'a dyn KeyInfoSigner,

    /// Signer identifier - either explicitly provided, or
    /// initialized from signing_certificate
    signer_identifier: SignerIdentifier,

    /// X.509 certificate used for signing.
    signing_certificate: Option<CapturedX509Certificate>,

    /// Content digest algorithm to use.
    digest_algorithm: DigestAlgorithm,

    /// Explicit content to use for calculating the `message-id`
    /// attribute.
    message_id_content: Option<Vec<u8>>,

    /// Whether `message_id_content` may differ from the encapsulated content.
    ///
    /// Set only via [`SignerBuilder::detached_message_digest`]; see that method
    /// for why a protocol might require it.
    allow_detached_message_digest: bool,

    /// The content type of the value being signed.
    ///
    /// This is a mandatory field for signed attributes. The default value
    /// is `id-data`.
    content_type: Oid,

    /// Extra attributes to include in the SignedAttributes set.
    extra_signed_attributes: Vec<Attribute>,

    #[cfg(feature = "http")]
    /// Time-Stamp Protocol (TSP) server HTTP URL to use.
    time_stamp_url: Option<reqwest::Url>,
}

impl<'a> SignerBuilder<'a> {
    fn default_digest_algorithm(signing_key: &dyn KeyInfoSigner) -> DigestAlgorithm {
        match signing_key.signature_algorithm() {
            Ok(SignatureAlgorithm::Ed25519) => DigestAlgorithm::Sha512,
            Ok(algorithm) => algorithm.digest_algorithm().unwrap_or(DigestAlgorithm::Sha256),
            Err(_) => DigestAlgorithm::Sha256,
        }
    }

    /// Construct a new entity that will sign content.
    ///
    /// An entity is constructed from a signing key, which is mandatory.
    pub fn new(
        signing_key: &'a dyn KeyInfoSigner,
        signing_certificate: CapturedX509Certificate,
    ) -> Self {
        Self {
            signing_key,
            signer_identifier: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: signing_certificate.issuer_name().clone(),
                serial_number: signing_certificate.serial_number_asn1().clone(),
            }),
            signing_certificate: Some(signing_certificate),
            digest_algorithm: Self::default_digest_algorithm(signing_key),
            message_id_content: None,
            allow_detached_message_digest: false,
            content_type: Oid(Bytes::copy_from_slice(OID_ID_DATA.as_ref())),
            extra_signed_attributes: Vec::new(),
            #[cfg(feature = "http")]
            time_stamp_url: None,
        }
    }

    /// Construct a new entity that will sign content.
    ///
    /// An entity is constructed from a signing key and signer identifier, which are
    /// mandatory.
    pub fn new_with_signer_identifier(
        signing_key: &'a dyn KeyInfoSigner,
        signer_identifier: SignerIdentifier,
    ) -> Self {
        Self {
            signing_key,
            signer_identifier,
            signing_certificate: None,
            digest_algorithm: Self::default_digest_algorithm(signing_key),
            message_id_content: None,
            allow_detached_message_digest: false,
            content_type: Oid(Bytes::copy_from_slice(OID_ID_DATA.as_ref())),
            extra_signed_attributes: Vec::new(),
            #[cfg(feature = "http")]
            time_stamp_url: None,
        }
    }

    /// Obtain the signature algorithm used by the signing key.
    pub fn signature_algorithm(&self) -> Result<SignatureAlgorithm, CmsError> {
        Ok(self.signing_key.signature_algorithm()?)
    }

    /// Define the digest algorithm used for CMS signed attributes.
    ///
    /// The selected digest must be compatible with the signature algorithm.
    /// In particular, Ed25519 requires SHA-512 and ECDSA requires the digest
    /// named by its signature algorithm.
    #[must_use]
    pub fn digest_algorithm(mut self, algorithm: DigestAlgorithm) -> Self {
        self.digest_algorithm = algorithm;
        self
    }

    /// Define the content to use to calculate the `message-id` attribute.
    ///
    /// In most cases, this is never called and the encapsulated content
    /// embedded within the generated message is used. However, some users
    /// omit storing the data inline and instead use a `message-id` digest
    /// calculated from a different source. This defines that different source.
    #[must_use]
    pub fn message_id_content(mut self, data: Vec<u8>) -> Self {
        self.message_id_content = Some(data);
        self
    }

    /// Define digested content that intentionally differs from the encapsulated
    /// content.
    ///
    /// [`Self::message_id_content`] requires the value it is given to match the
    /// content configured on the [`SignedDataBuilder`], because a mismatch is
    /// almost always a bug: the `message-digest` attribute would not describe the
    /// message. This method is the deliberate exception.
    ///
    /// A few protocols digest something other than the encapsulated content
    /// verbatim. Authenticode is the motivating case: its `eContent` is an
    /// `SpcIndirectDataContent` SEQUENCE, but the `message-digest` attribute
    /// covers only that SEQUENCE's *content octets* — the value with its own tag
    /// and length removed. Expressing that requires digesting different bytes
    /// from the ones stored.
    ///
    /// Prefer [`Self::message_id_content`]. Reach for this only when a
    /// specification mandates the difference, since nothing downstream can then
    /// verify the digest against the stored content for you.
    #[must_use]
    pub fn detached_message_digest(mut self, data: Vec<u8>) -> Self {
        self.message_id_content = Some(data);
        self.allow_detached_message_digest = true;
        self
    }

    /// Define the content type of the signed content.
    #[must_use]
    pub fn content_type(mut self, oid: Oid) -> Self {
        self.content_type = oid;
        self
    }

    /// Add an additional attribute to sign.
    #[must_use]
    pub fn signed_attribute(mut self, typ: Oid, values: Vec<AttributeValue>) -> Self {
        self.extra_signed_attributes.push(Attribute { typ, values });
        self
    }

    /// Add an additional OctetString signed attribute.
    ///
    /// This is a helper for converting a byte slice to an OctetString and AttributeValue
    /// without having to go through low-level ASN.1 code.
    #[must_use]
    pub fn signed_attribute_octet_string(self, typ: Oid, data: &[u8]) -> Self {
        self.signed_attribute(
            typ,
            vec![AttributeValue::new(Captured::from_values(
                Mode::Der,
                data.encode_ref(),
            ))],
        )
    }

    /// Obtain a time-stamp token from a server.
    ///
    /// If this is called, the URL must be a server implementing the Time-Stamp Protocol
    /// (TSP) as defined by RFC 3161. At signature generation time, the server will be
    /// contacted and the time stamp token response will be added as an unsigned attribute
    /// on the [SignedData] instance.
    #[cfg(feature = "http")]
    pub fn time_stamp_url(mut self, url: impl IntoUrl) -> Result<Self, CmsError> {
        self.time_stamp_url = Some(url.into_url().map_err(TimeStampError::from)?);
        Ok(self)
    }
}

/// Encapsulated content to sign.
enum SignedContent {
    /// No content is being signed.
    None,

    /// Signed content to be embedded in the signature.
    Inline(Vec<u8>),

    /// Signed content whose digest is to be captured but won't be included in the signature.
    ///
    /// Internal value is the raw content, not the digest.
    External(Vec<u8>),
}

fn sort_der<T>(values: impl IntoIterator<Item = T>) -> Result<Vec<T>, std::io::Error>
where
    T: Values,
{
    let mut encoded = values
        .into_iter()
        .map(|value| {
            let mut der = Vec::new();
            value.write_encoded(Mode::Der, &mut der)?;
            Ok((der, value))
        })
        .collect::<Result<Vec<_>, std::io::Error>>()?;

    encoded.sort_by(|(left, _), (right, _)| left.cmp(right));

    Ok(encoded.into_iter().map(|(_, value)| value).collect())
}

/// Entity for incrementally deriving a SignedData primitive.
///
/// Use this type for generating an RFC 5652 payload for signed data.
///
/// By default, the encapsulated content to sign is empty. Call [Self::content_inline()]
/// or [Self::content_external()] to define encapsulated content.
pub struct SignedDataBuilder<'a> {
    /// Encapsulated content to sign.
    signed_content: SignedContent,

    /// Entities who will generated signatures.
    signers: Vec<SignerBuilder<'a>>,

    /// X.509 certificates to add to the payload.
    certificates: Vec<CapturedX509Certificate>,

    /// The OID to use for `EncapsulatedContentInfo.eContentType`.
    content_type: Oid,

    /// The signing time to include in signatures.
    ///
    /// All signatures will use the same time.
    signing_time: UtcTime,
}

impl Default for SignedDataBuilder<'_> {
    fn default() -> Self {
        Self {
            signed_content: SignedContent::None,
            signers: vec![],
            certificates: vec![],
            content_type: Oid(OID_ID_DATA.as_ref().into()),
            signing_time: UtcTime::now(),
        }
    }
}

impl<'a> SignedDataBuilder<'a> {
    /// Define encapsulated content that will be stored inline in the produced signature.
    #[must_use]
    pub fn content_inline(mut self, content: Vec<u8>) -> Self {
        self.signed_content = SignedContent::Inline(content);
        self
    }

    /// Define encapsulated content that won't be present in the produced signature.
    ///
    /// The content will be digested and that digest conveyed in the built signature.
    /// But the content itself won't be present in the signature. RFC 5652 refers to
    /// this as an _external signature_.
    #[must_use]
    pub fn content_external(mut self, content: Vec<u8>) -> Self {
        self.signed_content = SignedContent::External(content);
        self
    }

    /// Add a signer.
    ///
    /// The signer is the thing generating the cryptographic signature over
    /// data to be signed.
    #[must_use]
    pub fn signer(mut self, signer: SignerBuilder<'a>) -> Self {
        self.signers.push(signer);
        self
    }

    /// Add a certificate defined by our crate's Certificate type.
    #[must_use]
    pub fn certificate(mut self, cert: CapturedX509Certificate) -> Self {
        if !self.certificates.iter().any(|x| x == &cert) {
            self.certificates.push(cert);
        }

        self
    }

    /// Add multiple certificates to the certificates chain.
    #[must_use]
    pub fn certificates(mut self, certs: impl Iterator<Item = CapturedX509Certificate>) -> Self {
        for cert in certs {
            if !self.certificates.iter().any(|x| x == &cert) {
                self.certificates.push(cert);
            }
        }

        self
    }

    /// Force the OID for the `ContentInfo.contentType` field.
    #[must_use]
    pub fn content_type(mut self, oid: Oid) -> Self {
        self.content_type = oid;
        self
    }

    /// Specify the signing time to use in signatures.
    ///
    /// If not called, current time at struct construction will be used.
    #[must_use]
    pub fn signing_time(mut self, time: UtcTime) -> Self {
        self.signing_time = time;
        self
    }

    /// Construct a `SignedData` object from the parameters received so far.
    pub fn build_signed_data(&self) -> Result<SignedData, CmsError> {
        let mut signer_infos = SignerInfos::default();
        let mut seen_digest_algorithms = HashSet::new();
        let mut seen_certificates = self.certificates.clone();
        let mut signed_data_version = if self.content_type == OID_ID_DATA {
            CmsVersion::V1
        } else {
            CmsVersion::V3
        };

        for signer in &self.signers {
            let signer_signature_algorithm = signer.signature_algorithm()?;
            validate_signature_digest_algorithms(
                signer_signature_algorithm,
                signer.digest_algorithm,
            )?;

            if signer.content_type != self.content_type {
                return Err(CmsError::SignedAttributeContentTypeMismatch);
            }

            for (index, attribute) in signer.extra_signed_attributes.iter().enumerate() {
                if attribute.typ == OID_CONTENT_TYPE
                    || attribute.typ == OID_MESSAGE_DIGEST
                    || attribute.typ == OID_SIGNING_TIME
                    || signer.extra_signed_attributes[..index]
                        .iter()
                        .any(|candidate| candidate.typ == attribute.typ)
                {
                    return Err(CmsError::DuplicateSignedAttribute(attribute.typ.clone()));
                }
                if attribute.values.is_empty() {
                    return Err(CmsError::EmptySignedAttributeValues(attribute.typ.clone()));
                }
            }

            // A message-digest that does not describe the stored content is
            // almost always a bug, so reject it unless the caller opted in via
            // `SignerBuilder::detached_message_digest`.
            if let Some(override_content) = &signer.message_id_content {
                if !signer.allow_detached_message_digest {
                    let configured_content = match &self.signed_content {
                        SignedContent::None => None,
                        SignedContent::Inline(content) | SignedContent::External(content) => {
                            Some(content)
                        }
                    };
                    if configured_content.is_some_and(|content| content != override_content) {
                        return Err(CmsError::ConflictingDigestContent);
                    }
                }
            }

            seen_digest_algorithms.insert(signer.digest_algorithm);

            if let Some(signing_certificate) = &signer.signing_certificate {
                if signing_certificate.key_algorithm() != signer.signing_key.key_algorithm()
                    || signing_certificate.public_key_data()
                        != signer.signing_key.public_key_data()
                {
                    return Err(CmsError::SigningKeyCertificateMismatch);
                }

                if !seen_certificates.iter().any(|x| x == signing_certificate) {
                    seen_certificates.push(signing_certificate.clone());
                }
            }

            let version = match signer.signer_identifier {
                SignerIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V1,
                SignerIdentifier::SubjectKeyIdentifier(_) => {
                    signed_data_version = CmsVersion::V3;
                    CmsVersion::V3
                }
            };
            let digest_algorithm = DigestAlgorithmIdentifier {
                algorithm: signer.digest_algorithm.into(),
                parameters: None,
            };

            // The message digest attribute is mandatory.
            //
            // Message digest is computed from override content on the signer
            // or the encapsulated content if present. The "empty" hash is a
            // valid value if no content (only signed attributes) are being signed.
            let mut hasher = signer.digest_algorithm.digester();
            if let Some(content) = &signer.message_id_content {
                hasher.update(content);
            } else {
                match &self.signed_content {
                    SignedContent::None => {}
                    SignedContent::Inline(content) | SignedContent::External(content) => {
                        hasher.update(content)
                    }
                }
            }
            let digest = hasher.finish();

            let mut signed_attributes = SignedAttributes::default();

            // The content-type field is mandatory.
            signed_attributes.push(Attribute {
                typ: Oid(Bytes::copy_from_slice(OID_CONTENT_TYPE.as_ref())),
                values: vec![AttributeValue::new(Captured::from_values(
                    Mode::Der,
                    signer.content_type.encode_ref(),
                ))],
            });

            // Set `messageDigest` field
            signed_attributes.push(Attribute {
                typ: Oid(Bytes::copy_from_slice(OID_MESSAGE_DIGEST.as_ref())),
                values: vec![AttributeValue::new(Captured::from_values(
                    Mode::Der,
                    digest.as_ref().encode(),
                ))],
            });

            // Add signing time because it is common to include.
            signed_attributes.push(Attribute {
                typ: Oid(Bytes::copy_from_slice(OID_SIGNING_TIME.as_ref())),
                values: vec![AttributeValue::new(Captured::from_values(
                    Mode::Der,
                    self.signing_time.clone().encode(),
                ))],
            });

            signed_attributes.extend(signer.extra_signed_attributes.iter().cloned());

            for attribute in signed_attributes.iter_mut() {
                attribute.values = sort_der(std::mem::take(&mut attribute.values))?;
            }

            // According to RFC 5652, signed attributes are DER encoded. This means a SET
            // (which SignedAttributes is) should be sorted. But bcder doesn't appear to do
            // this. So we manually sort here.
            let signed_attributes = signed_attributes.as_sorted()?;

            let signed_attributes = Some(signed_attributes);

            let signature_algorithm = signer_signature_algorithm.into();

            // The function for computing the signed attributes digested content
            // is on SignerInfo. So construct an instance so we can compute the
            // signature.
            let mut signer_info = SignerInfo {
                version,
                sid: signer.signer_identifier.clone(),
                digest_algorithm,
                signed_attributes,
                signature_algorithm,
                signature: SignatureValue::new(Bytes::copy_from_slice(&[])),
                unsigned_attributes: None,
                signed_attributes_data: None,
            };

            // The content being signed is the DER encoded signed attributes, if present, or the
            // encapsulated content. Since we always create signed attributes above, it *must* be
            // the DER encoded signed attributes.
            let signed_content = signer_info
                .signed_attributes_digested_content()?
                .ok_or(CmsError::NoSignedAttributes)?;

            let signature = signer.signing_key.try_sign(&signed_content)?;
            signer_info.signature = SignatureValue::new(Bytes::from(signature.clone()));
            signer_info.signature_algorithm = signer_signature_algorithm.into();

            #[cfg(feature = "http")]
            if let Some(url) = &signer.time_stamp_url {
                // The message sent to the TSA (via a digest) is the signature of the signed data.
                let res = time_stamp_message_http(
                    url.clone(),
                    signature.as_ref(),
                    signer.digest_algorithm,
                )?;

                if !res.is_success() {
                    return Err(TimeStampError::Unsuccessful(res.clone()).into());
                }

                let signed_data = res
                    .signed_data()?
                    .ok_or(CmsError::TimeStampProtocol(TimeStampError::BadResponse))?;

                let parsed_signed_data = crate::SignedData::try_from(&signed_data)?;
                if parsed_signed_data.signers().count() != 1 {
                    return Err(CmsError::MalformedTimeStampToken(
                        "token must contain exactly one signer",
                    ));
                }
                for time_stamp_signer in parsed_signed_data.signers() {
                    time_stamp_signer.verify_with_signed_data(&parsed_signed_data)?;
                    time_stamp_signer
                        .verify_time_stamp_signing_certificate(&parsed_signed_data)?;
                }

                let mut unsigned_attributes = UnsignedAttributes::default();
                unsigned_attributes.push(Attribute {
                    typ: Oid(Bytes::copy_from_slice(OID_TIME_STAMP_TOKEN.as_ref())),
                    values: vec![AttributeValue::new(Captured::from_values(
                        Mode::Der,
                        signed_data.encode_ref(),
                    ))],
                });

                signer_info.unsigned_attributes = Some(unsigned_attributes);
            }

            signer_infos.push(signer_info);
        }

        let mut digest_algorithms = DigestAlgorithmIdentifiers::default();
        digest_algorithms.extend(sort_der(seen_digest_algorithms.into_iter().map(|alg| {
            DigestAlgorithmIdentifier {
                algorithm: alg.into(),
                parameters: None,
            }
        }))?);

        let mut certificates = CertificateSet::default();
        certificates.extend(sort_der(seen_certificates.into_iter().map(|cert| {
            CertificateChoices::Certificate(Box::new(cert.into()))
        }))?);

        let mut sorted_signer_infos = SignerInfos::default();
        sorted_signer_infos.extend(sort_der(signer_infos.iter().cloned())?);

        let signed_data = SignedData {
            version: signed_data_version,
            digest_algorithms,
            content_info: EncapsulatedContentInfo {
                content_type: self.content_type.clone(),
                content: match &self.signed_content {
                    SignedContent::None | SignedContent::External(_) => None,
                    SignedContent::Inline(content) => {
                        Some(OctetString::new(Bytes::copy_from_slice(content)))
                    }
                },
            },
            certificates: if certificates.is_empty() {
                None
            } else {
                Some(certificates)
            },
            crls: None,
            signer_infos: sorted_signer_infos,
        };

        Ok(signed_data)
    }

    /// Construct a DER-encoded ASN.1 document containing a `SignedData` object.
    ///
    /// RFC 5652 says `SignedData` is BER encoded. However, DER is a stricter subset
    /// of BER. DER encodings are valid BER. So producing DER encoded data is perfectly
    /// valid. We choose to go with the more well-defined encoding format.
    pub fn build_der(&self) -> Result<Vec<u8>, CmsError> {
        let signed_data = self.build_signed_data()?;

        let mut ber = Vec::new();
        signed_data
            .encode_ref()
            .write_encoded(Mode::Der, &mut ber)?;

        Ok(ber)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{asn1::rfc5652::OID_ID_SIGNED_DATA, SignedData},
        x509_certificate::{
            rfc5280::AlgorithmParameter, testutil::*, EcdsaCurve, KeyAlgorithm,
            InMemorySigningKeyPair, X509CertificateBuilder,
        },
    };

    #[cfg(feature = "http")]
    const DIGICERT_TIMESTAMP_URL: &str = "http://timestamp.digicert.com";

    #[test]
    fn simple_rsa_signature_inline() {
        let key = rsa_private_key();
        let cert = rsa_cert();

        let signer = SignerBuilder::new(&key, cert);

        let ber = SignedDataBuilder::default()
            .content_inline(vec![42])
            .signer(signer)
            .build_der()
            .unwrap();

        let signed_data = crate::SignedData::parse_ber(&ber).unwrap();
        assert_eq!(signed_data.signed_content(), Some(vec![42].as_ref()));
        assert_eq!(signed_data.content_type(), &OID_ID_DATA);

        for signer in signed_data.signers() {
            signer.verify_with_signed_data(&signed_data).unwrap();
            signer
                .verify_message_digest_with_signed_data(&signed_data)
                .unwrap();
            signer
                .verify_signature_with_signed_data(&signed_data)
                .unwrap();
            assert!(signer.unsigned_attributes.is_none());
        }
    }

    #[test]
    fn builder_rejects_mismatched_content_types() {
        let key = rsa_private_key();
        let cert = rsa_cert();
        let signer = SignerBuilder::new(&key, cert);

        assert!(matches!(
            SignedDataBuilder::default()
                .content_type(Oid(OID_ID_SIGNED_DATA.as_ref().into()))
                .signer(signer)
                .build_der(),
            Err(CmsError::SignedAttributeContentTypeMismatch)
        ));
    }

    #[test]
    fn builder_selects_versions_from_content_and_signer_identifier() {
        let key = rsa_private_key();
        let cert = rsa_cert();
        let content_type = Oid(OID_ID_SIGNED_DATA.as_ref().into());
        let signer = SignerBuilder::new(&key, cert).content_type(content_type.clone());

        let signed_data = SignedDataBuilder::default()
            .content_type(content_type)
            .signer(signer)
            .build_signed_data()
            .unwrap();
        assert_eq!(signed_data.version, CmsVersion::V3);
        assert_eq!(signed_data.signer_infos[0].version, CmsVersion::V1);

        let signer = SignerBuilder::new_with_signer_identifier(
            &key,
            SignerIdentifier::SubjectKeyIdentifier(OctetString::new(Bytes::from_static(
                b"subject-key-id",
            ))),
        );
        let signed_data = SignedDataBuilder::default()
            .signer(signer)
            .build_signed_data()
            .unwrap();
        assert_eq!(signed_data.version, CmsVersion::V3);
        assert_eq!(signed_data.signer_infos[0].version, CmsVersion::V3);
    }

    #[test]
    fn subject_key_identifier_signer_round_trips_and_verifies() {
        let key = InMemorySigningKeyPair::generate_random(KeyAlgorithm::Ed25519).unwrap();
        let key_identifier = b"key-id";
        let mut certificate_builder = X509CertificateBuilder::default();
        certificate_builder
            .subject()
            .append_common_name_utf8_string("SKI signer")
            .unwrap();
        certificate_builder.add_extension_der_data(
            Oid(Bytes::from_static(&[85, 29, 14])),
            false,
            [0x04, key_identifier.len() as u8]
                .into_iter()
                .chain(key_identifier.iter().copied())
                .collect::<Vec<_>>(),
        );
        let certificate = certificate_builder.create_with_key_pair(&key).unwrap();

        let signer = SignerBuilder::new_with_signer_identifier(
            &key,
            SignerIdentifier::SubjectKeyIdentifier(OctetString::new(Bytes::from_static(
                key_identifier,
            ))),
        );
        let encoded = SignedDataBuilder::default()
            .content_inline(b"signed with an SKI".to_vec())
            .certificate(certificate)
            .signer(signer)
            .build_der()
            .unwrap();

        let signed_data = crate::SignedData::parse_ber(&encoded).unwrap();
        let signer = signed_data.signers().next().unwrap();
        assert!(signer.certificate_issuer_and_serial().is_none());
        assert_eq!(signer.subject_key_identifier(), Some(key_identifier.as_slice()));
        signer.verify_with_signed_data(&signed_data).unwrap();
    }

    #[test]
    fn builder_rejects_duplicate_mandatory_attribute() {
        let key = rsa_private_key();
        let cert = rsa_cert();
        let signer = SignerBuilder::new(&key, cert).signed_attribute(
            Oid(OID_MESSAGE_DIGEST.as_ref().into()),
            Vec::new(),
        );

        assert!(matches!(
            SignedDataBuilder::default().signer(signer).build_der(),
            Err(CmsError::DuplicateSignedAttribute(_))
        ));
    }

    #[test]
    fn builder_rejects_empty_and_conflicting_attribute_content() {
        let key = rsa_private_key();
        let cert = rsa_cert();
        let signer = SignerBuilder::new(&key, cert.clone()).signed_attribute(
            Oid(Bytes::from_static(&[0x2a, 0x03])),
            Vec::new(),
        );

        assert!(matches!(
            SignedDataBuilder::default().signer(signer).build_der(),
            Err(CmsError::EmptySignedAttributeValues(_))
        ));

        let signer = SignerBuilder::new(&key, cert).message_id_content(vec![1]);
        assert!(matches!(
            SignedDataBuilder::default()
                .content_external(vec![2])
                .signer(signer)
                .build_der(),
            Err(CmsError::ConflictingDigestContent)
        ));
    }

    /// Authenticode digests the content octets of its `SpcIndirectDataContent`
    /// SEQUENCE rather than the stored `eContent`, so the mismatch has to be
    /// expressible — but only on purpose.
    #[test]
    fn detached_message_digest_opts_out_of_the_conflict_check() {
        let key = rsa_private_key();
        let cert = rsa_cert();

        let signer = SignerBuilder::new(&key, cert.clone()).detached_message_digest(vec![1]);
        let der = SignedDataBuilder::default()
            .content_inline(vec![2])
            .signer(signer)
            .build_der()
            .expect("an explicitly detached digest should be allowed");
        assert!(!der.is_empty());

        // The digest must be over the detached bytes, not the stored content.
        let expected = DigestAlgorithm::Sha256.digest_data(&[1]);
        assert!(
            der.windows(expected.len()).any(|w| w == expected),
            "message-digest should cover the detached content"
        );

        // Without the opt-in the same configuration is still rejected.
        let signer = SignerBuilder::new(&key, cert).message_id_content(vec![1]);
        assert!(matches!(
            SignedDataBuilder::default()
                .content_inline(vec![2])
                .signer(signer)
                .build_der(),
            Err(CmsError::ConflictingDigestContent)
        ));
    }

    #[test]
    fn builder_rejects_a_certificate_for_another_key() {
        let (_, key) = self_signed_ed25519_key_pair();
        let (unrelated_certificate, _) = self_signed_ed25519_key_pair();

        assert!(matches!(
            SignedDataBuilder::default()
                .signer(SignerBuilder::new(&key, unrelated_certificate))
                .build_der(),
            Err(CmsError::SigningKeyCertificateMismatch)
        ));
    }

    #[test]
    fn parser_rejects_invalid_generic_signature_algorithm_parameters() {
        let key = rsa_private_key();
        let cert = rsa_cert();
        let mut raw = SignedDataBuilder::default()
            .content_inline(vec![42])
            .signer(SignerBuilder::new(&key, cert))
            .build_signed_data()
            .unwrap();

        raw.signer_infos[0].signature_algorithm.algorithm = KeyAlgorithm::Rsa.into();
        raw.signer_infos[0].signature_algorithm.parameters = Some(AlgorithmParameter::from_oid(
            Oid(OID_ID_DATA.as_ref().into()),
        ));

        assert!(crate::SignedData::try_from(&raw).is_err());
    }

    #[test]
    fn parser_rejects_sha512_null_parameters_for_ed25519() {
        let (certificate, key) = self_signed_ed25519_key_pair();
        let mut raw = SignedDataBuilder::default()
            .content_inline(vec![42])
            .signer(SignerBuilder::new(&key, certificate.clone()))
            .build_signed_data()
            .unwrap();
        raw.signer_infos[0].digest_algorithm.parameters = Some(AlgorithmParameter::null());

        assert!(crate::SignedData::try_from(&raw).is_err());

        let mut raw = SignedDataBuilder::default()
            .content_inline(vec![42])
            .signer(SignerBuilder::new(&key, certificate))
            .build_signed_data()
            .unwrap();
        raw.digest_algorithms[0].parameters = Some(AlgorithmParameter::null());

        assert!(crate::SignedData::try_from(&raw).is_err());
    }

    #[test]
    fn parser_rejects_duplicate_digest_algorithms() {
        let key = rsa_private_key();
        let certificate = rsa_cert();
        let mut raw = SignedDataBuilder::default()
            .content_inline(vec![42])
            .signer(SignerBuilder::new(&key, certificate))
            .build_signed_data()
            .unwrap();
        let duplicate = raw.digest_algorithms[0].clone();
        raw.digest_algorithms.push(duplicate);

        assert!(matches!(
            crate::SignedData::try_from(&raw),
            Err(CmsError::DuplicateDigestAlgorithm(_))
        ));
    }

    #[test]
    fn simple_rsa_signature_external() {
        let key = rsa_private_key();
        let cert = rsa_cert();

        let signer = SignerBuilder::new(&key, cert);

        let ber = SignedDataBuilder::default()
            .content_external(vec![42])
            .signer(signer)
            .build_der()
            .unwrap();

        let signed_data = crate::SignedData::parse_ber(&ber).unwrap();
        assert!(signed_data.signed_content().is_none());

        for signer in signed_data.signers() {
            assert!(matches!(
                signer.verify_with_signed_data(&signed_data),
                Err(CmsError::DetachedContentRequired)
            ));
            signer.verify_with_content(&signed_data, &[42]).unwrap();
            signer.verify_message_digest_with_content(&[42]).unwrap();
            signer
                .verify_signature_with_signed_data(&signed_data)
                .unwrap();
            assert!(signer.unsigned_attributes.is_none());
        }
    }

    #[cfg(feature = "http")]
    #[test]
    #[ignore = "requires a live external time-stamp service"]
    fn time_stamp_url() {
        let key = rsa_private_key();
        let cert = rsa_cert();

        let signer = SignerBuilder::new(&key, cert)
            .time_stamp_url(DIGICERT_TIMESTAMP_URL)
            .unwrap();

        let ber = SignedDataBuilder::default()
            .content_inline(vec![42])
            .signer(signer)
            .build_der()
            .unwrap();

        let signed_data = crate::SignedData::parse_ber(&ber).unwrap();

        for signer in signed_data.signers() {
            let unsigned = signer.unsigned_attributes().unwrap();
            let tst = unsigned.time_stamp_token.as_ref().unwrap();
            assert!(tst.certificates.is_some());

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
        }
    }

    #[test]
    fn simple_ecdsa_signature() {
        for curve in EcdsaCurve::all() {
            let (cert, key) = self_signed_ecdsa_key_pair(Some(*curve));

            let cms = SignedDataBuilder::default()
                .content_inline("hello world".as_bytes().to_vec())
                .certificate(cert.clone())
                .signer(SignerBuilder::new(&key, cert))
                .build_der()
                .unwrap();

            let signed_data = SignedData::parse_ber(&cms).unwrap();

            for signer in signed_data.signers() {
                signer
                    .verify_signature_with_signed_data(&signed_data)
                    .unwrap();
            }
        }
    }

    #[test]
    fn simple_ed25519_signature() {
        let (cert, key) = self_signed_ed25519_key_pair();

        let cms = SignedDataBuilder::default()
            .content_inline("hello world".as_bytes().to_vec())
            .certificate(cert.clone())
            .signer(SignerBuilder::new(&key, cert))
            .build_der()
            .unwrap();

        let signed_data = SignedData::parse_ber(&cms).unwrap();

        for signer in signed_data.signers() {
            signer
                .verify_signature_with_signed_data(&signed_data)
                .unwrap();
        }
    }
}
