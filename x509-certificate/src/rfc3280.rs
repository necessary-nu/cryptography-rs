// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ASN.1 types defined in RFC 3280.

use {
    crate::rfc4519::{
        OID_COMMON_NAME, OID_COUNTRY_NAME, OID_LOCALITY_NAME, OID_ORGANIZATIONAL_UNIT_NAME,
        OID_ORGANIZATION_NAME, OID_STATE_PROVINCE_NAME,
    },
    bcder::{
        decode::{BytesSource, Constructed, DecodeError, Source},
        encode,
        encode::{PrimitiveContent, Values},
        string::{Ia5String, PrintableString, Utf8String},
        Captured, Mode, OctetString, Oid, Tag,
    },
    std::{
        fmt::{Debug, Display, Formatter},
        io::Write,
        ops::{Deref, DerefMut},
        str::FromStr,
    },
};

pub type GeneralNames = Vec<GeneralName>;

/// General name.
///
/// ```ASN.1
/// GeneralName ::= CHOICE {
///   otherName                       [0]     AnotherName,
///   rfc822Name                      [1]     IA5String,
///   dNSName                         [2]     IA5String,
///   x400Address                     [3]     ORAddress,
///   directoryName                   [4]     Name,
///   ediPartyName                    [5]     EDIPartyName,
///   uniformResourceIdentifier       [6]     IA5String,
///   iPAddress                       [7]     OCTET STRING,
///   registeredID                    [8]     OBJECT IDENTIFIER }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneralName {
    OtherName(AnotherName),
    Rfc822Name(Ia5String),
    DnsName(Ia5String),
    X400Address(OrAddress),
    DirectoryName(Name),
    EdiPartyName(EdiPartyName),
    UniformResourceIdentifier(Ia5String),
    IpAddress(OctetString),
    RegisteredId(Oid),
}

impl GeneralName {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        Self::take_opt_from(cons)?.ok_or_else(|| cons.content_err("unexpected GeneralName variant"))
    }

    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        if let Some(name) =
            cons.take_opt_constructed_if(Tag::CTX_0, AnotherName::from_sequence)?
        {
            return Ok(Some(Self::OtherName(name)));
        }
        if let Some(name) = cons.take_opt_value_if(Tag::CTX_1, Ia5String::from_content)? {
            return Ok(Some(Self::Rfc822Name(name)));
        }
        if let Some(name) = cons.take_opt_value_if(Tag::CTX_2, Ia5String::from_content)? {
            return Ok(Some(Self::DnsName(name)));
        }
        if let Some(name) =
            cons.take_opt_constructed_if(Tag::CTX_3, OrAddress::from_sequence)?
        {
            return Ok(Some(Self::X400Address(name)));
        }
        if let Some(name) = cons.take_opt_constructed_if(Tag::CTX_4, Name::take_from)? {
            return Ok(Some(Self::DirectoryName(name)));
        }
        if let Some(name) =
            cons.take_opt_constructed_if(Tag::CTX_5, EdiPartyName::from_sequence)?
        {
            return Ok(Some(Self::EdiPartyName(name)));
        }
        if let Some(name) = cons.take_opt_value_if(Tag::CTX_6, Ia5String::from_content)? {
            return Ok(Some(Self::UniformResourceIdentifier(name)));
        }
        if let Some(name) = cons.take_opt_value_if(Tag::ctx(7), OctetString::from_content)? {
            return Ok(Some(Self::IpAddress(name)));
        }
        if let Some(name) = cons.take_opt_primitive_if(Tag::ctx(8), Oid::from_primitive)? {
            return Ok(Some(Self::RegisteredId(name)));
        }

        Ok(None)
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        match self {
            Self::OtherName(name) => (
                Some(name.encode_ref_as(Tag::CTX_0)),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            Self::Rfc822Name(name) => (
                None,
                Some(name.encode_ref_as(Tag::CTX_1)),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            Self::DnsName(name) => (
                None,
                None,
                Some(name.encode_ref_as(Tag::CTX_2)),
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            Self::X400Address(name) => (
                None,
                None,
                None,
                Some(name.encode_ref_as(Tag::CTX_3)),
                None,
                None,
                None,
                None,
                None,
            ),
            Self::DirectoryName(name) => (
                None,
                None,
                None,
                None,
                // Name is a CHOICE, so the context-specific tag is explicit.
                Some(encode::Constructed::new(Tag::CTX_4, name.encode_ref())),
                None,
                None,
                None,
                None,
            ),
            Self::EdiPartyName(name) => (
                None,
                None,
                None,
                None,
                None,
                Some(name.encode_ref_as(Tag::CTX_5)),
                None,
                None,
                None,
            ),
            Self::UniformResourceIdentifier(name) => (
                None,
                None,
                None,
                None,
                None,
                None,
                Some(name.encode_ref_as(Tag::CTX_6)),
                None,
                None,
            ),
            Self::IpAddress(name) => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(name.encode_ref_as(Tag::ctx(7))),
                None,
            ),
            Self::RegisteredId(name) => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(name.encode_ref_as(Tag::ctx(8))),
            ),
        }
    }
}

/// A reference to another name.
///
/// ```ASN.1
/// AnotherName ::= SEQUENCE {
///   type-id    OBJECT IDENTIFIER,
///   value      [0] EXPLICIT ANY DEFINED BY type-id }
/// ```
#[derive(Clone, Debug)]
pub struct AnotherName {
    pub type_id: Oid,
    pub value: Captured,
}

impl PartialEq for AnotherName {
    fn eq(&self, other: &Self) -> bool {
        self.type_id == other.type_id && self.value.as_slice() == other.value.as_slice()
    }
}

impl Eq for AnotherName {}

impl AnotherName {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::from_sequence)
    }

    fn from_sequence<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        let type_id = Oid::take_from(cons)?;
        let value = cons.take_constructed_if(Tag::CTX_0, |cons| cons.capture_one())?;

        Ok(Self { type_id, value })
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::sequence_as(
            tag,
            (
                self.type_id.encode_ref(),
                encode::Constructed::new(Tag::CTX_0, crate::CapturedValues(&self.value)),
            ),
        )
    }
}

impl Values for AnotherName {
    fn encoded_len(&self, mode: Mode) -> usize {
        encode::sequence((
            self.type_id.encode_ref(),
            encode::Constructed::new(Tag::CTX_0, crate::CapturedValues(&self.value)),
        ))
        .encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        encode::sequence((
            self.type_id.encode_ref(),
            encode::Constructed::new(Tag::CTX_0, crate::CapturedValues(&self.value)),
        ))
        .write_encoded(mode, target)
    }
}

/// EDI party name.
///
/// ```ASN.1
/// EDIPartyName ::= SEQUENCE {
///   nameAssigner            [0]     DirectoryString OPTIONAL,
///   partyName               [1]     DirectoryString }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdiPartyName {
    pub name_assigner: Option<DirectoryString>,
    pub party_name: DirectoryString,
}

impl EdiPartyName {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::from_sequence)
    }

    fn from_sequence<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        let name_assigner =
            cons.take_opt_constructed_if(Tag::CTX_0, DirectoryString::take_from)?;
        let party_name = cons.take_constructed_if(Tag::CTX_1, DirectoryString::take_from)?;

        Ok(Self {
            name_assigner,
            party_name,
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.name_assigner
                .as_ref()
                .map(|name_assigner| {
                    encode::Constructed::new(Tag::CTX_0, name_assigner.encode_ref())
                }),
            encode::Constructed::new(Tag::CTX_1, self.party_name.encode_ref()),
        ))
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::sequence_as(
            tag,
            (
                self.name_assigner
                    .as_ref()
                    .map(|name_assigner| {
                        encode::Constructed::new(Tag::CTX_0, name_assigner.encode_ref())
                    }),
                encode::Constructed::new(Tag::CTX_1, self.party_name.encode_ref()),
            ),
        )
    }
}

/// Directory string.
///
/// ```ASN.1
/// DirectoryString ::= CHOICE {
///       teletexString           TeletexString (SIZE (1..MAX)),
///       printableString         PrintableString (SIZE (1..MAX)),
///       universalString         UniversalString (SIZE (1..MAX)),
///       utf8String              UTF8String (SIZE (1..MAX)),
///       bmpString               BMPString (SIZE (1..MAX)) }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectoryString {
    // TODO implement.
    TeletexString,
    PrintableString(PrintableString),
    // TODO implement.
    UniversalString,
    Utf8String(Utf8String),
    // TODO implement.
    BmpString,
}

impl DirectoryString {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_value(|tag, content| {
            if tag == Tag::PRINTABLE_STRING {
                Ok(Self::PrintableString(PrintableString::from_content(
                    content,
                )?))
            } else if tag == Tag::UTF8_STRING {
                Ok(Self::Utf8String(Utf8String::from_content(content)?))
            } else {
                Err(content
                    .content_err("only decoding of PrintableString and UTF8String is implemented"))
            }
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        match self {
            Self::PrintableString(ps) => (Some(ps.encode_ref()), None, None),
            Self::Utf8String(s) => (None, Some(s.encode_ref()), None),
            _ => (
                None,
                None,
                Some(crate::UnsupportedEncoder(
                    "encoding this DirectoryString variant is not implemented",
                )),
            ),
        }
    }
}

impl Display for DirectoryString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Self::PrintableString(s) => s.to_string(),
            Self::Utf8String(s) => s.to_string(),
            Self::TeletexString => "<unsupported TeletexString>".to_string(),
            Self::UniversalString => "<unsupported UniversalString>".to_string(),
            Self::BmpString => "<unsupported BmpString>".to_string(),
        };
        write!(f, "{}", str)
    }
}

impl Values for DirectoryString {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Name {
    RdnSequence(RdnSequence),
}

impl Name {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        Ok(Self::RdnSequence(RdnSequence::take_from(cons)?))
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        match self {
            Self::RdnSequence(seq) => seq.encode_ref(),
        }
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        match self {
            Self::RdnSequence(seq) => seq.encode_ref_as(tag),
        }
    }

    /// Iterate over relative distinguished name entries in this instance.
    pub fn iter_rdn(&self) -> impl Iterator<Item = &RelativeDistinguishedName> {
        self.0.iter()
    }

    /// Iterate over all attributes in this Name.
    pub fn iter_attributes(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.0.iter().flat_map(|rdn| rdn.iter())
    }

    /// Iterate over all attributes, yielding mutable entries.
    pub fn iter_mut_attributes(&mut self) -> impl Iterator<Item = &mut AttributeTypeAndValue> {
        self.0.iter_mut().flat_map(|rdn| rdn.iter_mut())
    }

    /// Iterate over all attributes in this Name having a given OID.
    pub fn iter_by_oid(&self, oid: Oid) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_attributes().filter(move |atv| atv.typ == oid)
    }

    /// Iterate over all attributes in this Name having a given OID, yielding mutable instances.
    pub fn iter_mut_by_oid(
        &mut self,
        oid: Oid,
    ) -> impl Iterator<Item = &mut AttributeTypeAndValue> {
        self.iter_mut_attributes().filter(move |atv| atv.typ == oid)
    }

    /// Iterate over all Common Name (CN) attributes.
    pub fn iter_common_name(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(Oid(OID_COMMON_NAME.as_ref().into()))
    }

    /// Iterate over all Country (C) attributes.
    pub fn iter_country(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(Oid(OID_COUNTRY_NAME.as_ref().into()))
    }

    /// Iterate over all Locality Name (L) attributes.
    pub fn iter_locality(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(Oid(OID_LOCALITY_NAME.as_ref().into()))
    }

    /// Iterate over all State or Province attributes.
    pub fn iter_state_province(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(Oid(OID_STATE_PROVINCE_NAME.as_ref().into()))
    }

    /// Iterate over all Organization (O) attributes.
    pub fn iter_organization(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(Oid(OID_ORGANIZATION_NAME.as_ref().into()))
    }

    /// Iterate over all Organizational Unit (OU) attributes.
    pub fn iter_organizational_unit(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(Oid(OID_ORGANIZATIONAL_UNIT_NAME.as_ref().into()))
    }

    /// Find the first attribute given an OID search.
    pub fn find_attribute(&self, oid: Oid) -> Option<&AttributeTypeAndValue> {
        self.iter_by_oid(oid).next()
    }

    /// Attempt to obtain a string attribute given
    pub fn find_first_attribute_string(
        &self,
        oid: Oid,
    ) -> Result<Option<String>, DecodeError<<BytesSource as Source>::Error>> {
        if let Some(atv) = self.find_attribute(oid) {
            Ok(Some(atv.to_string()?))
        } else {
            Ok(None)
        }
    }

    /// Obtain a user friendly string representation of this instance.
    ///
    /// This prints common OIDs like common name and organization unit in a way
    /// that is similar to how tools like OpenSSL render certificates.
    ///
    /// Not all attributes are printed. Do not compare the output of this
    /// function to test equality.
    pub fn user_friendly_str(&self) -> Result<String, DecodeError<<BytesSource as Source>::Error>> {
        let mut fields = vec![];

        for cn in self.iter_common_name() {
            fields.push(format!("CN={}", cn.to_string()?));
        }
        for ou in self.iter_organizational_unit() {
            fields.push(format!("OU={}", ou.to_string()?));
        }
        for o in self.iter_organization() {
            fields.push(format!("O={}", o.to_string()?));
        }
        for l in self.iter_locality() {
            fields.push(format!("L={}", l.to_string()?));
        }
        for state in self.iter_state_province() {
            fields.push(format!("S={}", state.to_string()?));
        }
        for c in self.iter_country() {
            fields.push(format!("C={}", c.to_string()?));
        }

        Ok(fields.join(", "))
    }

    /// Appends a PrintableString value for the given OID.
    ///
    /// The attribute will always be written to a new RDN.
    pub fn append_printable_string(
        &mut self,
        oid: Oid,
        value: &str,
    ) -> Result<(), bcder::string::CharSetError> {
        let mut rdn = RelativeDistinguishedName::default();
        rdn.push(AttributeTypeAndValue::new_printable_string(oid, value)?);
        self.0.push(rdn);

        Ok(())
    }

    /// Appends a Utf8String value for the given OID.
    ///
    /// The attribute will always be written to a new RD.
    pub fn append_utf8_string(
        &mut self,
        oid: Oid,
        value: &str,
    ) -> Result<(), bcder::string::CharSetError> {
        let mut rdn = RelativeDistinguishedName::default();
        rdn.push(AttributeTypeAndValue::new_utf8_string(oid, value)?);
        self.0.push(rdn);

        Ok(())
    }

    /// Append a Common Name (CN) attribute to the first RDN.
    pub fn append_common_name_utf8_string(
        &mut self,
        value: &str,
    ) -> Result<(), bcder::string::CharSetError> {
        self.append_utf8_string(Oid(OID_COMMON_NAME.as_ref().into()), value)
    }

    /// Append a Country (C) attribute to the first RDN.
    #[deprecated(note = "countryName must be a two-character PrintableString; use append_country_printable_string")]
    pub fn append_country_utf8_string(
        &mut self,
        value: &str,
    ) -> Result<(), bcder::string::CharSetError> {
        self.append_utf8_string(Oid(OID_COUNTRY_NAME.as_ref().into()), value)
    }

    /// Append a two-character Country (C) PrintableString attribute.
    pub fn append_country_printable_string(
        &mut self,
        value: &str,
    ) -> Result<(), bcder::string::CharSetError> {
        if value.len() != 2 {
            return Err(bcder::string::CharSetError);
        }

        self.append_printable_string(Oid(OID_COUNTRY_NAME.as_ref().into()), value)
    }

    /// Append an Organization Name (O) attribute to the first RDN.
    pub fn append_organization_utf8_string(
        &mut self,
        value: &str,
    ) -> Result<(), bcder::string::CharSetError> {
        self.append_utf8_string(Oid(OID_ORGANIZATION_NAME.as_ref().into()), value)
    }

    /// Append an Organizational Unit (OU) attribute to the first RDN.
    pub fn append_organizational_unit_utf8_string(
        &mut self,
        value: &str,
    ) -> Result<(), bcder::string::CharSetError> {
        self.append_utf8_string(Oid(OID_ORGANIZATIONAL_UNIT_NAME.as_ref().into()), value)
    }
}

impl Default for Name {
    fn default() -> Self {
        Self::RdnSequence(RdnSequence::default())
    }
}

impl Deref for Name {
    type Target = RdnSequence;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::RdnSequence(seq) => seq,
        }
    }
}

impl DerefMut for Name {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::RdnSequence(seq) => seq,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RdnSequence(Vec<RelativeDistinguishedName>);

impl Deref for RdnSequence {
    type Target = Vec<RelativeDistinguishedName>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RdnSequence {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl RdnSequence {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let mut values = Vec::new();

            while let Some(value) = RelativeDistinguishedName::take_opt_from(cons)? {
                values.push(value);
            }

            Ok(Self(values))
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence(&self.0)
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::sequence_as(tag, &self.0)
    }
}

pub type DistinguishedName = RdnSequence;

/// Relative distinguished name.
///
/// ```ASN.1
/// RelativeDistinguishedName ::=
///   SET OF AttributeTypeAndValue
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelativeDistinguishedName(Vec<AttributeTypeAndValue>);

impl Deref for RelativeDistinguishedName {
    type Target = Vec<AttributeTypeAndValue>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RelativeDistinguishedName {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl RelativeDistinguishedName {
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_set(|cons| {
            let mut values = Vec::new();

            while let Some(value) = AttributeTypeAndValue::take_opt_from(cons)? {
                values.push(value);
            }

            Ok(Self(values))
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::set(&self.0)
    }
}

impl Values for RelativeDistinguishedName {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

#[derive(Clone, Debug)]
pub struct OrAddress(Captured);

impl PartialEq for OrAddress {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for OrAddress {}

impl OrAddress {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::from_sequence)
    }

    fn from_sequence<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        Ok(Self(cons.capture_all()?))
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::Constructed::new(tag, crate::CapturedValues(&self.0))
    }
}

/// Attribute type and its value.
///
/// ```ASN.1
/// AttributeTypeAndValue ::= SEQUENCE {
///   type     AttributeType,
///   value    AttributeValue }
/// ```
#[derive(Clone)]
pub struct AttributeTypeAndValue {
    pub typ: AttributeType,
    pub value: AttributeValue,
}

impl Debug for AttributeTypeAndValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("AttributeTypeAndValue");
        s.field("type", &format_args!("{}", self.typ));
        s.field("value", &self.value);
        s.finish()
    }
}

impl AttributeTypeAndValue {
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let typ = AttributeType::take_from(cons)?;
            let value = cons.capture_one()?;

            Ok(Self {
                typ,
                value: value.into(),
            })
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.typ.encode_ref(),
            crate::CapturedValues(self.value.deref()),
        ))
    }

    /// Attempt to coerce the stored value to a Rust string.
    pub fn to_string(&self) -> Result<String, DecodeError<<BytesSource as Source>::Error>> {
        self.value.to_string()
    }

    /// Construct a new instance with a PrintableString given an OID and Rust string.
    pub fn new_printable_string(oid: Oid, s: &str) -> Result<Self, bcder::string::CharSetError> {
        Ok(Self {
            typ: oid,
            value: AttributeValue::new_printable_string(s)?,
        })
    }

    /// Construct a new instance with a Utf8String given an OID and Rust string.
    pub fn new_utf8_string(oid: Oid, s: &str) -> Result<Self, bcder::string::CharSetError> {
        Ok(Self {
            typ: oid,
            value: AttributeValue::new_utf8_string(s)?,
        })
    }

    /// Set the captured value to a Utf8String.
    pub fn set_utf8_string_value(&mut self, s: &str) -> Result<(), bcder::string::CharSetError> {
        self.value.set_utf8_string_value(s)
    }
}

impl PartialEq for AttributeTypeAndValue {
    fn eq(&self, other: &Self) -> bool {
        self.typ == other.typ && self.value.as_slice() == other.value.as_slice()
    }
}

impl Eq for AttributeTypeAndValue {}

impl Values for AttributeTypeAndValue {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

pub type AttributeType = Oid;

#[derive(Clone)]
pub struct AttributeValue(Captured);

impl Debug for AttributeValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", hex::encode(self.0.as_slice())))
    }
}

impl AttributeValue {
    /// Construct a new instance containing a PrintableString given a Rust string.
    pub fn new_printable_string(s: &str) -> Result<Self, bcder::string::CharSetError> {
        let mut slf = Self(Captured::empty(Mode::Der));

        slf.set_printable_string_value(s)?;

        Ok(slf)
    }

    /// Construct a new instance containing a Utf8String given a Rust string.
    pub fn new_utf8_string(s: &str) -> Result<Self, bcder::string::CharSetError> {
        let mut slf = Self(Captured::empty(Mode::Der));

        slf.set_utf8_string_value(s)?;

        Ok(slf)
    }

    /// Attempt to convert the inner value to a Rust string.
    ///
    /// The inner value can be any number of different types. This will try
    /// a lot of them and hopefully yield a working result.
    ///
    /// If the inner type isn't a known string, a decoding error occurs.
    pub fn to_string(&self) -> Result<String, DecodeError<<BytesSource as Source>::Error>> {
        self.0.clone().decode(|cons| {
            match cons.take_opt_value_if(Tag::NUMERIC_STRING, |content| {
                bcder::NumericString::from_content(content)
            })? { Some(s) => {
                Ok(s.to_string())
            } _ => { match cons.take_opt_value_if(Tag::PRINTABLE_STRING, |content| {
                bcder::PrintableString::from_content(content)
            })? { Some(s) => {
                Ok(s.to_string())
            } _ => { match cons.take_opt_value_if(Tag::UTF8_STRING, |content| {
                bcder::Utf8String::from_content(content)
            })? { Some(s) => {
                Ok(s.to_string())
            } _ => { match cons.take_opt_value_if(Tag::IA5_STRING, |content| {
                bcder::Ia5String::from_content(content)
            })? { Some(s) => {
                Ok(s.to_string())
            } _ => {
                Ok(DirectoryString::take_from(cons)?.to_string())
            }}}}}}}}
        })
    }

    /// Set the captured value to a PrintableString.
    pub fn set_printable_string_value(
        &mut self,
        value: &str,
    ) -> Result<(), bcder::string::CharSetError> {
        let ps = DirectoryString::PrintableString(PrintableString::from_str(value)?);
        let captured = bcder::Captured::from_values(Mode::Der, ps);
        self.0 = captured;

        Ok(())
    }

    /// Set the captured value to a Utf8String.
    pub fn set_utf8_string_value(
        &mut self,
        value: &str,
    ) -> Result<(), bcder::string::CharSetError> {
        let ds = DirectoryString::Utf8String(Utf8String::from_str(value)?);
        let captured = bcder::Captured::from_values(Mode::Der, ds);
        self.0 = captured;

        Ok(())
    }
}

impl Deref for AttributeValue {
    type Target = Captured;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Captured> for AttributeValue {
    fn from(v: Captured) -> Self {
        Self(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(der: &[u8]) -> GeneralName {
        let parsed = Constructed::decode(der, Mode::Der, GeneralName::take_from).unwrap();
        let mut encoded = Vec::new();
        parsed
            .encode_ref()
            .write_encoded(Mode::Der, &mut encoded)
            .unwrap();
        assert_eq!(encoded, der);
        parsed
    }

    #[test]
    fn general_name_implicit_primitive_variants_round_trip() {
        assert!(matches!(
            round_trip(&[
                0x82, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
            ]),
            GeneralName::DnsName(_)
        ));
        assert!(matches!(
            round_trip(&[0x87, 0x04, 127, 0, 0, 1]),
            GeneralName::IpAddress(_)
        ));
        assert!(matches!(
            round_trip(&[0x88, 0x03, 0x2a, 0x03, 0x04]),
            GeneralName::RegisteredId(_)
        ));
    }

    #[test]
    fn general_name_explicit_directory_name_round_trips() {
        assert!(matches!(
            round_trip(&[
                0xa4, 0x0e, 0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04,
                0x03, 0x0c, 0x01, b'x',
            ]),
            GeneralName::DirectoryName(_)
        ));
    }

    #[test]
    fn country_name_helper_enforces_x520_syntax() {
        let mut name = Name::default();
        name.append_country_printable_string("US").unwrap();
        assert!(name.append_country_printable_string("USA").is_err());
    }

    #[test]
    fn unsupported_directory_string_variants_return_encoding_errors() {
        let value = DirectoryString::TeletexString;
        let mut encoded = Vec::new();
        assert!(value.write_encoded(Mode::Der, &mut encoded).is_err());
        assert_eq!(value.to_string(), "<unsupported TeletexString>");
    }
}
