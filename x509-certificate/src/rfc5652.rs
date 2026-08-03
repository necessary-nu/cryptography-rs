// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ASN.1 types defined in RFC 5652.
//!
//! Only the types referenced by X.509 certificates are defined here.
//! For the higher-level CMS types, see the `cryptographic-message-syntax`
//! crate.

use {
    bcder::{
        decode::{Constructed, DecodeError, Source},
        encode::{self, PrimitiveContent, Values},
        Captured, Mode, Oid,
    },
    std::{
        fmt::{Debug, Formatter},
        io::Write,
        ops::{Deref, DerefMut},
    },
};

/// A single attribute.
///
/// ```ASN.1
/// Attribute ::= SEQUENCE {
///   attrType OBJECT IDENTIFIER,
///   attrValues SET OF AttributeValue }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct Attribute {
    pub typ: Oid,
    pub values: Vec<AttributeValue>,
}

impl Debug for Attribute {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Attribute");
        s.field("type", &format_args!("{}", self.typ));
        s.field("values", &self.values);
        s.finish()
    }
}

impl Attribute {
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let typ = Oid::take_from(cons)?;

            let values = cons.take_set(|cons| {
                let mut values = Vec::new();

                while let Some(value) = AttributeValue::take_opt_from(cons)? {
                    values.push(value);
                }

                if values.is_empty() {
                    Err(cons.content_err("Attribute values must not be empty"))
                } else {
                    Ok(values)
                }
            })?;

            Ok(Self { typ, values })
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((self.typ.encode_ref(), encode::set(&self.values)))
    }

    pub fn encode(self) -> impl Values {
        encode::sequence((self.typ.encode(), encode::set(self.values)))
    }
}

impl Values for Attribute {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

#[derive(Clone)]
pub struct AttributeValue(Captured);

impl Debug for AttributeValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{}",
            hex::encode(self.0.clone().into_bytes().as_ref())
        ))
    }
}

impl AttributeValue {
    /// Construct a new instance from captured data.
    pub fn new(captured: Captured) -> Self {
        Self(captured)
    }

    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        let captured = cons.capture(|cons| {
            cons.skip_opt(|_, _, _| Ok(()))?;
            Ok(())
        })?;

        if captured.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Self(captured)))
        }
    }
}

impl Values for AttributeValue {
    fn encoded_len(&self, mode: Mode) -> usize {
        crate::CapturedValues(&self.0).encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        crate::CapturedValues(&self.0).write_encoded(mode, target)
    }
}

impl Deref for AttributeValue {
    type Target = Captured;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AttributeValue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialEq for AttributeValue {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for AttributeValue {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_parser_preserves_multiple_values() {
        let der = [
            0x30, 0x0c, 0x06, 0x02, 0x2a, 0x03, 0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01,
            0x02,
        ];
        let attribute = Constructed::decode(der.as_slice(), Mode::Der, |cons| {
            Attribute::take_opt_from(cons)?.ok_or_else(|| cons.content_err("missing attribute"))
        })
        .unwrap();

        assert_eq!(attribute.values.len(), 2);
        assert_eq!(attribute.values[0].as_slice(), [0x02, 0x01, 0x01]);
        assert_eq!(attribute.values[1].as_slice(), [0x02, 0x01, 0x02]);
    }

    #[test]
    fn attribute_parser_rejects_empty_values() {
        let der = [0x30, 0x06, 0x06, 0x02, 0x2a, 0x03, 0x31, 0x00];

        assert!(Constructed::decode(der.as_slice(), Mode::Der, |cons| {
            Attribute::take_opt_from(cons)?.ok_or_else(|| cons.content_err("missing attribute"))
        })
        .is_err());
    }
}
