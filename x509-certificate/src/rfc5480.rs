// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ASN.1 primitives defined by RFC 5480.

use bcder::{
    decode::{Constructed, DecodeError, Source},
    encode::{PrimitiveContent, Values},
    Oid, Tag,
};

/// Elliptic curve parameters.
///
/// ```ASN.1
/// ECParameters ::= CHOICE {
///   namedCurve         OBJECT IDENTIFIER
///   -- implicitCurve   NULL
///   -- specifiedCurve  SpecifiedECDomain
///  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EcParameters {
    NamedCurve(Oid),
    ImplicitCurve,
    // TODO implement SpecifiedECDomain
    SpecifiedCurve,
}

impl EcParameters {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        match Oid::take_opt_from(cons)? { Some(oid) => {
            Ok(Self::NamedCurve(oid))
        } _ => {
            let null_value = cons.take_opt_primitive_if(Tag::NULL, |cons| {
                cons.take_all()?;
                Ok(())
            })?;

            if null_value.is_some() {
                Ok(Self::ImplicitCurve)
            } else {
                Err(cons.content_err("parsing of SpecifiecECDomain not implemented"))
            }
        }}
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        match self {
            Self::NamedCurve(oid) => (Some(oid.encode_ref_as(tag)), None, None),
            Self::ImplicitCurve => (None, Some(().encode_as(tag)), None),
            Self::SpecifiedCurve => (
                None,
                None,
                Some(crate::UnsupportedEncoder(
                    "SpecifiedECDomain encoding is not implemented",
                )),
            ),
        }
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        match self {
            Self::NamedCurve(oid) => (Some(oid.encode_ref()), None, None),
            Self::ImplicitCurve => (None, Some(().encode()), None),
            Self::SpecifiedCurve => (
                None,
                None,
                Some(crate::UnsupportedEncoder(
                    "SpecifiedECDomain encoding is not implemented",
                )),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, bcder::Mode};

    #[test]
    fn unsupported_specified_curve_returns_an_encoding_error() {
        let mut encoded = Vec::new();
        assert!(
            EcParameters::SpecifiedCurve
                .encode_ref()
                .write_encoded(Mode::Der, &mut encoded)
                .is_err()
        );
    }
}
