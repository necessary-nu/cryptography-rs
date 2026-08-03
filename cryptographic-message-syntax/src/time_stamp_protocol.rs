// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Time-Stamp Protocol (TSP) / RFC 3161 client.

use {
    crate::asn1::{
        rfc3161::{
            MessageImprint, PkiStatus, TimeStampReq, TimeStampResp, TstInfo,
            OID_CONTENT_TYPE_TST_INFO,
        },
        rfc5652::{SignedData, OID_ID_SIGNED_DATA},
    },
    bcder::{
        decode::{Constructed, DecodeError, IntoSource, Source},
        encode::Values,
        Integer, OctetString,
    },
    rand::{TryRng, rngs::SysRng},
    reqwest::IntoUrl,
    std::{convert::Infallible, io::Read, ops::Deref, time::Duration},
    subtle::ConstantTimeEq,
    x509_certificate::DigestAlgorithm,
};

pub const HTTP_CONTENT_TYPE_REQUEST: &str = "application/timestamp-query";

pub const HTTP_CONTENT_TYPE_RESPONSE: &str = "application/timestamp-reply";

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum TimeStampError {
    Io(std::io::Error),
    Reqwest(reqwest::Error),
    Asn1Decode(DecodeError<Infallible>),
    Http(&'static str),
    Random,
    NonceMismatch,
    MessageImprintMismatch,
    PolicyMismatch,
    InvalidMessageImprint,
    ResponseTooLarge,
    Unsuccessful(TimeStampResp),
    BadResponse,
}

impl std::fmt::Display for TimeStampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => f.write_fmt(format_args!("I/O error: {}", e)),
            Self::Reqwest(e) => f.write_fmt(format_args!("HTTP error: {}", e)),
            Self::Asn1Decode(e) => f.write_fmt(format_args!("ASN.1 decode error: {}", e)),
            Self::Http(msg) => f.write_str(msg),
            Self::Random => f.write_str("error generating random nonce"),
            Self::NonceMismatch => f.write_str("nonce mismatch"),
            Self::MessageImprintMismatch => f.write_str("message imprint mismatch"),
            Self::PolicyMismatch => f.write_str("time-stamp policy mismatch"),
            Self::InvalidMessageImprint => f.write_str("invalid time-stamp message imprint"),
            Self::ResponseTooLarge => f.write_str("time-stamp response is too large"),
            Self::Unsuccessful(r) => f.write_fmt(format_args!(
                "unsuccessful Time-Stamp Protocol response: {:?}: {:?}",
                r.status.status, r.status.status_string
            )),
            Self::BadResponse => f.write_str("bad server response"),
        }
    }
}

fn validate_message_imprint(
    imprint: &MessageImprint,
) -> Result<DigestAlgorithm, TimeStampError> {
    let algorithm = DigestAlgorithm::try_from(&imprint.hash_algorithm)
        .map_err(|_| TimeStampError::InvalidMessageImprint)?;
    let expected_length = algorithm.digest_data(&[]).len();

    if imprint.hashed_message.to_bytes().len() == expected_length {
        Ok(algorithm)
    } else {
        Err(TimeStampError::InvalidMessageImprint)
    }
}

impl std::error::Error for TimeStampError {}

impl From<std::io::Error> for TimeStampError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<reqwest::Error> for TimeStampError {
    fn from(e: reqwest::Error) -> Self {
        Self::Reqwest(e)
    }
}

impl From<DecodeError<Infallible>> for TimeStampError {
    fn from(e: DecodeError<Infallible>) -> Self {
        Self::Asn1Decode(e)
    }
}

/// High-level interface to [TimeStampResp].
///
/// This type provides a high-level interface to the low-level ASN.1 response
/// type from a Time-Stamp Protocol request.
pub struct TimeStampResponse(TimeStampResp);

impl Deref for TimeStampResponse {
    type Target = TimeStampResp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TimeStampResponse {
    /// Whether the time stamp request was successful.
    pub fn is_success(&self) -> bool {
        matches!(
            self.0.status.status,
            PkiStatus::Granted | PkiStatus::GrantedWithMods
        )
    }

    /// Obtain the size of the time-stamp token data.
    pub fn token_content_size(&self) -> Option<usize> {
        self.0
            .time_stamp_token
            .as_ref()
            .map(|token| token.content.len())
    }

    /// Decode the `SignedData` value in the response.
    pub fn signed_data(&self) -> Result<Option<SignedData>, DecodeError<Infallible>> {
        if let Some(token) = &self.0.time_stamp_token {
            let source = token.content.clone();

            if token.content_type == OID_ID_SIGNED_DATA {
                Ok(Some(source.decode(SignedData::take_from)?))
            } else {
                Err(source
                    .into_source()
                    .content_err("invalid OID on signed data"))
            }
        } else {
            Ok(None)
        }
    }

    pub fn tst_info(&self) -> Result<Option<TstInfo>, DecodeError<Infallible>> {
        match self.signed_data()? { Some(signed_data)
            if signed_data.content_info.content_type == OID_CONTENT_TYPE_TST_INFO => {
                if let Some(content) = signed_data.content_info.content {
                    Ok(Some(Constructed::decode(
                        content.to_bytes(),
                        bcder::Mode::Der,
                        TstInfo::take_from,
                    )?))
                } else {
                    Ok(None)
                }
            } _ => {
            Ok(None)
        }}
    }
}

impl From<TimeStampResp> for TimeStampResponse {
    fn from(resp: TimeStampResp) -> Self {
        Self(resp)
    }
}

/// Send a [TimeStampReq] to a server via HTTP.
///
/// Successful responses are checked against the requested version, message
/// imprint, nonce, policy, and `certReq` value. When `certReq` is true, the
/// returned CMS signature, ESS certificate binding, timestamping-only EKU, and
/// certificate validity at generation time are also checked.
///
/// This does not validate the TSA certificate chain, trust anchor, or revocation
/// status. If `certReq` is false, the response contains no signer certificate and
/// this function cannot authenticate its CMS signature.
pub fn time_stamp_request_http(
    url: impl IntoUrl,
    request: &TimeStampReq,
) -> Result<TimeStampResponse, TimeStampError> {
    let request_digest_algorithm = validate_message_imprint(&request.message_imprint)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()?;

    let mut body = Vec::<u8>::new();
    request
        .encode_ref()
        .write_encoded(bcder::Mode::Der, &mut body)?;

    let response = client
        .post(url)
        .header("Content-Type", HTTP_CONTENT_TYPE_REQUEST)
        .body(body)
        .send()?;

    let content_type_is_valid = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(HTTP_CONTENT_TYPE_RESPONSE));

    if response.status().is_success() && content_type_is_valid {
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_SIZE)
        {
            return Err(TimeStampError::ResponseTooLarge);
        }

        let mut response_bytes = Vec::new();
        response
            .take(MAX_RESPONSE_SIZE + 1)
            .read_to_end(&mut response_bytes)?;
        if response_bytes.len() as u64 > MAX_RESPONSE_SIZE {
            return Err(TimeStampError::ResponseTooLarge);
        }

        let res = TimeStampResponse(Constructed::decode(
            response_bytes.as_slice(),
            bcder::Mode::Der,
            TimeStampResp::take_from,
        )?);

        if res.is_success() {
            let raw_signed_data = res.signed_data()?.ok_or(TimeStampError::BadResponse)?;
            let certificates_present = raw_signed_data.certificates.is_some();
            if request.cert_req.unwrap_or(false) != certificates_present {
                return Err(TimeStampError::BadResponse);
            }

            let tst_info = res.tst_info()?.ok_or(TimeStampError::BadResponse)?;

            if tst_info.version != Integer::from(1) {
                return Err(TimeStampError::BadResponse);
            }

            let wanted_imprint = request.message_imprint.hashed_message.to_bytes();
            let got_imprint = tst_info.message_imprint.hashed_message.to_bytes();
            let response_digest_algorithm = validate_message_imprint(&tst_info.message_imprint)?;
            if request_digest_algorithm != response_digest_algorithm
                || !bool::from(wanted_imprint.as_ref().ct_eq(got_imprint.as_ref()))
            {
                return Err(TimeStampError::MessageImprintMismatch);
            }

            if tst_info.nonce != request.nonce {
                return Err(TimeStampError::NonceMismatch);
            }

            if request
                .req_policy
                .as_ref()
                .is_some_and(|policy| policy != &tst_info.policy)
            {
                return Err(TimeStampError::PolicyMismatch);
            }

            if certificates_present {
                let parsed = crate::SignedData::try_from(&raw_signed_data)
                    .map_err(|_| TimeStampError::BadResponse)?;
                if parsed.signers().count() != 1 {
                    return Err(TimeStampError::BadResponse);
                }
                let signer = parsed.signers().next().ok_or(TimeStampError::BadResponse)?;
                signer
                    .verify_with_signed_data(&parsed)
                    .and_then(|_| signer.verify_time_stamp_signing_certificate(&parsed))
                    .map_err(|_| TimeStampError::BadResponse)?;
            }
        }

        Ok(res)
    } else {
        Err(TimeStampError::Http("bad HTTP response"))
    }
}

/// Send a Time-Stamp request for a given message to an HTTP URL.
///
/// This is a wrapper around [time_stamp_request_http] that constructs the low-level
/// ASN.1 request object with reasonable defaults and requests the TSA certificate,
/// allowing the response's cryptographic integrity to be checked. TSA certificate
/// trust, chain building, and revocation checking remain the caller's responsibility.
pub fn time_stamp_message_http(
    url: impl IntoUrl,
    message: &[u8],
    digest_algorithm: DigestAlgorithm,
) -> Result<TimeStampResponse, TimeStampError> {
    let mut h = digest_algorithm.digester();
    h.update(message);
    let digest = h.finish();

    let mut random = [0u8; 16];
    SysRng
        .try_fill_bytes(&mut random)
        .map_err(|_| TimeStampError::Random)?;

    let request = TimeStampReq {
        version: Integer::from(1),
        message_imprint: MessageImprint {
            hash_algorithm: digest_algorithm.into(),
            hashed_message: OctetString::new(bytes::Bytes::copy_from_slice(digest.as_ref())),
        },
        req_policy: None,
        nonce: Some(Integer::from(u128::from_le_bytes(random))),
        cert_req: Some(true),
        extensions: None,
    };

    time_stamp_request_http(url, &request)
}

#[cfg(test)]
mod test {
    use super::*;

    const DIGICERT_TIMESTAMP_URL: &str = "http://timestamp.digicert.com";

    #[test]
    fn malformed_message_imprint_length_is_rejected() {
        let imprint = MessageImprint {
            hash_algorithm: DigestAlgorithm::Sha256.into(),
            hashed_message: OctetString::new(bytes::Bytes::from_static(b"too short")),
        };

        assert!(matches!(
            validate_message_imprint(&imprint),
            Err(TimeStampError::InvalidMessageImprint)
        ));
    }

    #[test]
    fn verify_static() {
        let signed_data =
            crate::SignedData::parse_ber(include_bytes!("testdata/tsp-signed-data.der")).unwrap();

        for signer in signed_data.signers() {
            signer.verify_with_signed_data(&signed_data).unwrap();
            signer
                .verify_time_stamp_signing_certificate(&signed_data)
                .unwrap();
        }
    }

    #[test]
    #[ignore = "requires a live external time-stamp service"]
    fn simple_request() {
        let message = b"hello, world";

        let res = time_stamp_message_http(DIGICERT_TIMESTAMP_URL, message, DigestAlgorithm::Sha256)
            .unwrap();

        let signed_data = res.signed_data().unwrap().unwrap();
        assert_eq!(
            signed_data.content_info.content_type,
            OID_CONTENT_TYPE_TST_INFO
        );
        let tst_info = res.tst_info().unwrap().unwrap();
        assert_eq!(tst_info.version, Integer::from(1));

        let parsed = crate::SignedData::try_from(&signed_data).unwrap();
        for signer in parsed.signers() {
            signer
                .verify_message_digest_with_signed_data(&parsed)
                .unwrap();
            signer.verify_signature_with_signed_data(&parsed).unwrap();
        }
    }
}
