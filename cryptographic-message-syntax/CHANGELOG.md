# `cryptographic-message-syntax` History

<!-- next-header -->

## Unreleased

Released on ReleaseDate.

* Migrated cryptographic operations from `ring` to the RustCrypto-backed
  `x509-certificate` APIs.
* Upgraded `signature` 2 -> 3, `pem` 3 -> 4, `rand` 0.8 -> 0.10,
  `reqwest` 0.12 -> 0.13, and `bytes` 1.8 -> 1.12. Replaced `chrono` with
  Jiff; parsed CMS signing times now use `jiff::Timestamp`.
* Raised the MSRV from Rust 1.85 to 1.86. Basic CMS signing and verification no
  longer pull HTTP client dependencies when the `http` feature is disabled.
* Added combined verification APIs that verify signatures together with signed
  content type and message digest attributes. Digest comparisons are constant
  time, duplicate attributes are rejected, and signer certificates now require
  exact issuer-and-serial or subject-key-identifier matching. Detached content
  must be supplied explicitly instead of being silently treated as empty.
* Enforced CMS `SignedData`/`SignerInfo` version rules, declared digest
  algorithms, RFC-required signature/digest pairings (including Ed25519/SHA-512
  and P-384/SHA-384), mandatory signed attributes for non-`id-data` content, and
  canonical DER signed-attribute sets. Builders reject signing-key/certificate
  mismatches, empty attribute value sets, and contradictory digest content, and
  sort all generated SET OF values.
* Corrected the explicit `[0]` wrapper on generic `ContentInfo`, added complete
  subject-key-identifier signer support, and made unsupported ASN.1 encodings
  return errors rather than panic or silently omit data.
* Corrected Time-Stamp Protocol ASN.1 tags, defaults, failure bits, accuracy
  constraints, content type, message-imprint binding, response/token status
  consistency, and nonce generation (now 128 random bits).
* Hardened the HTTP timestamp client with timeouts, a response-size limit,
  response content-type validation, nonce/policy/imprint checks, CMS signature
  verification, ESS certificate binding, timestamping-only EKU enforcement, and
  TSA certificate validity checks at token generation time.
* Timestamp verification still does not validate TSA chains, trust anchors, or
  revocation; callers must provide that PKI validation.
* Live external timestamp-service tests are now ignored by default so the test
  suite is hermetic.

## 0.28.0

Released on 2025-08-17.

* MSRV 1.75 -> 1.85.
* Rust edition 2021 -> 2024.

## 0.27.0

Released on 2024-11-02.

* MSRV 1.65 -> 1.75.
* The crate now has an `http` feature to control availability of features making
  HTTP requests (notably time-stamp protocol support). Disabling the feature
  removes the dependency on `reqwest`, which slims down the dependency tree
  significantly. (#21)
* `bytes` 1.5 -> 1.8.
* `reqwest` 0.11 -> 0.12.
* `signature` 2.1 -> 2.2.

## 0.26.0

Released on 2023-11-07.

## 0.25.1

Released on 2023-11-05.

* `SignedDataBuilder` now stores a signing time and uses it for all signatures.
  Before, each signer would compute the current time and use that time, possibly
  resulting in signatures having slightly different times. The signing time
  is computed at `SignedDataBuilder` construction time. A `signing_time()`
  method can be used to pass a custom time to use for signing.

## 0.25.0

Released on 2023-11-03.

* `pem` 2.0 -> 3.0.
* `ring` 0.16 -> 0.17.

## 0.24.0

Released on 2023-07-24.

* `TimeStampResponse` is now exported in the public API.
* `TimeStampResponse` now implements `From<TimeStampResp>`.
* New method `SignedDataBuilder::build_signed_data()` has been extracted from
  `SignedDataBuilder::build_der()` and returns a `SignedData` instance,
  allowing access to a Rust struct representation before serialization.
* `SignedAttributes` are now sorted by taking the serialization of the
  entire `Attribute` (OID type + values). The previous implementation only
  encoded the `Attribute`'s `attrValues` field and would not yield correct
  sorting if the `attrType` OID was different. (#16)

## 0.23.0

Released on 2023-06-03.

* pem upgraded 1.1 -> 2.0.
* ``chrono`` compiled without default features (#12).

## 0.22.0

Released on 2023-03-19.

* `SignerBuilder` gained a `new_with_signer_identifier()` that allows constructing
  from a `SignerIdentifier` instead of a `CapturedX509Certificate`. This API allows
  usage in alternate signing scenarios, such as those found in RFC 5272. Contributed
  by Outurnate in #8.
* bytes upgraded 1.3 -> 1.4.
* Minimum Rust version 1.61 -> 1.65.

## 0.21.0

Released on 2023-01-21.

* signature upgraded 1.6 -> 2.0.

## 0.20.0

Released on 2022-12-30.

* bytes upgraded 1.0 -> 1.3.
* pem upgraded 1.0 -> 1.1.
* signature upgraded 1.3 -> 1.6.

## 0.19.0

Released on 2022-12-19.

* Canonical home of project moved to https://github.com/indygreg/cryptography-rs.
* Cargo.toml now defines patch versions of all dependencies.

## 0.18.0

(Released 2022-09-17)

## 0.17.0

(Released 2022-08-07)

* bcder crate upgraded from 0.6.1 to 0.7.0. This entailed a lot of
  changes, mainly to error handling.
* `SignedAttributes` should now be sorted properly. Previous versions
  had a sorting mechanism that was only partially correct and would
  result in incorrect sorting for some inputs. The old behavior could
  have resulted in incorrect signatures being produced or validations
  incorrectly failing. (#614)
* The crate now re-exports some symbols for 3rd party crates
  `bcder::Oid` and `bytes::Bytes`.
* Support for creating *external signatures*, which are signatures
  over external content not stored inline in produced signatures.
  (#614)
* (API change) `SignedDataBuilder::signed_content()` has effectively
  been renamed to `content_inline()`. (#614)
