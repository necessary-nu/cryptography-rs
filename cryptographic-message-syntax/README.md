# cryptographic-message-syntax

`cryptographic-message-syntax` is a pure Rust implementation of
Cryptographic Message Syntax (CMS) as defined by RFC 5652. Also included
is Time-Stamp Protocol (TSP) (RFC 3161) client support.

From a high level CMS defines a way to digitally sign and authenticate
arbitrary content.

This crate was originally developed to support code signing on Apple
platforms. (See the `apple-codesign` Rust crate.) However, it is a
generic library crate. But some historical decisions from its original
may remain.

This crate verifies CMS integrity but does not establish certificate or TSA
trust. It has not received a formal independent security audit, and its ASN.1
parser has no general resource limits. See the security limitations in
`src/lib.rs` before using it with untrusted signatures.
