# Security policy

## Accepted advisory: RUSTSEC-2023-0071

The necessary.nu production code-signing deployment accepts
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
for the RustCrypto `rsa` dependency. Production RSA private keys and all RSA
private-key operations are confined to an HSM. The vulnerable software RSA
private-key operation is therefore not exposed by that deployment.

This exception is specific to that architecture. It does not cover a
network-observable service using `InMemorySigningKeyPair::Rsa`. Such a service
must use a hardened external signer, or assess and mitigate the advisory
independently.

The exception must be revisited if the HSM boundary changes or RustCrypto
publishes a fix.
