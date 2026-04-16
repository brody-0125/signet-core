# Changelog

All notable changes to `signet-core` are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 — April 16, 2026

### Selective Disclosure (`ecdsa-sd-2023`) — full holder/verifier lifecycle
- New `SelectiveDisclosure.deriveProof(...)` — holder-side step that strips the
  issuer HMAC key from the presented proof and emits a derived proof
  (CBOR tag `0xd9 0x5d 0x01`) carrying `baseSignature`, `publicKey`,
  per-quad signatures, a `c14n → HMAC` `labelMap`, and `mandatoryIndexes`.
- New `SelectiveDisclosure.verifyDerivedProof(...)` — verifier-side
  reconstruction of the signed canonical form via `labelMap`; no HMAC key
  required.
- Base proof CBOR header corrected to `0xd9 0x5d 0x00` and `proofValue`
  multibase prefix corrected to `u` (base64url-no-pad) per W3C
  VC-DI-ECDSA §3.5.2 / §3.5.3. `eddsa-rdfc-2022` and `ecdsa-rdfc-2022`
  retain `z` (base58btc).

### Security hardening
- ECDSA P-256 signatures are now normalized to **low-S** on sign and
  rejected as malformed on verify, closing a signature-malleability path
  where `(r, s)` and `(r, n − s)` both verified for the same message.
  Affects `signEcdsaP256Raw` and `SelectiveDisclosure.signEcdsaP256`.
- Defensive **key material zeroization**: Ed25519 seed bytes, P-256
  private keys, and the `ecdsa-sd-2023` HMAC-SHA256 key are now wiped
  via `try-finally` after use, reducing exposure in heap dumps, core
  dumps, and swap.

### JSON-LD canonicalization
- `JsonLdProcessor` applies **Unicode NFC** at the ingress boundary to
  string literals and map keys, so composed/decomposed forms canonicalize
  identically. Numeric type handling widened to `Short`, `Byte`, `Float`,
  `BigDecimal`, `BigInteger`; unknown types now fail loudly.
- Added W3C `rdf-canon` conformance tests (vectors 001–006, 017, 020,
  021, 043, 053, 054, 076) covering blank-node relabeling, graph
  isomorphism, RDF collections, and language-tagged literals.

### Build & CI
- Added GitHub Actions workflow (`.github/workflows/ci.yml`) running
  `./gradlew build` on every push and pull request with Temurin JDK 17,
  Gradle wrapper caching, and a concurrency group that cancels superseded
  runs on the same ref.
