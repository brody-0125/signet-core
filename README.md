# Signet Core

Framework-agnostic Java library for building, signing, and validating [Open Badges 3.0](https://www.imsglobal.org/spec/ob/v3p0) Verifiable Credentials.

## Overview

Signet Core provides the foundational primitives for the Open Badges 3.0 ecosystem:

- **Credential Building** — Construct W3C Verifiable Credentials compliant with the OB 3.0 data model
- **Cryptographic Signing** — Sign and verify credentials using JWS (VC-JWT), DataIntegrity EdDSA (eddsa-rdfc-2022), DataIntegrity ECDSA (ecdsa-rdfc-2022), and Selective Disclosure (ecdsa-sd-2023)
- **Key Management** — Generate, serialize, and convert Ed25519 and P-256 key pairs with Multikey encoding
- **JSON-LD Processing** — RDFC-1.0 (URDNA2015) canonicalization and W3C VC safe mode validation
- **Structural Validation** — Validate OB 3.0 credential structure and JSON-LD context integrity

This module has **zero Spring dependencies** and can be used in any Java 17+ application.

## Installation

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("work.brodykim:signet-core:0.1.0")
}
```

### Gradle (Groovy DSL)

```groovy
dependencies {
    implementation 'work.brodykim:signet-core:0.1.0'
}
```

## Quick Start

### 1. Build a Credential

```java
import work.brodykim.signet.core.*;
import work.brodykim.signet.credential.*;

// Define issuer and achievement
var issuer = new BadgeIssuer(
    UUID.randomUUID(), "My Organization",
    "https://example.com", "badges@example.com", "An example issuer"
);

var achievement = new BadgeAchievement(
    UUID.randomUUID(), "Java Proficiency",
    "Demonstrated proficiency in Java programming",
    "Passed the Java certification exam",
    "https://example.com/criteria",
    "Achievement", "https://example.com/badge.png",
    List.of("java", "programming"), List.of()
);

// Build the credential
var builder = new CredentialBuilder("https://example.com", "my-salt");
var request = CredentialRequest.builder(
        UUID.randomUUID(), "recipient@example.com", achievement, issuer)
    .recipientName("Jane Doe")
    .build();

Map<String, Object> credential = builder.buildCredential(request);
```

### 2. Sign with Data Integrity (EdDSA)

```java
import work.brodykim.signet.credential.*;

// Generate or load a key pair
var keyPair = KeyPairManager.generateEd25519KeyPair();
var serialized = KeyPairManager.serializeKeyPair(keyPair);
var multibase = KeyPairManager.toPublicKeyMultibase(keyPair);

// Sign
var signer = new CredentialSigner();
Map<String, Object> signed = signer.signWithDataIntegrity(
    credential, keyPair,
    "https://example.com/issuers/1#key-1"
);

// Verify
boolean valid = signer.verifyDataIntegrity(signed, keyPair.toPublicJWK());
```

### 3. Sign as JWS (VC-JWT)

```java
String jws = signer.signCredential(credential, keyPair);
boolean valid = signer.verifyCredential(jws, keyPair.toPublicJWK());
```

### 4. Validate Credential Structure

```java
import work.brodykim.signet.core.OpenBadgesValidator;

var validator = new OpenBadgesValidator();
var result = validator.validate(credential);

if (!result.valid()) {
    System.err.println("Validation errors: " + result.errors());
}
```

## Package Structure

| Package | Description |
|---------|-------------|
| `work.brodykim.signet.core` | OB 3.0 data model records (`BadgeAchievement`, `BadgeIssuer`, etc.), `OpenBadgesValidator`, JSON-LD context constants |
| `work.brodykim.signet.credential` | `CredentialBuilder`, `CredentialSigner`, `KeyPairManager`, `SelectiveDisclosure`, multibase/CBOR utilities |
| `work.brodykim.signet.jsonld` | `JsonLdProcessor` (RDFC-1.0 canonicalization), `CachedDocumentLoader` (context caching) |

## Supported Proof Mechanisms

| Proof Type | Algorithm | Method |
|------------|-----------|--------|
| JWS (VC-JWT) | Ed25519 | `CredentialSigner.signCredential()` |
| DataIntegrity | eddsa-rdfc-2022 | `CredentialSigner.signWithDataIntegrity()` |
| DataIntegrity | ecdsa-rdfc-2022 (P-256) | `CredentialSigner.signWithEcdsaDataIntegrity()` |
| Selective Disclosure | ecdsa-sd-2023 (P-256) | `SelectiveDisclosure.createBaseProof()` |

## Supported Key Types

| Key Type | Curve | Generation | Multikey Encoding |
|----------|-------|------------|-------------------|
| Ed25519 | Ed25519 | `KeyPairManager.generateEd25519KeyPair()` | `z6Mk...` prefix |
| ECDSA | P-256 (secp256r1) | `KeyPairManager.generateP256KeyPair()` | `zDna...` prefix |

## Bundled JSON-LD Contexts

The `CachedDocumentLoader` ships with pre-bundled contexts to avoid network fetches:

- `https://www.w3.org/ns/credentials/v2` — W3C VC Data Model 2.0
- `https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json` — Open Badges 3.0

## Requirements

- Java 17+
- No Spring or framework dependencies

## Specification Compliance

This library implements the following specifications:

- [Open Badges Specification v3.0](https://www.imsglobal.org/spec/ob/v3p0) by 1EdTech Consortium
- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Data Integrity EdDSA Cryptosuites v1.0](https://www.w3.org/TR/vc-di-eddsa/)
- [W3C Data Integrity ECDSA Cryptosuites v1.0](https://www.w3.org/TR/vc-di-ecdsa/)
- [RDF Dataset Canonicalization (RDFC-1.0)](https://www.w3.org/TR/rdf-canon/)

> **Note:** This implementation is not certified by 1EdTech. See the [NOTICE](NOTICE) file for full compliance details.

## License

Licensed under the [Apache License 2.0](../LICENSE).
