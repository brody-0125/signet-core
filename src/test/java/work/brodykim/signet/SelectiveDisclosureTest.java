package work.brodykim.signet;

import work.brodykim.signet.credential.KeyPairManager;
import work.brodykim.signet.credential.Multibase;
import work.brodykim.signet.credential.SelectiveDisclosure;
import work.brodykim.signet.jsonld.CachedDocumentLoader;
import work.brodykim.signet.jsonld.JsonLdProcessor;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SelectiveDisclosureTest {

    private final JsonLdProcessor jsonLdProcessor = new JsonLdProcessor(new CachedDocumentLoader());
    private final SelectiveDisclosure sd = new SelectiveDisclosure(jsonLdProcessor);

    @Test
    @SuppressWarnings("unchecked")
    void deriveProofProducesEcdsaSd2023DerivedProofShape() {
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = sd.createBaseProof(
                credential, keyPair, "https://example.com/issuers/1#key-1",
                List.of("/issuer", "/validFrom"));

        Map<String, Object> derived = sd.deriveProof(signed);

        assertTrue(derived.containsKey("proof"));
        Map<String, Object> proof = (Map<String, Object>) derived.get("proof");
        assertEquals("DataIntegrityProof", proof.get("type"));
        assertEquals("ecdsa-sd-2023", proof.get("cryptosuite"));
        String proofValue = (String) proof.get("proofValue");
        assertNotNull(proofValue);
        assertTrue(proofValue.startsWith("z"), "proofValue must be multibase base58btc");

        // Derived proof uses CBOR tag 0xd9 0x5d 0x01 (vs. base proof's 0xd9 0x5d 0x02).
        // This tag is the wire-level marker that the HMAC key has been stripped.
        byte[] cbor = Multibase.decodeBase58Btc(proofValue);
        assertEquals((byte) 0xd9, cbor[0]);
        assertEquals((byte) 0x5d, cbor[1]);
        assertEquals((byte) 0x01, cbor[2], "Derived proof must use tag 0x5d01, not 0x5d02 (base)");
    }

    @Test
    @SuppressWarnings("unchecked")
    void derivedProofValueDoesNotContainHmacKeyBytes() {
        // This is the central security guarantee of the W3C ecdsa-sd-2023
        // derivation step. A leaked HMAC key lets any verifier brute-force
        // the small canonical-label space (`_:c14n0`, `_:c14n1`, ...) and
        // recover blank-node masking, then dictionary-attack each per-quad
        // signature to recover undisclosed claim values.
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = sd.createBaseProof(
                credential, keyPair, "https://example.com/issuers/1#key-1",
                List.of("/issuer", "/validFrom"));

        // Pull the HMAC key out of the base proof (it lives inside the CBOR
        // proofValue; structure: tag(3) + arrayHeader(1) + baseSig(2+64) +
        // pubKey(2+33) + hmacKey(2+32) + ...). We just need to verify the
        // 32-byte key bytes are absent from the derived proofValue, so we
        // locate them by scanning for any 32-byte byte-string in the base
        // proof that lies after the publicKey.
        Map<String, Object> baseProof = (Map<String, Object>) signed.get("proof");
        byte[] baseCbor = Multibase.decodeBase58Btc((String) baseProof.get("proofValue"));
        // Layout: 0xd9 0x5d 0x02 | 0x85 (array(5)) | 0x58 0x40 [64 bytes baseSig]
        //         | 0x58 0x21 [33 bytes pubKey] | 0x58 0x20 [32 bytes hmacKey] | ...
        int hmacKeyOffset = 3 + 1 + 2 + 64 + 2 + 33 + 2;
        byte[] hmacKey = new byte[32];
        System.arraycopy(baseCbor, hmacKeyOffset, hmacKey, 0, 32);

        Map<String, Object> derived = sd.deriveProof(signed);
        Map<String, Object> derivedProof = (Map<String, Object>) derived.get("proof");
        byte[] derivedCbor = Multibase.decodeBase58Btc((String) derivedProof.get("proofValue"));

        assertFalse(containsSubsequence(derivedCbor, hmacKey),
                "Derived proof must not embed the HMAC key bytes — that would let any "
                        + "verifier reverse blank-node masking and recover hidden claims.");
    }

    @Test
    void roundTripCreateBaseProofThenDeriveThenVerifySucceeds() {
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = sd.createBaseProof(
                credential, keyPair, "https://example.com/issuers/1#key-1",
                List.of("/issuer", "/validFrom"));

        Map<String, Object> derived = sd.deriveProof(signed);

        assertTrue(sd.verifyDerivedProof(derived),
                "A freshly derived proof must verify under the issuer's public key");
    }

    @Test
    @SuppressWarnings("unchecked")
    void verifyFailsWhenDocumentIsTamperedAfterDerivation() {
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = sd.createBaseProof(
                credential, keyPair, "https://example.com/issuers/1#key-1",
                List.of("/issuer", "/validFrom"));
        Map<String, Object> derived = sd.deriveProof(signed);

        // Tamper a mandatory claim (issuer name) — verification must reject.
        Map<String, Object> tampered = new LinkedHashMap<>(derived);
        Map<String, Object> tamperedIssuer = new LinkedHashMap<>(
                (Map<String, Object>) tampered.get("issuer"));
        tamperedIssuer.put("name", "Attacker");
        tampered.put("issuer", tamperedIssuer);

        assertFalse(sd.verifyDerivedProof(tampered),
                "Verification must fail when a disclosed claim is altered post-derivation");
    }

    @Test
    @SuppressWarnings("unchecked")
    void verifyFailsWhenSignatureBytesAreFlipped() {
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = sd.createBaseProof(
                credential, keyPair, "https://example.com/issuers/1#key-1",
                List.of("/issuer", "/validFrom"));
        Map<String, Object> derived = sd.deriveProof(signed);

        Map<String, Object> proof = (Map<String, Object>) derived.get("proof");
        byte[] cbor = Multibase.decodeBase58Btc((String) proof.get("proofValue"));
        // Flip a byte deep inside the CBOR (somewhere in the base signature).
        cbor[10] ^= (byte) 0xFF;
        proof.put("proofValue", Multibase.encodeBase58Btc(cbor));

        assertFalse(sd.verifyDerivedProof(derived),
                "Verification must fail when proofValue bytes are corrupted");
    }

    @Test
    void deriveProofIsDeterministicForFixedHmacKey() {
        // Sanity check: with a fixed base proof, derivation is a pure function
        // of the input. Two derivations of the same base proof must yield the
        // same proofValue (the labelMap and signatures depend only on the
        // canonicalization + the issuer's HMAC key).
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = sd.createBaseProof(
                credential, keyPair, "https://example.com/issuers/1#key-1",
                List.of("/issuer"));

        Map<String, Object> first = sd.deriveProof(signed);
        Map<String, Object> second = sd.deriveProof(signed);

        @SuppressWarnings("unchecked")
        String firstProofValue = (String) ((Map<String, Object>) first.get("proof")).get("proofValue");
        @SuppressWarnings("unchecked")
        String secondProofValue = (String) ((Map<String, Object>) second.get("proof")).get("proofValue");

        assertEquals(firstProofValue, secondProofValue);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static boolean containsSubsequence(byte[] haystack, byte[] needle) {
        if (needle.length == 0 || haystack.length < needle.length) return false;
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }

    private Map<String, Object> buildSampleCredential() {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", List.of(
                "https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"));
        credential.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        credential.put("id", "https://example.com/cred/1");
        credential.put("issuer", Map.of(
                "id", "https://example.com/issuers/1",
                "type", "Profile",
                "name", "Test Issuer"));
        credential.put("validFrom", "2026-01-01T00:00:00Z");
        credential.put("name", "Test Badge");
        return credential;
    }
}
