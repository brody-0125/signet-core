package work.brodykim.signet;

import com.fasterxml.jackson.databind.ObjectMapper;
import work.brodykim.signet.credential.CredentialSigner;
import work.brodykim.signet.credential.KeyPairManager;
import work.brodykim.signet.credential.Multibase;
import work.brodykim.signet.jsonld.CachedDocumentLoader;
import work.brodykim.signet.jsonld.JsonLdProcessor;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CredentialSignerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JsonLdProcessor jsonLdProcessor = new JsonLdProcessor(new CachedDocumentLoader());
    private final CredentialSigner signer = new CredentialSigner(objectMapper, jsonLdProcessor);

    @Test
    void shouldSignAndVerifyCredentialViaJws() {
        OctetKeyPair keyPair = KeyPairManager.generateEd25519KeyPair();
        Map<String, Object> credential = Map.of("type", "test", "name", "Test Badge");

        String jws = signer.signCredential(credential, keyPair);
        assertNotNull(jws);
        assertTrue(jws.contains("."));

        boolean valid = signer.verifyCredential(jws, keyPair.toPublicJWK());
        assertTrue(valid);
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldSignWithDataIntegrityProofUsingRdfc10() {
        OctetKeyPair keyPair = KeyPairManager.generateEd25519KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = signer.signWithDataIntegrity(
                credential, keyPair, "https://example.com/issuers/1#key-1");

        // Verify proof structure
        assertTrue(signed.containsKey("proof"));
        Map<String, Object> proof = (Map<String, Object>) signed.get("proof");
        assertEquals("DataIntegrityProof", proof.get("type"));
        assertEquals("eddsa-rdfc-2022", proof.get("cryptosuite"));
        assertEquals("assertionMethod", proof.get("proofPurpose"));
        assertEquals("https://example.com/issuers/1#key-1", proof.get("verificationMethod"));
        assertNotNull(proof.get("created"));

        // Verify proofValue is multibase base58btc (starts with 'z')
        String proofValue = (String) proof.get("proofValue");
        assertNotNull(proofValue);
        assertTrue(proofValue.startsWith("z"), "proofValue must be multibase base58btc (prefix 'z'), got: " + proofValue);
        assertTrue(proofValue.length() > 60, "proofValue should encode a 64-byte Ed25519 signature");
    }

    @Test
    void shouldVerifyDataIntegrityProofWithRdfc10() {
        OctetKeyPair keyPair = KeyPairManager.generateEd25519KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = signer.signWithDataIntegrity(
                credential, keyPair, "https://example.com/issuers/1#key-1");

        boolean valid = signer.verifyDataIntegrity(signed, keyPair.toPublicJWK());
        assertTrue(valid, "Should verify a credential signed with RDFC-1.0 DataIntegrity proof");
    }

    @Test
    void shouldFailDataIntegrityVerificationWithWrongKey() {
        OctetKeyPair keyPair1 = KeyPairManager.generateEd25519KeyPair();
        OctetKeyPair keyPair2 = KeyPairManager.generateEd25519KeyPair();

        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = signer.signWithDataIntegrity(
                credential, keyPair1, "https://example.com/issuers/1#key-1");

        boolean valid = signer.verifyDataIntegrity(signed, keyPair2.toPublicJWK());
        assertFalse(valid, "Should fail verification with a different key");
    }

    @Test
    void shouldFailDataIntegrityVerificationWithTamperedDocument() {
        OctetKeyPair keyPair = KeyPairManager.generateEd25519KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = signer.signWithDataIntegrity(
                credential, keyPair, "https://example.com/issuers/1#key-1");

        // Tamper with the document
        Map<String, Object> tampered = new LinkedHashMap<>(signed);
        tampered.put("name", "Tampered");

        boolean valid = signer.verifyDataIntegrity(tampered, keyPair.toPublicJWK());
        assertFalse(valid, "Should fail verification when document is tampered");
    }

    @Test
    void shouldFailJwsVerificationWithWrongKey() {
        OctetKeyPair keyPair1 = KeyPairManager.generateEd25519KeyPair();
        OctetKeyPair keyPair2 = KeyPairManager.generateEd25519KeyPair();
        Map<String, Object> credential = Map.of("type", "test");

        String jws = signer.signCredential(credential, keyPair1);
        boolean valid = signer.verifyCredential(jws, keyPair2.toPublicJWK());
        assertFalse(valid);
    }

    // ── ECDSA P-256 DataIntegrity (ecdsa-rdfc-2022) tests ───────────────────

    @Test
    @SuppressWarnings("unchecked")
    void shouldSignWithEcdsaDataIntegrityProof() {
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = signer.signWithEcdsaDataIntegrity(
                credential, keyPair, "https://example.com/issuers/1#key-1");

        assertTrue(signed.containsKey("proof"));
        Map<String, Object> proof = (Map<String, Object>) signed.get("proof");
        assertEquals("DataIntegrityProof", proof.get("type"));
        assertEquals("ecdsa-rdfc-2022", proof.get("cryptosuite"));
        assertEquals("assertionMethod", proof.get("proofPurpose"));
        assertEquals("https://example.com/issuers/1#key-1", proof.get("verificationMethod"));
        assertNotNull(proof.get("created"));

        String proofValue = (String) proof.get("proofValue");
        assertNotNull(proofValue);
        assertTrue(proofValue.startsWith("z"), "proofValue must be multibase base58btc");
    }

    @Test
    void shouldVerifyEcdsaDataIntegrityProof() {
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = signer.signWithEcdsaDataIntegrity(
                credential, keyPair, "https://example.com/issuers/1#key-1");

        boolean valid = signer.verifyEcdsaDataIntegrity(signed, keyPair.toPublicJWK());
        assertTrue(valid, "Should verify ECDSA-signed credential");
    }

    @Test
    void shouldFailEcdsaVerificationWithWrongKey() {
        ECKey keyPair1 = KeyPairManager.generateP256KeyPair();
        ECKey keyPair2 = KeyPairManager.generateP256KeyPair();

        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = signer.signWithEcdsaDataIntegrity(
                credential, keyPair1, "https://example.com/issuers/1#key-1");

        boolean valid = signer.verifyEcdsaDataIntegrity(signed, keyPair2.toPublicJWK());
        assertFalse(valid, "Should fail ECDSA verification with a different key");
    }

    @Test
    void shouldFailEcdsaVerificationWithTamperedDocument() {
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = signer.signWithEcdsaDataIntegrity(
                credential, keyPair, "https://example.com/issuers/1#key-1");

        Map<String, Object> tampered = new LinkedHashMap<>(signed);
        tampered.put("name", "Tampered");

        boolean valid = signer.verifyEcdsaDataIntegrity(tampered, keyPair.toPublicJWK());
        assertFalse(valid, "Should fail ECDSA verification when document is tampered");
    }

    // ── ECDSA signature malleability (low-S enforcement) regression tests ───

    /** P-256 curve order n. */
    private static final BigInteger P256_N = new BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private static final BigInteger P256_HALF_N = P256_N.shiftRight(1);

    @Test
    @SuppressWarnings("unchecked")
    void ecdsaSignaturesShouldAlwaysBeInLowSForm() {
        // Regression: JDK SunEC produces high-S signatures roughly half the time.
        // After our normalization, every signature must have s <= n/2. Run many
        // iterations so the probability of missing a high-S path is negligible.
        ECKey keyPair = KeyPairManager.generateP256KeyPair();

        for (int i = 0; i < 50; i++) {
            Map<String, Object> credential = buildSampleCredential();
            credential.put("id", "https://example.com/cred/" + i);

            Map<String, Object> signed = signer.signWithEcdsaDataIntegrity(
                    credential, keyPair, "https://example.com/issuers/1#key-1");

            Map<String, Object> proof = (Map<String, Object>) signed.get("proof");
            String proofValue = (String) proof.get("proofValue");
            byte[] sig = Multibase.decodeBase58Btc(proofValue);
            assertEquals(64, sig.length, "P-256 P1363 signature must be 64 bytes");

            BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
            assertTrue(s.compareTo(P256_HALF_N) <= 0,
                    "s must be <= n/2 (low-S canonical form) on iteration " + i
                            + ", got s=" + s.toString(16));
            assertTrue(s.signum() > 0, "s must be positive");
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void ecdsaVerificationShouldRejectMalleableHighSVariant() {
        // Malleability attack: given a valid signature (r, s), compute (r, n-s).
        // Without low-S enforcement, this would also verify — allowing the same
        // credential to be represented by two distinct proofValues, breaking
        // revocation/tracking systems that key off the signature bytes.
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = signer.signWithEcdsaDataIntegrity(
                credential, keyPair, "https://example.com/issuers/1#key-1");

        // Sanity: the original signature verifies.
        assertTrue(signer.verifyEcdsaDataIntegrity(signed, keyPair.toPublicJWK()));

        // Forge the high-S twin by flipping s -> n - s.
        Map<String, Object> proof = new LinkedHashMap<>((Map<String, Object>) signed.get("proof"));
        byte[] origSig = Multibase.decodeBase58Btc((String) proof.get("proofValue"));
        byte[] forged = flipS(origSig, P256_N);

        // Preconditions: r is unchanged, s has actually been flipped to high-S.
        assertArrayEquals(Arrays.copyOfRange(origSig, 0, 32),
                Arrays.copyOfRange(forged, 0, 32),
                "forgery should leave r untouched");
        BigInteger forgedS = new BigInteger(1, Arrays.copyOfRange(forged, 32, 64));
        assertTrue(forgedS.compareTo(P256_HALF_N) > 0,
                "forged signature must be in high-S region to exercise malleability");

        proof.put("proofValue", Multibase.encodeBase58Btc(forged));
        Map<String, Object> tampered = new LinkedHashMap<>(signed);
        tampered.put("proof", proof);

        boolean valid = signer.verifyEcdsaDataIntegrity(tampered, keyPair.toPublicJWK());
        assertFalse(valid, "Verifier must reject the malleable high-S twin of a valid signature");
    }

    @Test
    @SuppressWarnings("unchecked")
    void ecdsaVerificationShouldRejectMalformedSignatureLength() {
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        Map<String, Object> credential = buildSampleCredential();

        Map<String, Object> signed = signer.signWithEcdsaDataIntegrity(
                credential, keyPair, "https://example.com/issuers/1#key-1");

        Map<String, Object> proof = new LinkedHashMap<>((Map<String, Object>) signed.get("proof"));
        // Truncate the signature to an invalid length.
        byte[] origSig = Multibase.decodeBase58Btc((String) proof.get("proofValue"));
        byte[] truncated = Arrays.copyOfRange(origSig, 0, 32);
        proof.put("proofValue", Multibase.encodeBase58Btc(truncated));

        Map<String, Object> tampered = new LinkedHashMap<>(signed);
        tampered.put("proof", proof);

        assertFalse(signer.verifyEcdsaDataIntegrity(tampered, keyPair.toPublicJWK()),
                "Verifier must reject signatures that are not 64 bytes");
    }

    /** Flip s to n - s in an IEEE P1363 (r || s) signature, keeping r intact. */
    private static byte[] flipS(byte[] p1363, BigInteger n) {
        int half = p1363.length / 2;
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(p1363, half, p1363.length));
        BigInteger sPrime = n.subtract(s);
        byte[] sBytes = sPrime.toByteArray();
        byte[] out = p1363.clone();
        Arrays.fill(out, half, out.length, (byte) 0);
        // Right-align sBytes into the s region, stripping any BigInteger sign byte.
        if (sBytes.length > half) {
            System.arraycopy(sBytes, sBytes.length - half, out, half, half);
        } else {
            System.arraycopy(sBytes, 0, out, half + (half - sBytes.length), sBytes.length);
        }
        return out;
    }

    // ── Helper ──────────────────────────────────────────────────────────────

    private Map<String, Object> buildSampleCredential() {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", List.of("https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"));
        credential.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        credential.put("id", "https://example.com/cred/1");
        credential.put("issuer", Map.of("id", "https://example.com/issuers/1", "type", "Profile", "name", "Test"));
        credential.put("validFrom", "2026-01-01T00:00:00Z");
        credential.put("name", "Test Badge");
        return credential;
    }
}
