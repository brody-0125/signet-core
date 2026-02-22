package work.brodykim.signet;

import com.fasterxml.jackson.databind.ObjectMapper;
import work.brodykim.signet.credential.CredentialSigner;
import work.brodykim.signet.credential.KeyPairManager;
import work.brodykim.signet.jsonld.CachedDocumentLoader;
import work.brodykim.signet.jsonld.JsonLdProcessor;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import org.junit.jupiter.api.Test;

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
