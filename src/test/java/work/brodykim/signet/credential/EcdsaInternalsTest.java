package work.brodykim.signet.credential;

import work.brodykim.signet.jsonld.CachedDocumentLoader;
import work.brodykim.signet.jsonld.JsonLdProcessor;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that need package-level access to low-level ECDSA helpers and the
 * CBOR-encoded ecdsa-sd-2023 proof value. Package is intentionally
 * {@code work.brodykim.signet.credential} to reach the package-private
 * {@code derToP1363}, {@code p1363ToDer}, and {@code P256_*} constants in
 * {@link CredentialSigner} without widening production visibility.
 */
class EcdsaInternalsTest {

    // CBOR layout emitted by CborEncoder.encodeBaseProofValue for a P-256 base proof:
    //   [0..2]  0xd9 0x5d 0x02   — ecdsa-sd-2023 base-proof tag
    //   [3]     0x85             — CBOR array(5) header
    //   [4..5]  0x58 0x40        — byte string, length 64
    //   [6..69] 64-byte base signature
    private static final int CBOR_BASE_SIG_OFFSET = 6;
    private static final int CBOR_BASE_SIG_END = CBOR_BASE_SIG_OFFSET + 64;

    private final JsonLdProcessor jsonLdProcessor = new JsonLdProcessor(new CachedDocumentLoader());
    private final SelectiveDisclosure selectiveDisclosure = new SelectiveDisclosure(jsonLdProcessor);

    // ── DER ⇄ P1363 round-trip coverage (exercises the DER fallback path) ──

    @Test
    void derToP1363RoundTripsForRealJdkDerSignature()
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
                   com.nimbusds.jose.JOSEException {
        // The JDK DER path in signEcdsaP256Raw/verifyEcdsaP256Raw is only reached
        // when SHA256withECDSAinP1363Format is absent. Modern JDKs always ship
        // it, so the fallback is effectively never exercised at runtime. Test
        // the conversion directly against a real DER signature produced by the
        // JDK so a regression in derToP1363/p1363ToDer would still be caught.
        ECKey jwk = KeyPairManager.generateP256KeyPair();
        ECPrivateKey privateKey = jwk.toECPrivateKey();

        byte[] data = "payload under test".getBytes();
        Signature sig = Signature.getInstance(CredentialSigner.ALGO_ECDSA_DER);
        sig.initSign(privateKey);
        sig.update(data);
        byte[] derSig = sig.sign();

        byte[] p1363 = CredentialSigner.derToP1363(derSig, CredentialSigner.P256_COMPONENT_LEN);
        assertEquals(64, p1363.length, "P-256 P1363 must be 64 bytes");

        byte[] derAgain = CredentialSigner.p1363ToDer(p1363);

        // Verifier must accept either form for the same (key, data).
        Signature verifyDer = Signature.getInstance(CredentialSigner.ALGO_ECDSA_DER);
        verifyDer.initVerify(jwk.toECPublicKey());
        verifyDer.update(data);
        assertTrue(verifyDer.verify(derAgain),
                "DER → P1363 → DER round-trip must produce a DER signature that verifies");
    }

    @Test
    void p1363ToDerHandlesHighBitSetOnBothComponents() {
        // DER integer encoding requires a leading 0x00 when the MSB is set
        // (otherwise the value would be interpreted as negative). Exercise that
        // branch by crafting P1363 bytes with 0x80 in both r and s.
        byte[] p1363 = new byte[64];
        p1363[0] = (byte) 0x80;   // r has MSB set
        p1363[1] = 0x01;
        p1363[32] = (byte) 0x80;  // s has MSB set
        p1363[33] = 0x02;
        // Fill the rest with non-zero so the values are full-length.
        Arrays.fill(p1363, 2, 32, (byte) 0x11);
        Arrays.fill(p1363, 34, 64, (byte) 0x22);

        byte[] der = CredentialSigner.p1363ToDer(p1363);
        // 0x30 | total-len | 0x02 | 33 | 0x00 | 32 r-bytes | 0x02 | 33 | 0x00 | 32 s-bytes
        assertEquals(0x30, der[0] & 0xFF, "DER SEQUENCE marker");
        assertEquals(0x02, der[2] & 0xFF, "DER INTEGER marker for r");
        assertEquals(33, der[3] & 0xFF, "r must be padded to 33 bytes (leading 0x00)");
        assertEquals(0x00, der[4] & 0xFF, "r padding byte");
        assertEquals(0x02, der[37] & 0xFF, "DER INTEGER marker for s");
        assertEquals(33, der[38] & 0xFF, "s must be padded to 33 bytes");
        assertEquals(0x00, der[39] & 0xFF, "s padding byte");

        byte[] backToP1363 = CredentialSigner.derToP1363(der, CredentialSigner.P256_COMPONENT_LEN);
        assertArrayEquals(p1363, backToP1363,
                "DER → P1363 → DER → P1363 must be a no-op for fully-populated inputs");
    }

    // ── normalizeToLowS direct unit coverage ──────────────────────────────

    @Test
    void normalizeToLowSFlipsExactlyWhenSExceedsHalfN() {
        byte[] lowS = new byte[64];
        Arrays.fill(lowS, 0, 32, (byte) 0x11);  // arbitrary r
        // s = 1 (low)
        lowS[63] = 0x01;
        assertSame(lowS, CredentialSigner.normalizeToLowS(lowS),
                "s already low → must return input unchanged (same reference)");

        byte[] highS = new byte[64];
        Arrays.fill(highS, 0, 32, (byte) 0x11);
        // s = n - 1 (definitely > n/2)
        byte[] nMinus1 = CredentialSigner.P256_N.subtract(BigInteger.ONE).toByteArray();
        System.arraycopy(nMinus1, nMinus1.length - 32, highS, 32, 32);

        byte[] normalized = CredentialSigner.normalizeToLowS(highS);
        assertNotSame(highS, normalized, "high-S path must allocate a new array");
        BigInteger normalizedS = new BigInteger(1, Arrays.copyOfRange(normalized, 32, 64));
        assertEquals(BigInteger.ONE, normalizedS,
                "n - (n - 1) must equal 1");
        assertArrayEquals(Arrays.copyOfRange(highS, 0, 32), Arrays.copyOfRange(normalized, 0, 32),
                "r must be preserved during low-S normalization");
    }

    // ── ecdsa-sd-2023 base signature low-S invariant ──────────────────────

    @Test
    void selectiveDisclosureBaseSignatureIsAlwaysLowS() {
        // Mirror of the ecdsa-rdfc-2022 low-S invariant, but for ecdsa-sd-2023.
        // The base signature is extracted directly from the CBOR prefix (see
        // CBOR_BASE_SIG_OFFSET) rather than via a decoder — main doesn't ship
        // one yet, and the prefix layout is fixed for P-256 base proofs.
        ECKey keyPair = KeyPairManager.generateP256KeyPair();

        for (int i = 0; i < 20; i++) {
            Map<String, Object> credential = buildSampleCredential();
            credential.put("id", "https://example.com/cred/" + i);

            Map<String, Object> signed = selectiveDisclosure.createBaseProof(
                    credential, keyPair,
                    "https://example.com/issuers/1#key-1",
                    List.of("/issuer"));

            @SuppressWarnings("unchecked")
            Map<String, Object> proof = (Map<String, Object>) signed.get("proof");
            byte[] cbor = Multibase.decodeBase64UrlNoPad((String) proof.get("proofValue"));

            // Lock in the CBOR prefix so a regression in CborEncoder that shifts
            // the signature offset would surface here.
            assertEquals((byte) 0xd9, cbor[0]);
            assertEquals((byte) 0x5d, cbor[1]);
            // W3C VC-DI-ECDSA §3.5.2: base-proof CBOR tag low byte is 0x00.
            assertEquals((byte) 0x00, cbor[2]);
            assertEquals((byte) 0x85, cbor[3]);
            assertEquals((byte) 0x58, cbor[4]);
            assertEquals((byte) 0x40, cbor[5]);

            byte[] baseSig = Arrays.copyOfRange(cbor, CBOR_BASE_SIG_OFFSET, CBOR_BASE_SIG_END);
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(baseSig, 32, 64));
            assertTrue(s.signum() > 0, "s must be positive on iteration " + i);
            assertTrue(s.compareTo(CredentialSigner.P256_HALF_N) <= 0,
                    "ecdsa-sd-2023 base signature must be low-S on iteration " + i
                            + " (got s=" + s.toString(16) + ")");
        }
    }

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
