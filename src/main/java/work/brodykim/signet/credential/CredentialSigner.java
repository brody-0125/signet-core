package work.brodykim.signet.credential;

import work.brodykim.signet.core.BadgeUtils;
import work.brodykim.signet.jsonld.JsonLdProcessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Signs and verifies Open Badges 3.0 Verifiable Credentials.
 *
 * <p>Supports three proof mechanisms:
 * <ul>
 *   <li><b>JWS (compact serialization)</b> — wraps the credential in a JWS envelope</li>
 *   <li><b>DataIntegrity (eddsa-rdfc-2022)</b> — Ed25519 signature over RDFC-1.0 canonicalized document</li>
 *   <li><b>DataIntegrity (ecdsa-rdfc-2022)</b> — ECDSA P-256 signature over RDFC-1.0 canonicalized document</li>
 * </ul>
 *
 * <p><b>Canonicalization:</b> Uses Titanium JSON-LD + URDNA2015 (RDFC-1.0) for
 * spec-compliant canonicalization: JSON-LD → RDF → canonical N-Quads.
 */
public class CredentialSigner {

    private final ObjectMapper objectMapper;
    private final JsonLdProcessor jsonLdProcessor;

    public CredentialSigner(ObjectMapper objectMapper, JsonLdProcessor jsonLdProcessor) {
        this.objectMapper = objectMapper;
        this.jsonLdProcessor = jsonLdProcessor;
    }

    // ── JWS (EdDSA/Ed25519) ─────────────────────────────────────────────────

    /**
     * Sign a credential as a JWS compact serialization (EdDSA/Ed25519).
     */
    public String signCredential(Map<String, Object> credential, OctetKeyPair privateKey) {
        try {
            String payload = objectMapper.writeValueAsString(credential);
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                    .keyID(privateKey.getKeyID())
                    .type(new JOSEObjectType("vc+ld+jwt"))
                    .build();
            JWSObject jwsObject = new JWSObject(header, new Payload(payload));
            jwsObject.sign(new Ed25519Signer(privateKey));
            return jwsObject.serialize();
        } catch (JsonProcessingException | JOSEException e) {
            throw new IllegalStateException("Failed to sign credential", e);
        }
    }

    /**
     * Verify a JWS-signed credential.
     */
    public boolean verifyCredential(String jws, OctetKeyPair publicKey) {
        try {
            JWSObject jwsObject = JWSObject.parse(jws);
            return jwsObject.verify(new Ed25519Verifier(publicKey));
        } catch (Exception e) {
            return false;
        }
    }

    // ── DataIntegrity: eddsa-rdfc-2022 ──────────────────────────────────────

    /**
     * Sign a credential with a DataIntegrity proof (eddsa-rdfc-2022 cryptosuite).
     */
    public Map<String, Object> signWithDataIntegrity(Map<String, Object> credential,
                                                     OctetKeyPair privateKey,
                                                     String verificationMethodId) {
        try {
            String created = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
            byte[] combined = buildDataIntegrityHash(credential, "eddsa-rdfc-2022", verificationMethodId, created);
            byte[] signature = signEd25519Raw(combined, privateKey);
            return attachProof(credential, "eddsa-rdfc-2022", verificationMethodId, signature, created);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign credential with eddsa-rdfc-2022", e);
        }
    }

    /**
     * Verify a DataIntegrity proof (eddsa-rdfc-2022).
     */
    @SuppressWarnings("unchecked")
    public boolean verifyDataIntegrity(Map<String, Object> signedCredential, OctetKeyPair publicKey) {
        try {
            Map<String, Object> mutableCred = new LinkedHashMap<>(signedCredential);
            Object proofObj = mutableCred.remove("proof");
            if (!(proofObj instanceof Map<?, ?> proofMap)) return false;

            Object proofValueObj = proofMap.get("proofValue");
            if (!(proofValueObj instanceof String proofValue)) return false;
            if (!proofValue.startsWith("z")) return false;

            byte[] signature = Multibase.decodeBase58Btc(proofValue);

            Map<String, Object> proofConfig = new LinkedHashMap<>();
            proofConfig.put("@context", mutableCred.get("@context"));
            for (Map.Entry<?, ?> entry : proofMap.entrySet()) {
                if (!"proofValue".equals(entry.getKey())) {
                    proofConfig.put((String) entry.getKey(), entry.getValue());
                }
            }

            byte[] documentHash = BadgeUtils.sha256(canonicalize(mutableCred));
            byte[] proofConfigHash = BadgeUtils.sha256(canonicalize(proofConfig));

            byte[] combined = new byte[64];
            System.arraycopy(proofConfigHash, 0, combined, 0, 32);
            System.arraycopy(documentHash, 0, combined, 32, 32);

            return verifyEd25519Raw(combined, signature, publicKey);
        } catch (Exception e) {
            return false;
        }
    }

    // ── DataIntegrity: ecdsa-rdfc-2022 ──────────────────────────────────────

    /**
     * Sign a credential with a DataIntegrity proof (ecdsa-rdfc-2022 cryptosuite).
     * Uses ECDSA P-256 (SHA-256) over RDFC-1.0 canonicalized document.
     */
    public Map<String, Object> signWithEcdsaDataIntegrity(Map<String, Object> credential,
                                                          ECKey privateKey,
                                                          String verificationMethodId) {
        try {
            String created = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
            byte[] combined = buildDataIntegrityHash(credential, "ecdsa-rdfc-2022", verificationMethodId, created);
            byte[] signature = signEcdsaP256Raw(combined, privateKey);
            return attachProof(credential, "ecdsa-rdfc-2022", verificationMethodId, signature, created);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign credential with ecdsa-rdfc-2022", e);
        }
    }

    /**
     * Verify a DataIntegrity proof (ecdsa-rdfc-2022) using a P-256 public key.
     */
    public boolean verifyEcdsaDataIntegrity(Map<String, Object> signedCredential, ECKey publicKey) {
        try {
            Map<String, Object> mutableCred = new LinkedHashMap<>(signedCredential);
            Object proofObj = mutableCred.remove("proof");
            if (!(proofObj instanceof Map<?, ?> proofMap)) return false;

            Object proofValueObj = proofMap.get("proofValue");
            if (!(proofValueObj instanceof String proofValue)) return false;
            if (!proofValue.startsWith("z")) return false;

            byte[] signature = Multibase.decodeBase58Btc(proofValue);

            Map<String, Object> proofConfig = new LinkedHashMap<>();
            proofConfig.put("@context", mutableCred.get("@context"));
            for (Map.Entry<?, ?> entry : proofMap.entrySet()) {
                if (!"proofValue".equals(entry.getKey())) {
                    proofConfig.put((String) entry.getKey(), entry.getValue());
                }
            }

            byte[] documentHash = BadgeUtils.sha256(canonicalize(mutableCred));
            byte[] proofConfigHash = BadgeUtils.sha256(canonicalize(proofConfig));

            byte[] combined = new byte[64];
            System.arraycopy(proofConfigHash, 0, combined, 0, 32);
            System.arraycopy(documentHash, 0, combined, 32, 32);

            return verifyEcdsaP256Raw(combined, signature, publicKey);
        } catch (Exception e) {
            return false;
        }
    }

    // ── Shared DataIntegrity helpers ────────────────────────────────────────

    private byte[] buildDataIntegrityHash(Map<String, Object> credential,
                                          String cryptosuite,
                                          String verificationMethodId,
                                          String created) {
        Map<String, Object> proofConfig = new LinkedHashMap<>();
        proofConfig.put("@context", credential.get("@context"));
        proofConfig.put("type", "DataIntegrityProof");
        proofConfig.put("cryptosuite", cryptosuite);
        proofConfig.put("created", created);
        proofConfig.put("verificationMethod", verificationMethodId);
        proofConfig.put("proofPurpose", "assertionMethod");

        Map<String, Object> documentWithoutProof = new LinkedHashMap<>(credential);
        documentWithoutProof.remove("proof");
        byte[] documentHash = BadgeUtils.sha256(canonicalize(documentWithoutProof));
        byte[] proofConfigHash = BadgeUtils.sha256(canonicalize(proofConfig));

        // W3C Data Integrity: combined = proofConfigHash || documentHash
        byte[] combined = new byte[64];
        System.arraycopy(proofConfigHash, 0, combined, 0, 32);
        System.arraycopy(documentHash, 0, combined, 32, 32);
        return combined;
    }

    private Map<String, Object> attachProof(Map<String, Object> credential,
                                            String cryptosuite,
                                            String verificationMethodId,
                                            byte[] signature,
                                            String created) {
        String proofValue = Multibase.encodeBase58Btc(signature);

        Map<String, Object> proof = new LinkedHashMap<>();
        proof.put("type", "DataIntegrityProof");
        proof.put("cryptosuite", cryptosuite);
        proof.put("created", created);
        proof.put("verificationMethod", verificationMethodId);
        proof.put("proofPurpose", "assertionMethod");
        proof.put("proofValue", proofValue);

        Map<String, Object> result = new LinkedHashMap<>(credential);
        result.put("proof", proof);
        return result;
    }

    private byte[] canonicalize(Map<String, Object> data) {
        return jsonLdProcessor.canonicalize(data);
    }

    // ── Ed25519 low-level ───────────────────────────────────────────────────

    private byte[] signEd25519Raw(byte[] data, OctetKeyPair privateKey) throws GeneralSecurityException {
        byte[] seed = privateKey.getDecodedD();
        PrivateKey pk = null;
        try {
            EdECPrivateKeySpec spec = new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed);
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            pk = kf.generatePrivate(spec);

            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(pk);
            sig.update(data);
            return sig.sign();
        } finally {
            KeyWipe.zero(seed);
            KeyWipe.tryDestroy(pk);
        }
    }

    private boolean verifyEd25519Raw(byte[] data, byte[] signature, OctetKeyPair publicKey)
            throws GeneralSecurityException {
        PublicKey pk = decodeEd25519PublicKey(publicKey.getDecodedX());

        Signature sig = Signature.getInstance("Ed25519");
        sig.initVerify(pk);
        sig.update(data);
        return sig.verify(signature);
    }

    private PublicKey decodeEd25519PublicKey(byte[] rawKey) throws GeneralSecurityException {
        byte[] copy = rawKey.clone();
        boolean xOdd = (copy[copy.length - 1] & 0x80) != 0;
        copy[copy.length - 1] &= 0x7F;

        byte[] reversed = new byte[copy.length];
        for (int i = 0; i < copy.length; i++) {
            reversed[i] = copy[copy.length - 1 - i];
        }

        BigInteger y = new BigInteger(1, reversed);
        EdECPoint point = new EdECPoint(xOdd, y);
        EdECPublicKeySpec pubSpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, point);
        KeyFactory kf = KeyFactory.getInstance("Ed25519");
        return kf.generatePublic(pubSpec);
    }

    // ── ECDSA P-256 low-level ───────────────────────────────────────────────

    /**
     * Sign data with ECDSA P-256 in IEEE P1363 format (r || s, 64 bytes).
     * The W3C Data Integrity ECDSA spec requires P1363 format, not DER.
     */
    private byte[] signEcdsaP256Raw(byte[] data, ECKey privateKey) throws GeneralSecurityException {
        ECPrivateKey ecPrivateKey = null;
        try {
            ecPrivateKey = privateKey.toECPrivateKey();
            try {
                Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
                sig.initSign(ecPrivateKey);
                sig.update(data);
                return sig.sign();
            } catch (java.security.NoSuchAlgorithmException e) {
                // Fallback: use DER format and convert to P1363
                Signature sig = Signature.getInstance("SHA256withECDSA");
                sig.initSign(ecPrivateKey);
                sig.update(data);
                byte[] derSig = sig.sign();
                return derToP1363(derSig, 32);
            }
        } catch (com.nimbusds.jose.JOSEException e) {
            throw new GeneralSecurityException("Failed to extract EC private key from JWK", e);
        } finally {
            KeyWipe.tryDestroy(ecPrivateKey);
        }
    }

    private boolean verifyEcdsaP256Raw(byte[] data, byte[] signature, ECKey publicKey)
            throws GeneralSecurityException {
        try {
            ECPublicKey ecPublicKey = publicKey.toECPublicKey();
            try {
                Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
                sig.initVerify(ecPublicKey);
                sig.update(data);
                return sig.verify(signature);
            } catch (java.security.NoSuchAlgorithmException e) {
                // Fallback: convert P1363 to DER and verify
                byte[] derSig = p1363ToDer(signature);
                Signature sig = Signature.getInstance("SHA256withECDSA");
                sig.initVerify(ecPublicKey);
                sig.update(data);
                return sig.verify(derSig);
            }
        } catch (com.nimbusds.jose.JOSEException e) {
            throw new GeneralSecurityException("Failed to extract EC public key from JWK", e);
        }
    }

    /**
     * Convert a DER-encoded ECDSA signature to IEEE P1363 format (r || s).
     */
    static byte[] derToP1363(byte[] derSig, int componentLength) {
        // DER format: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
        int offset = 2; // skip 0x30 and total length
        if (derSig[0] != 0x30) throw new IllegalArgumentException("Invalid DER signature");

        // Parse r
        if (derSig[offset] != 0x02) throw new IllegalArgumentException("Invalid DER signature: expected 0x02 for r");
        offset++;
        int rLen = derSig[offset++] & 0xFF;
        byte[] r = Arrays.copyOfRange(derSig, offset, offset + rLen);
        offset += rLen;

        // Parse s
        if (derSig[offset] != 0x02) throw new IllegalArgumentException("Invalid DER signature: expected 0x02 for s");
        offset++;
        int sLen = derSig[offset++] & 0xFF;
        byte[] s = Arrays.copyOfRange(derSig, offset, offset + sLen);

        // Convert to fixed-length P1363 format
        byte[] result = new byte[componentLength * 2];
        copyToFixed(r, result, 0, componentLength);
        copyToFixed(s, result, componentLength, componentLength);
        return result;
    }

    /**
     * Convert IEEE P1363 format (r || s) to DER-encoded ECDSA signature.
     */
    static byte[] p1363ToDer(byte[] p1363Sig) {
        int half = p1363Sig.length / 2;
        byte[] r = trimLeadingZeros(Arrays.copyOfRange(p1363Sig, 0, half));
        byte[] s = trimLeadingZeros(Arrays.copyOfRange(p1363Sig, half, p1363Sig.length));

        // Add leading zero if high bit set (DER signed integer representation)
        if (r.length > 0 && (r[0] & 0x80) != 0) {
            byte[] padded = new byte[r.length + 1];
            System.arraycopy(r, 0, padded, 1, r.length);
            r = padded;
        }
        if (s.length > 0 && (s[0] & 0x80) != 0) {
            byte[] padded = new byte[s.length + 1];
            System.arraycopy(s, 0, padded, 1, s.length);
            s = padded;
        }

        int totalLen = 2 + r.length + 2 + s.length;
        byte[] der = new byte[2 + totalLen];
        int idx = 0;
        der[idx++] = 0x30;
        der[idx++] = (byte) totalLen;
        der[idx++] = 0x02;
        der[idx++] = (byte) r.length;
        System.arraycopy(r, 0, der, idx, r.length);
        idx += r.length;
        der[idx++] = 0x02;
        der[idx++] = (byte) s.length;
        System.arraycopy(s, 0, der, idx, s.length);
        return der;
    }

    private static void copyToFixed(byte[] src, byte[] dest, int destOffset, int length) {
        if (src.length > length) {
            // Strip leading zeros (BigInteger sign extension)
            System.arraycopy(src, src.length - length, dest, destOffset, length);
        } else {
            System.arraycopy(src, 0, dest, destOffset + length - src.length, src.length);
        }
    }

    private static byte[] trimLeadingZeros(byte[] bytes) {
        int start = 0;
        while (start < bytes.length - 1 && bytes[start] == 0) {
            start++;
        }
        return start == 0 ? bytes : Arrays.copyOfRange(bytes, start, bytes.length);
    }
}
