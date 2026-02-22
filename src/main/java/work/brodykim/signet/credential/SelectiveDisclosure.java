package work.brodykim.signet.credential;

import work.brodykim.signet.core.BadgeUtils;
import work.brodykim.signet.jsonld.JsonLdProcessor;
import com.nimbusds.jose.jwk.ECKey;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Implements the ecdsa-sd-2023 (ECDSA Selective Disclosure) base proof creation
 * algorithm for W3C Data Integrity proofs.
 *
 * <p>This implements the issuer-side "createBaseProof" algorithm per
 * <a href="https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-sd-2023">W3C ECDSA Cryptosuites v1.0</a>.
 *
 * <p>The algorithm:
 * <ol>
 *   <li>Generate a random HMAC key</li>
 *   <li>Replace blank node identifiers with HMAC-based pseudonyms</li>
 *   <li>Canonicalize the HMAC'd document (RDFC-1.0)</li>
 *   <li>Split canonical N-Quads into mandatory and non-mandatory</li>
 *   <li>Sign mandatory hash + non-mandatory signatures + pointers with ECDSA P-256</li>
 *   <li>Encode proof as CBOR: [baseSignature, publicKey, hmacKey, signatures, mandatoryPointers]</li>
 * </ol>
 */
public class SelectiveDisclosure {

    private static final Pattern BLANK_NODE_PATTERN = Pattern.compile("_:([^ ]+)");
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final JsonLdProcessor jsonLdProcessor;

    public SelectiveDisclosure(JsonLdProcessor jsonLdProcessor) {
        this.jsonLdProcessor = jsonLdProcessor;
    }

    /**
     * Create a base proof for selective disclosure (ecdsa-sd-2023).
     *
     * @param credential           unsigned credential document
     * @param privateKey           issuer's P-256 private key
     * @param verificationMethodId URI of the verification method
     * @param mandatoryPointers    JSON Pointer strings for mandatory disclosure paths
     * @return signed credential with ecdsa-sd-2023 proof
     */
    public Map<String, Object> createBaseProof(Map<String, Object> credential,
                                               ECKey privateKey,
                                               String verificationMethodId,
                                               List<String> mandatoryPointers) {
        try {
            // Step 1: Generate HMAC key
            byte[] hmacKey = new byte[32];
            SECURE_RANDOM.nextBytes(hmacKey);

            // Step 2: Canonicalize the document with HMAC-based blank node labels
            Map<String, Object> documentWithoutProof = new LinkedHashMap<>(credential);
            documentWithoutProof.remove("proof");

            byte[] canonicalBytes = jsonLdProcessor.canonicalize(documentWithoutProof);
            String canonicalNQuads = new String(canonicalBytes, StandardCharsets.UTF_8);

            // Replace blank node identifiers with HMAC-based labels
            String hmacNQuads = replaceBlankNodesWithHmac(canonicalNQuads, hmacKey);

            // Step 3: Split into individual N-Quad lines
            String[] allQuads = hmacNQuads.split("\n");
            List<String> quadList = new ArrayList<>();
            for (String quad : allQuads) {
                if (!quad.isBlank()) {
                    quadList.add(quad);
                }
            }

            // Step 4: Determine mandatory vs non-mandatory quads
            // For simplicity, we match mandatory pointers against quad content.
            // In a full implementation, JSON Pointer resolution against the expanded
            // document would determine which quads are mandatory.
            List<Integer> mandatoryIndexes = resolveMandatoryIndexes(quadList, mandatoryPointers, credential);
            List<Integer> nonMandatoryIndexes = new ArrayList<>();
            for (int i = 0; i < quadList.size(); i++) {
                if (!mandatoryIndexes.contains(i)) {
                    nonMandatoryIndexes.add(i);
                }
            }

            // Step 5: Hash mandatory quads
            StringBuilder mandatoryBuilder = new StringBuilder();
            for (int idx : mandatoryIndexes) {
                mandatoryBuilder.append(quadList.get(idx)).append("\n");
            }
            byte[] mandatoryHash = BadgeUtils.sha256(
                    mandatoryBuilder.toString().getBytes(StandardCharsets.UTF_8));

            // Step 6: Sign each non-mandatory quad individually
            List<byte[]> signatures = new ArrayList<>();
            for (int idx : nonMandatoryIndexes) {
                byte[] quadHash = BadgeUtils.sha256(
                        quadList.get(idx).getBytes(StandardCharsets.UTF_8));
                byte[] sig = signEcdsaP256(quadHash, privateKey);
                signatures.add(sig);
            }

            // Step 7: Build proof config hash
            String created = java.time.Instant.now()
                    .truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString();
            Map<String, Object> proofConfig = new LinkedHashMap<>();
            proofConfig.put("@context", credential.get("@context"));
            proofConfig.put("type", "DataIntegrityProof");
            proofConfig.put("cryptosuite", "ecdsa-sd-2023");
            proofConfig.put("created", created);
            proofConfig.put("verificationMethod", verificationMethodId);
            proofConfig.put("proofPurpose", "assertionMethod");

            byte[] proofConfigHash = BadgeUtils.sha256(
                    jsonLdProcessor.canonicalize(proofConfig));

            // Step 8: Compute base signature
            // baseSignature = ECDSA(proofConfigHash || mandatoryHash)
            byte[] baseInput = new byte[64];
            System.arraycopy(proofConfigHash, 0, baseInput, 0, 32);
            System.arraycopy(mandatoryHash, 0, baseInput, 32, 32);
            byte[] baseSignature = signEcdsaP256(baseInput, privateKey);

            // Step 9: Get compressed public key
            ECPublicKey ecPubKey = privateKey.toECPublicKey();
            byte[] compressedPubKey = KeyPairManager.compressP256PublicKey(ecPubKey);

            // Step 10: Encode proof value as CBOR
            byte[] proofValueBytes = CborEncoder.encodeBaseProofValue(
                    baseSignature, compressedPubKey, hmacKey,
                    signatures, mandatoryPointers);
            String proofValue = Multibase.encodeBase58Btc(proofValueBytes);

            // Step 11: Attach proof
            Map<String, Object> proof = new LinkedHashMap<>();
            proof.put("type", "DataIntegrityProof");
            proof.put("cryptosuite", "ecdsa-sd-2023");
            proof.put("created", created);
            proof.put("verificationMethod", verificationMethodId);
            proof.put("proofPurpose", "assertionMethod");
            proof.put("proofValue", proofValue);

            Map<String, Object> result = new LinkedHashMap<>(credential);
            result.put("proof", proof);
            return result;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create ecdsa-sd-2023 base proof", e);
        }
    }

    /**
     * Replace blank node identifiers in canonical N-Quads with HMAC-based labels.
     * This ensures deterministic but unpredictable blank node identifiers.
     */
    String replaceBlankNodesWithHmac(String nquads, byte[] hmacKey) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));

            StringBuffer result = new StringBuffer();
            Matcher matcher = BLANK_NODE_PATTERN.matcher(nquads);
            while (matcher.find()) {
                String originalId = matcher.group(1);
                byte[] hmacBytes = mac.doFinal(originalId.getBytes(StandardCharsets.UTF_8));
                // Use hex encoding for the HMAC'd blank node label
                StringBuilder hex = new StringBuilder("_:b");
                for (int i = 0; i < 16; i++) { // Use first 16 bytes for a shorter label
                    hex.append(String.format("%02x", hmacBytes[i]));
                }
                matcher.appendReplacement(result, hex.toString());
                // Re-initialize for next use (Mac is reusable after doFinal)
            }
            matcher.appendTail(result);
            return result.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC computation failed", e);
        }
    }

    /**
     * Resolve which quad indexes are mandatory based on JSON Pointers.
     *
     * <p>This is a simplified implementation that matches pointer paths against
     * quad content. A full implementation would resolve JSON Pointers against
     * the expanded JSON-LD document to determine exactly which RDF triples
     * correspond to mandatory fields.
     */
    private List<Integer> resolveMandatoryIndexes(List<String> quads,
                                                  List<String> mandatoryPointers,
                                                  Map<String, Object> credential) {
        List<Integer> indexes = new ArrayList<>();

        if (mandatoryPointers.isEmpty()) {
            return indexes;
        }

        // Convert JSON Pointers to property names for matching
        List<String> propertyNames = new ArrayList<>();
        for (String pointer : mandatoryPointers) {
            // JSON Pointer like "/issuer" → "issuer", "/credentialSubject/type" → "type"
            String[] parts = pointer.split("/");
            if (parts.length > 0) {
                propertyNames.add(parts[parts.length - 1]);
            }
        }

        // Mark quads that contain mandatory property IRIs
        for (int i = 0; i < quads.size(); i++) {
            String quad = quads.get(i);
            for (String prop : propertyNames) {
                // Check if the quad's predicate contains the property name
                if (quad.contains("/" + prop + ">") || quad.contains("#" + prop + ">")) {
                    indexes.add(i);
                    break;
                }
            }
        }

        return indexes;
    }

    private byte[] signEcdsaP256(byte[] data, ECKey privateKey) throws GeneralSecurityException {
        try {
            ECPrivateKey ecPrivateKey = privateKey.toECPrivateKey();
            try {
                Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
                sig.initSign(ecPrivateKey);
                sig.update(data);
                return sig.sign();
            } catch (java.security.NoSuchAlgorithmException e) {
                Signature sig = Signature.getInstance("SHA256withECDSA");
                sig.initSign(ecPrivateKey);
                sig.update(data);
                byte[] derSig = sig.sign();
                return CredentialSigner.derToP1363(derSig, 32);
            }
        } catch (com.nimbusds.jose.JOSEException e) {
            throw new GeneralSecurityException("Failed to extract EC private key", e);
        }
    }
}
