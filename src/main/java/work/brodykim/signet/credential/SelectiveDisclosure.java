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
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
    private static final String CRYPTOSUITE_ECDSA_SD_2023 = "ecdsa-sd-2023";

    /** Cached P-256 curve parameters — cheap to reuse, expensive to rebuild. */
    private static final ECParameterSpec P256_SPEC;

    static {
        try {
            java.security.AlgorithmParameters params =
                    java.security.AlgorithmParameters.getInstance("EC");
            params.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
            P256_SPEC = params.getParameterSpec(ECParameterSpec.class);
        } catch (java.security.NoSuchAlgorithmException
                 | java.security.spec.InvalidParameterSpecException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

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
        // Step 1: Generate HMAC key
        byte[] hmacKey = new byte[32];
        ECPrivateKey ecPrivateKey = null;
        try {
            SECURE_RANDOM.nextBytes(hmacKey);
            // Extract the JCA private key once and reuse it for every signature
            // below (one base signature plus one per non-mandatory quad).
            // toECPrivateKey() runs KeyFactory.generatePrivate internally.
            ecPrivateKey = privateKey.toECPrivateKey();

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
                byte[] sig = signEcdsaP256(quadHash, ecPrivateKey);
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
            byte[] baseSignature = signEcdsaP256(baseInput, ecPrivateKey);

            // Step 9: Get compressed public key
            ECPublicKey ecPubKey = privateKey.toECPublicKey();
            byte[] compressedPubKey = KeyPairManager.compressP256PublicKey(ecPubKey);

            // Step 10: Encode proof value as CBOR.
            // CborEncoder copies hmacKey synchronously; safe to zero below.
            byte[] proofValueBytes = CborEncoder.encodeBaseProofValue(
                    baseSignature, compressedPubKey, hmacKey,
                    signatures, mandatoryPointers);
            // W3C VC-DI-ECDSA §3.5.2: proofValue is multibase-base64url-no-pad
            // (starts with 'u'); parseBaseProofValue rejects anything else.
            String proofValue = Multibase.encodeBase64UrlNoPad(proofValueBytes);

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
        } finally {
            KeyWipe.zero(hmacKey);
            KeyWipe.tryDestroy(ecPrivateKey);
        }
    }

    /**
     * Replace blank node identifiers in canonical N-Quads with HMAC-based labels.
     * This ensures deterministic but unpredictable blank node identifiers.
     */
    String replaceBlankNodesWithHmac(String nquads, byte[] hmacKey) {
        SecretKeySpec keySpec = new SecretKeySpec(hmacKey, "HmacSHA256");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keySpec);

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
            }
            matcher.appendTail(result);
            return result.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC computation failed", e);
        } finally {
            KeyWipe.tryDestroy(keySpec);
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

    private static byte[] signEcdsaP256(byte[] data, ECPrivateKey ecPrivateKey) throws GeneralSecurityException {
        byte[] p1363;
        try {
            Signature sig = Signature.getInstance(CredentialSigner.ALGO_ECDSA_P1363);
            sig.initSign(ecPrivateKey);
            sig.update(data);
            p1363 = sig.sign();
        } catch (java.security.NoSuchAlgorithmException e) {
            Signature sig = Signature.getInstance(CredentialSigner.ALGO_ECDSA_DER);
            sig.initSign(ecPrivateKey);
            sig.update(data);
            byte[] derSig = sig.sign();
            p1363 = CredentialSigner.derToP1363(derSig, CredentialSigner.P256_COMPONENT_LEN);
        }
        return CredentialSigner.normalizeToLowS(p1363);
    }

    // ── Disclosure proof derivation (holder side) ───────────────────────────

    /**
     * Derive a disclosure proof from a base proof (ecdsa-sd-2023, holder side).
     *
     * <p>The returned credential carries a derived proof whose proofValue
     * <b>does not contain the HMAC key</b>. This is the central security
     * property of the W3C ecdsa-sd-2023 derivation step: the issuer's HMAC
     * key never leaves the holder. If it did, any verifier could replay
     * {@code HMAC(key, "_:c14nN")} over the small canonical-label space
     * and reconstruct undisclosed blank-node masking, then dictionary-attack
     * the per-quad signatures to recover hidden claim values.
     *
     * <p><b>Scope (initial implementation):</b> the revealed document equals
     * the original credential without subsetting. Selective subsetting of
     * claims at presentation time is left for a follow-up, since it requires
     * full JSON-Pointer resolution against the expanded document. This
     * derivation step nonetheless delivers the W3C-mandated security shape:
     * <ul>
     *   <li>HMAC key is stripped from the presented proof</li>
     *   <li>Canonical-label → HMAC-label binding is delivered as an explicit
     *       {@code labelMap} (the verifier reconstructs the signed canonical
     *       form without ever holding the HMAC key)</li>
     *   <li>Mandatory vs. non-mandatory split is preserved via
     *       {@code mandatoryIndexes}</li>
     * </ul>
     *
     * @param signedCredential credential carrying an ecdsa-sd-2023 base proof
     *                         (as produced by {@link #createBaseProof})
     * @return new credential with the proof's {@code proofValue} replaced by
     *         a derived proof value (CBOR tag {@code 0xd95d01})
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> deriveProof(Map<String, Object> signedCredential) {
        Object proofObj = signedCredential.get("proof");
        if (!(proofObj instanceof Map<?, ?> proofMap)) {
            throw new IllegalArgumentException("Credential is missing a proof object");
        }
        Object proofValueObj = proofMap.get("proofValue");
        if (!(proofValueObj instanceof String proofValue)) {
            throw new IllegalArgumentException("Proof is missing proofValue");
        }

        byte[] cbor = Multibase.decodeBase64UrlNoPad(proofValue);
        CborDecoder.BaseProofValue base = CborDecoder.decodeBaseProofValue(cbor);

        // Reproduce the issuer's canonical quad list. URDNA2015 is
        // deterministic, so canonicalizing the same document yields the same
        // ordered quads — we only need their structure (not HMAC'd labels)
        // because resolveMandatoryIndexes matches predicate IRIs, which are
        // unaffected by blank-node relabelling.
        Map<String, Object> documentWithoutProof = new LinkedHashMap<>(signedCredential);
        documentWithoutProof.remove("proof");

        byte[] canonicalBytes = jsonLdProcessor.canonicalize(documentWithoutProof);
        String canonicalNQuads = new String(canonicalBytes, StandardCharsets.UTF_8);
        List<String> canonicalQuads = splitNonEmpty(canonicalNQuads);

        // mandatoryPointers is authoritative — the issuer baked their
        // mandatory selection into the base proof. This implementation
        // reveals all quads, so mandatoryIndexes indexes directly into
        // the full canonical list.
        List<Integer> mandatoryIndexes = resolveMandatoryIndexes(
                canonicalQuads, base.mandatoryPointers, signedCredential);

        // labelMap: verifier's canonical labels → issuer's HMAC labels.
        // Delivered in the derived proof so the verifier can reconstruct
        // the signed canonical form without ever holding the HMAC key.
        Map<String, String> labelMap = buildLabelMap(canonicalNQuads, base.hmacKey);

        byte[] derivedBytes = CborEncoder.encodeDerivedProofValue(
                base.baseSignature, base.publicKey, base.signatures,
                labelMap, mandatoryIndexes);
        // W3C VC-DI-ECDSA §3.5.7: derived proofValue also uses multibase-
        // base64url-no-pad ('u' prefix); parseDerivedProofValue rejects others.
        String derivedProofValue = Multibase.encodeBase64UrlNoPad(derivedBytes);

        Map<String, Object> derivedProof = new LinkedHashMap<>((Map<String, Object>) proofMap);
        derivedProof.put("proofValue", derivedProofValue);

        Map<String, Object> result = new LinkedHashMap<>(signedCredential);
        result.put("proof", derivedProof);
        return result;
    }

    // ── Verifier-side: derived proof verification ───────────────────────────

    /**
     * Verify a derived (disclosure) proof produced by {@link #deriveProof}.
     *
     * <p>The verifier reconstructs the signed canonical form by:
     * <ol>
     *   <li>Canonicalizing the revealed document (URDNA2015) → quads with
     *       sequential canonical blank-node labels (e.g. {@code _:c14n0})</li>
     *   <li>Rewriting those labels using {@code labelMap} → quads with the
     *       original HMAC-derived labels the issuer signed over</li>
     *   <li>Splitting the rewritten quads into mandatory (per
     *       {@code mandatoryIndexes}) and non-mandatory</li>
     *   <li>Verifying the base signature over
     *       {@code SHA256(proofConfig) || SHA256(mandatoryQuads)}</li>
     *   <li>Verifying each non-mandatory quad's individual signature</li>
     * </ol>
     *
     * <p>Verification never requires the HMAC key — that is the entire point
     * of stripping it during derivation.
     *
     * <p><b>Public-key trust contract:</b> this method verifies that the
     * signatures in the proof are valid <i>under the public key embedded in
     * the proof itself</i> (the CBOR {@code publicKey} element). It does
     * <b>not</b> resolve {@code proof.verificationMethod} to a controller
     * document and it does <b>not</b> check that the embedded key matches
     * the expected issuer key. A conforming W3C VC Data Integrity verifier
     * MUST dereference {@code verificationMethod}, validate the controller
     * binding, and confirm the resolved key equals the proof's embedded key
     * before trusting this method's boolean result. This method intentionally
     * stops at cryptographic integrity so callers can layer their own
     * issuer/controller trust model on top — but a bare {@code true} here
     * is <b>not</b> sufficient to accept a credential in an open-world
     * verifier.
     *
     * @param derivedCredential credential carrying an ecdsa-sd-2023 derived
     *                          proof (as produced by {@link #deriveProof})
     * @return {@code true} if the proof bytes verify under their embedded
     *         public key; {@code false} on any structural, cryptosuite,
     *         or signature mismatch. Never throws.
     */
    @SuppressWarnings("unchecked")
    public boolean verifyDerivedProof(Map<String, Object> derivedCredential) {
        try {
            Object proofObj = derivedCredential.get("proof");
            if (!(proofObj instanceof Map<?, ?> proofMap)) return false;
            // Cryptosuite guard per W3C VC-DI-ECDSA §2.2.1: this method is only
            // defined for ecdsa-sd-2023. A proof carrying a different suite
            // (e.g. ecdsa-rdfc-2022) would cause a misleading CBOR decode
            // failure downstream; fail fast with a clean `false` instead.
            if (!CRYPTOSUITE_ECDSA_SD_2023.equals(proofMap.get("cryptosuite"))) return false;
            Object proofValueObj = proofMap.get("proofValue");
            if (!(proofValueObj instanceof String proofValue)) return false;

            byte[] cbor = Multibase.decodeBase64UrlNoPad(proofValue);
            CborDecoder.DerivedProofValue derived = CborDecoder.decodeDerivedProofValue(cbor);

            // Reconstruct the canonical form the issuer signed over.
            Map<String, Object> documentWithoutProof = new LinkedHashMap<>(derivedCredential);
            documentWithoutProof.remove("proof");
            byte[] canonicalBytes = jsonLdProcessor.canonicalize(documentWithoutProof);
            String canonicalNQuads = new String(canonicalBytes, StandardCharsets.UTF_8);
            String relabelled = applyLabelMap(canonicalNQuads, derived.labelMap);
            List<String> quadList = splitNonEmpty(relabelled);

            // Bounds-check per W3C VC-DI-ECDSA §3.5.8: every mandatoryIndex
            // must address a quad in the disclosed list.
            for (int idx : derived.mandatoryIndexes) {
                if (idx < 0 || idx >= quadList.size()) return false;
            }
            List<String> mandatoryQuads = new ArrayList<>();
            List<String> nonMandatoryQuads = new ArrayList<>();
            Set<Integer> mandatorySet = new HashSet<>(derived.mandatoryIndexes);
            for (int i = 0; i < quadList.size(); i++) {
                if (mandatorySet.contains(i)) {
                    mandatoryQuads.add(quadList.get(i));
                } else {
                    nonMandatoryQuads.add(quadList.get(i));
                }
            }

            // Recompute proofConfig hash (must match the issuer's input exactly,
            // hence the proof's `created`/`verificationMethod`/cryptosuite are
            // pulled directly from the supplied proof object).
            Map<String, Object> proofConfig = new LinkedHashMap<>();
            proofConfig.put("@context", derivedCredential.get("@context"));
            proofConfig.put("type", "DataIntegrityProof");
            proofConfig.put("cryptosuite", CRYPTOSUITE_ECDSA_SD_2023);
            proofConfig.put("created", proofMap.get("created"));
            proofConfig.put("verificationMethod", proofMap.get("verificationMethod"));
            proofConfig.put("proofPurpose", proofMap.get("proofPurpose"));
            byte[] proofConfigHash = BadgeUtils.sha256(jsonLdProcessor.canonicalize(proofConfig));

            // Recompute mandatoryHash and verify base signature.
            StringBuilder mandatoryBuilder = new StringBuilder();
            for (String q : mandatoryQuads) {
                mandatoryBuilder.append(q).append("\n");
            }
            byte[] mandatoryHash = BadgeUtils.sha256(
                    mandatoryBuilder.toString().getBytes(StandardCharsets.UTF_8));

            byte[] baseInput = new byte[64];
            System.arraycopy(proofConfigHash, 0, baseInput, 0, 32);
            System.arraycopy(mandatoryHash, 0, baseInput, 32, 32);

            ECPublicKey ecPubKey = decompressP256PublicKey(derived.publicKey);
            if (!verifyEcdsaP256(baseInput, derived.baseSignature, ecPubKey)) {
                return false;
            }

            // Verify per-quad signatures for the disclosed non-mandatory quads.
            // The number of supplied signatures must match the disclosed
            // non-mandatory quads (otherwise the proof was tampered with or
            // the holder filtered claims this code path doesn't yet support).
            if (derived.signatures.size() != nonMandatoryQuads.size()) {
                return false;
            }
            for (int i = 0; i < nonMandatoryQuads.size(); i++) {
                byte[] quadHash = BadgeUtils.sha256(
                        nonMandatoryQuads.get(i).getBytes(StandardCharsets.UTF_8));
                if (!verifyEcdsaP256(quadHash, derived.signatures.get(i), ecPubKey)) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static List<String> splitNonEmpty(String nquads) {
        String[] lines = nquads.split("\n");
        List<String> out = new ArrayList<>(lines.length);
        for (String line : lines) {
            if (!line.isBlank()) {
                out.add(line);
            }
        }
        return out;
    }

    /**
     * Build a labelMap: every blank-node label that appears in the canonical
     * N-Quads is mapped to its HMAC replacement. The verifier uses this to
     * rewrite their canonicalization output back to the form the issuer signed.
     */
    private Map<String, String> buildLabelMap(String canonicalNQuads, byte[] hmacKey) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            // LinkedHashMap so the on-wire CBOR order is deterministic
            // (matches first-appearance order in the canonical N-Quads).
            Map<String, String> map = new LinkedHashMap<>();
            HexFormat hex = HexFormat.of();
            Matcher matcher = BLANK_NODE_PATTERN.matcher(canonicalNQuads);
            while (matcher.find()) {
                String original = matcher.group(1);
                if (map.containsKey(original)) continue;
                byte[] hmacBytes = mac.doFinal(original.getBytes(StandardCharsets.UTF_8));
                // Truncate to 16 bytes to match replaceBlankNodesWithHmac's format.
                map.put(original, "b" + hex.formatHex(hmacBytes, 0, 16));
            }
            return map;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC computation failed", e);
        }
    }

    /**
     * Apply a labelMap to canonical N-Quads, rewriting each {@code _:label}
     * to {@code _:<labelMap[label]>}. Labels not present in the map are left
     * unchanged.
     */
    static String applyLabelMap(String nquads, Map<String, String> labelMap) {
        StringBuffer result = new StringBuffer();
        Matcher matcher = BLANK_NODE_PATTERN.matcher(nquads);
        while (matcher.find()) {
            String original = matcher.group(1);
            String mapped = labelMap.get(original);
            String replacement = "_:" + (mapped != null ? mapped : original);
            matcher.appendReplacement(result, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(result);
        return result.toString();
    }

    /**
     * Decompress a SEC1 compressed (33-byte) P-256 public key into a
     * {@link ECPublicKey} suitable for {@link Signature#initVerify}.
     */
    private static ECPublicKey decompressP256PublicKey(byte[] compressed) throws GeneralSecurityException {
        if (compressed.length != 33 || (compressed[0] != 0x02 && compressed[0] != 0x03)) {
            throw new GeneralSecurityException("Invalid SEC1 compressed P-256 public key");
        }
        boolean yOdd = compressed[0] == 0x03;
        java.math.BigInteger x = new java.math.BigInteger(1, java.util.Arrays.copyOfRange(compressed, 1, 33));

        // P-256 curve parameters (SEC2 / FIPS 186-4)
        java.math.BigInteger p = new java.math.BigInteger(
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
        java.math.BigInteger a = new java.math.BigInteger(
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
        java.math.BigInteger b = new java.math.BigInteger(
                "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);

        // y^2 = x^3 + a*x + b  (mod p)
        java.math.BigInteger ySquared = x.modPow(java.math.BigInteger.valueOf(3), p)
                .add(a.multiply(x)).add(b).mod(p);
        // For p ≡ 3 (mod 4), sqrt(z) mod p = z^((p+1)/4) mod p
        java.math.BigInteger y = ySquared.modPow(
                p.add(java.math.BigInteger.ONE).shiftRight(2), p);
        if (y.testBit(0) != yOdd) {
            y = p.subtract(y);
        }

        try {
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(new ECPoint(x, y), P256_SPEC);
            return (ECPublicKey) java.security.KeyFactory.getInstance("EC").generatePublic(pubSpec);
        } catch (java.security.spec.InvalidKeySpecException e) {
            throw new GeneralSecurityException("Failed to construct P-256 public key", e);
        }
    }

    private static boolean verifyEcdsaP256(byte[] data, byte[] signature, ECPublicKey publicKey)
            throws GeneralSecurityException {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (java.security.NoSuchAlgorithmException e) {
            byte[] derSig = CredentialSigner.p1363ToDer(signature);
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(derSig);
        }
    }
}
