package work.brodykim.signet.credential;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal CBOR decoder supporting the subset of types produced by
 * {@link CborEncoder} for ecdsa-sd-2023 base and derived proof values.
 *
 * <p>Supports:
 * <ul>
 *   <li>Unsigned integers (major type 0)</li>
 *   <li>Byte strings (major type 2)</li>
 *   <li>Text strings (major type 3)</li>
 *   <li>Arrays (major type 4)</li>
 *   <li>Maps (major type 5)</li>
 *   <li>CBOR tags (major type 6) — only the 3-byte form {@code 0xd9 XX XX}</li>
 * </ul>
 *
 * <p>Used to decode the proofValue blob produced by ecdsa-sd-2023 so
 * {@code SelectiveDisclosure} can derive disclosure proofs (without exposing
 * the HMAC key) and verify them.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8949">RFC 8949 — CBOR</a>
 */
final class CborDecoder {

    /** Decoded ecdsa-sd-2023 base proof contents. */
    static final class BaseProofValue {
        final byte[] baseSignature;
        final byte[] publicKey;
        final byte[] hmacKey;
        final List<byte[]> signatures;
        final List<String> mandatoryPointers;

        BaseProofValue(byte[] baseSignature, byte[] publicKey, byte[] hmacKey,
                       List<byte[]> signatures, List<String> mandatoryPointers) {
            this.baseSignature = baseSignature;
            this.publicKey = publicKey;
            this.hmacKey = hmacKey;
            this.signatures = signatures;
            this.mandatoryPointers = mandatoryPointers;
        }
    }

    /** Decoded ecdsa-sd-2023 derived (disclosure) proof contents. */
    static final class DerivedProofValue {
        final byte[] baseSignature;
        final byte[] publicKey;
        final List<byte[]> signatures;
        final Map<String, String> labelMap;
        final List<Integer> mandatoryIndexes;

        DerivedProofValue(byte[] baseSignature, byte[] publicKey,
                          List<byte[]> signatures, Map<String, String> labelMap,
                          List<Integer> mandatoryIndexes) {
            this.baseSignature = baseSignature;
            this.publicKey = publicKey;
            this.signatures = signatures;
            this.labelMap = labelMap;
            this.mandatoryIndexes = mandatoryIndexes;
        }
    }

    private CborDecoder() {
    }

    /**
     * Decode an ecdsa-sd-2023 base proof value.
     *
     * <p>Expected wire format (W3C VC-DI-ECDSA §3.5.2, matches
     * {@link CborEncoder#encodeBaseProofValue}): header bytes
     * {@code 0xd9 0x5d 0x00} followed by a 5-element array:
     * {@code [baseSignature, publicKey, hmacKey, signatures, mandatoryPointers]}.
     */
    static BaseProofValue decodeBaseProofValue(byte[] cbor) {
        ByteArrayInputStream in = new ByteArrayInputStream(cbor);
        try {
            expectTag(in, 0x5d00);
            int arrayLen = readArrayHeader(in);
            if (arrayLen != 5) {
                throw new IllegalArgumentException(
                        "Expected 5-element array for base proof, got " + arrayLen);
            }
            byte[] baseSignature = readByteString(in);
            byte[] publicKey = readByteString(in);
            byte[] hmacKey = readByteString(in);
            List<byte[]> signatures = readByteStringArray(in);
            List<String> mandatoryPointers = readTextStringArray(in);
            return new BaseProofValue(baseSignature, publicKey, hmacKey, signatures, mandatoryPointers);
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to decode base proof CBOR", e);
        }
    }

    /**
     * Decode an ecdsa-sd-2023 derived (disclosure) proof value.
     *
     * <p>Expected wire format (matches {@link CborEncoder#encodeDerivedProofValue}):
     * CBOR tag {@code 0xd9 0x5d 0x01} followed by a 5-element array:
     * {@code [baseSignature, publicKey, signatures, labelMap, mandatoryIndexes]}.
     *
     * <p>Note that the HMAC key is intentionally absent from the derived proof —
     * exposing it would let any verifier reverse the blank-node masking and
     * recover undisclosed claims.
     */
    static DerivedProofValue decodeDerivedProofValue(byte[] cbor) {
        ByteArrayInputStream in = new ByteArrayInputStream(cbor);
        try {
            expectTag(in, 0x5d01);
            int arrayLen = readArrayHeader(in);
            if (arrayLen != 5) {
                throw new IllegalArgumentException(
                        "Expected 5-element array for derived proof, got " + arrayLen);
            }
            byte[] baseSignature = readByteString(in);
            byte[] publicKey = readByteString(in);
            List<byte[]> signatures = readByteStringArray(in);
            Map<String, String> labelMap = readTextStringMap(in);
            List<Integer> mandatoryIndexes = readUnsignedIntArray(in);
            return new DerivedProofValue(baseSignature, publicKey, signatures, labelMap, mandatoryIndexes);
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to decode derived proof CBOR", e);
        }
    }

    // ── Major type readers ──────────────────────────────────────────────────

    private static void expectTag(ByteArrayInputStream in, int expectedTagValue) throws IOException {
        int first = readByte(in);
        // We only support the 3-byte tag form: 0xd9 (major type 6, additional info 25 = 2-byte tag)
        if (first != 0xd9) {
            throw new IllegalArgumentException(
                    String.format("Expected CBOR 2-byte tag (0xd9), got 0x%02x", first));
        }
        int high = readByte(in);
        int low = readByte(in);
        int actualTag = (high << 8) | low;
        if (actualTag != expectedTagValue) {
            throw new IllegalArgumentException(
                    String.format("Expected CBOR tag 0x%04x, got 0x%04x", expectedTagValue, actualTag));
        }
    }

    private static int readArrayHeader(ByteArrayInputStream in) throws IOException {
        long value = readMajorTypeValue(in, 4);
        if (value > Integer.MAX_VALUE) {
            throw new IOException("Array length exceeds Integer.MAX_VALUE");
        }
        return (int) value;
    }

    private static int readMapHeader(ByteArrayInputStream in) throws IOException {
        long value = readMajorTypeValue(in, 5);
        if (value > Integer.MAX_VALUE) {
            throw new IOException("Map size exceeds Integer.MAX_VALUE");
        }
        return (int) value;
    }

    private static byte[] readByteString(ByteArrayInputStream in) throws IOException {
        long len = readMajorTypeValue(in, 2);
        if (len > Integer.MAX_VALUE) {
            throw new IOException("Byte string length exceeds Integer.MAX_VALUE");
        }
        byte[] buf = new byte[(int) len];
        int read = in.read(buf);
        if (read != len) {
            throw new IOException("Truncated byte string: expected " + len + ", read " + read);
        }
        return buf;
    }

    private static String readTextString(ByteArrayInputStream in) throws IOException {
        long len = readMajorTypeValue(in, 3);
        if (len > Integer.MAX_VALUE) {
            throw new IOException("Text string length exceeds Integer.MAX_VALUE");
        }
        byte[] buf = new byte[(int) len];
        int read = in.read(buf);
        if (read != len) {
            throw new IOException("Truncated text string: expected " + len + ", read " + read);
        }
        return new String(buf, StandardCharsets.UTF_8);
    }

    private static long readUnsignedInt(ByteArrayInputStream in) throws IOException {
        return readMajorTypeValue(in, 0);
    }

    private static List<byte[]> readByteStringArray(ByteArrayInputStream in) throws IOException {
        int len = readArrayHeader(in);
        List<byte[]> result = new ArrayList<>(len);
        for (int i = 0; i < len; i++) {
            result.add(readByteString(in));
        }
        return result;
    }

    private static List<String> readTextStringArray(ByteArrayInputStream in) throws IOException {
        int len = readArrayHeader(in);
        List<String> result = new ArrayList<>(len);
        for (int i = 0; i < len; i++) {
            result.add(readTextString(in));
        }
        return result;
    }

    private static List<Integer> readUnsignedIntArray(ByteArrayInputStream in) throws IOException {
        int len = readArrayHeader(in);
        List<Integer> result = new ArrayList<>(len);
        for (int i = 0; i < len; i++) {
            long v = readUnsignedInt(in);
            if (v > Integer.MAX_VALUE) {
                throw new IOException("Unsigned int exceeds Integer.MAX_VALUE");
            }
            result.add((int) v);
        }
        return result;
    }

    private static Map<String, String> readTextStringMap(ByteArrayInputStream in) throws IOException {
        int size = readMapHeader(in);
        Map<String, String> result = new LinkedHashMap<>(size);
        for (int i = 0; i < size; i++) {
            String key = readTextString(in);
            String value = readTextString(in);
            result.put(key, value);
        }
        return result;
    }

    /**
     * Read the value field for an expected major type. Verifies the major type
     * matches and returns the unsigned argument value.
     */
    private static long readMajorTypeValue(ByteArrayInputStream in, int expectedMajorType) throws IOException {
        int first = readByte(in);
        int actualMajorType = (first >>> 5) & 0x07;
        if (actualMajorType != expectedMajorType) {
            throw new IOException(String.format(
                    "Expected major type %d, got %d (initial byte 0x%02x)",
                    expectedMajorType, actualMajorType, first));
        }
        int additional = first & 0x1f;
        if (additional < 24) {
            return additional;
        } else if (additional == 24) {
            return readByte(in);
        } else if (additional == 25) {
            return ((long) readByte(in) << 8) | readByte(in);
        } else if (additional == 26) {
            long b3 = readByte(in);
            long b2 = readByte(in);
            long b1 = readByte(in);
            long b0 = readByte(in);
            return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
        } else {
            throw new IOException("Unsupported CBOR additional info: " + additional);
        }
    }

    private static int readByte(ByteArrayInputStream in) throws IOException {
        int b = in.read();
        if (b < 0) {
            throw new IOException("Unexpected end of CBOR stream");
        }
        return b;
    }
}
