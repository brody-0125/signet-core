package work.brodykim.signet.credential;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * Minimal CBOR encoder supporting the specific types required by ecdsa-sd-2023 proof
 * serialization. Not a general-purpose CBOR library — only encodes:
 * <ul>
 *   <li>Unsigned integers (major type 0)</li>
 *   <li>Byte strings (major type 2)</li>
 *   <li>Arrays (major type 4)</li>
 *   <li>CBOR tags (major type 6)</li>
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8949">RFC 8949 — CBOR</a>
 */
final class CborEncoder {

    private CborEncoder() {
    }

    /**
     * Encode an ecdsa-sd-2023 base proof value.
     *
     * <p>Format: CBOR tag 0xd9 0x5d 0x02 followed by a CBOR array:
     * {@code [baseSignature, publicKey, hmacKey, signatures, mandatoryPointers]}
     *
     * @param baseSignature     ECDSA P-256 base signature (64 bytes)
     * @param publicKey         compressed P-256 public key (33 bytes)
     * @param hmacKey           HMAC-SHA256 key (32 bytes)
     * @param signatures        per-message ECDSA signatures (list of 64-byte arrays)
     * @param mandatoryPointers JSON Pointer strings for mandatory disclosure
     * @return CBOR-encoded byte array including the tag prefix
     */
    static byte[] encodeBaseProofValue(byte[] baseSignature, byte[] publicKey,
                                       byte[] hmacKey, List<byte[]> signatures,
                                       List<String> mandatoryPointers) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // CBOR tag: 0xd9 followed by 2-byte tag value 0x5d02
            out.write(0xd9);
            out.write(0x5d);
            out.write(0x02);

            // 5-element array
            writeArrayHeader(out, 5);

            // 1. baseSignature (byte string)
            writeByteString(out, baseSignature);

            // 2. publicKey (byte string)
            writeByteString(out, publicKey);

            // 3. hmacKey (byte string)
            writeByteString(out, hmacKey);

            // 4. signatures (array of byte strings)
            writeArrayHeader(out, signatures.size());
            for (byte[] sig : signatures) {
                writeByteString(out, sig);
            }

            // 5. mandatoryPointers (array of text strings)
            writeArrayHeader(out, mandatoryPointers.size());
            for (String ptr : mandatoryPointers) {
                writeTextString(out, ptr);
            }

            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("CBOR encoding failed", e);
        }
    }

    // ── CBOR major type writers ─────────────────────────────────────────────

    /**
     * Write a CBOR unsigned integer (major type 0).
     */
    static void writeUnsignedInt(ByteArrayOutputStream out, long value) throws IOException {
        writeMajorType(out, 0, value);
    }

    /**
     * Write a CBOR byte string header + payload (major type 2).
     */
    static void writeByteString(ByteArrayOutputStream out, byte[] data) throws IOException {
        writeMajorType(out, 2, data.length);
        out.write(data);
    }

    /**
     * Write a CBOR text string header + payload (major type 3).
     */
    static void writeTextString(ByteArrayOutputStream out, String text) throws IOException {
        byte[] utf8 = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        writeMajorType(out, 3, utf8.length);
        out.write(utf8);
    }

    /**
     * Write a CBOR array header (major type 4).
     */
    static void writeArrayHeader(ByteArrayOutputStream out, int count) throws IOException {
        writeMajorType(out, 4, count);
    }

    /**
     * Write a CBOR major type + additional info.
     * Supports values up to 2^32 - 1 (sufficient for credential data sizes).
     */
    private static void writeMajorType(ByteArrayOutputStream out, int majorType, long value)
            throws IOException {
        int mt = majorType << 5;
        if (value < 24) {
            out.write(mt | (int) value);
        } else if (value < 256) {
            out.write(mt | 24);
            out.write((int) value);
        } else if (value < 65536) {
            out.write(mt | 25);
            out.write((int) (value >> 8));
            out.write((int) (value & 0xFF));
        } else {
            out.write(mt | 26);
            out.write((int) (value >> 24));
            out.write((int) ((value >> 16) & 0xFF));
            out.write((int) ((value >> 8) & 0xFF));
            out.write((int) (value & 0xFF));
        }
    }
}
