package work.brodykim.signet.credential;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.text.ParseException;
import java.util.UUID;

/**
 * Manages cryptographic key pair generation, serialization, and conversion
 * for Ed25519 and P-256 keys used in OB 3.0 Data Integrity proofs.
 */
public final class KeyPairManager {

    public record SerializedKeyPair(String publicJwk, String privateJwk) {}

    private KeyPairManager() {}

    // ── Ed25519 ─────────────────────────────────────────────────────────────

    public static OctetKeyPair generateEd25519KeyPair() {
        try {
            return new OctetKeyPairGenerator(Curve.Ed25519)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate Ed25519 key pair", e);
        }
    }

    // ── P-256 (secp256r1) ───────────────────────────────────────────────────

    /**
     * Generate a P-256 (secp256r1) EC key pair for ECDSA Data Integrity proofs.
     */
    public static ECKey generateP256KeyPair() {
        try {
            return new ECKeyGenerator(Curve.P_256)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate P-256 key pair", e);
        }
    }

    // ── Serialization ───────────────────────────────────────────────────────

    public static SerializedKeyPair serializeKeyPair(OctetKeyPair keyPair) {
        String publicJwk = keyPair.toPublicJWK().toJSONString();
        String privateJwk = keyPair.toJSONString();
        return new SerializedKeyPair(publicJwk, privateJwk);
    }

    public static SerializedKeyPair serializeKeyPair(ECKey keyPair) {
        String publicJwk = keyPair.toPublicJWK().toJSONString();
        String privateJwk = keyPair.toJSONString();
        return new SerializedKeyPair(publicJwk, privateJwk);
    }

    public static OctetKeyPair deserializePrivateKey(String privateKeyJwk) {
        try {
            return OctetKeyPair.parse(privateKeyJwk);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Failed to parse private key JWK", e);
        }
    }

    public static OctetKeyPair deserializePublicKey(String publicKeyJwk) {
        try {
            return OctetKeyPair.parse(publicKeyJwk);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Failed to parse public key JWK", e);
        }
    }

    public static ECKey deserializeEcPrivateKey(String privateKeyJwk) {
        try {
            return ECKey.parse(privateKeyJwk);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Failed to parse EC private key JWK", e);
        }
    }

    public static ECKey deserializeEcPublicKey(String publicKeyJwk) {
        try {
            return ECKey.parse(publicKeyJwk);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Failed to parse EC public key JWK", e);
        }
    }

    // ── Multikey conversion ─────────────────────────────────────────────────

    /**
     * Convert a JWK Ed25519 public key to Multikey publicKeyMultibase format.
     * Format: 'z' + base58btc(0xed01 + 32-byte raw public key)
     *
     * @see <a href="https://www.w3.org/TR/controller-document/#multikey">Multikey specification</a>
     */
    public static String toPublicKeyMultibase(OctetKeyPair publicKey) {
        byte[] rawKey = publicKey.getDecodedX();
        // Ed25519 multicodec prefix: 0xed 0x01
        byte[] multicodec = new byte[2 + rawKey.length];
        multicodec[0] = (byte) 0xed;
        multicodec[1] = (byte) 0x01;
        System.arraycopy(rawKey, 0, multicodec, 2, rawKey.length);
        return Multibase.encodeBase58Btc(multicodec);
    }

    /**
     * Convert a JWK P-256 public key to Multikey publicKeyMultibase format.
     * Format: 'z' + base58btc(0x8024 + 33-byte SEC1 compressed public key)
     *
     * <p>The P-256 multicodec prefix is 0x1200, which encodes as varint bytes [0x80, 0x24].
     *
     * @see <a href="https://www.w3.org/TR/controller-document/#multikey">Multikey specification</a>
     */
    public static String toPublicKeyMultibase(ECKey publicKey) {
        try {
            ECPublicKey ecPubKey = publicKey.toECPublicKey();
            byte[] compressedKey = compressP256PublicKey(ecPubKey);
            // P-256 multicodec varint: 0x1200 → [0x80, 0x24]
            byte[] multicodec = new byte[2 + compressedKey.length];
            multicodec[0] = (byte) 0x80;
            multicodec[1] = (byte) 0x24;
            System.arraycopy(compressedKey, 0, multicodec, 2, compressedKey.length);
            return Multibase.encodeBase58Btc(multicodec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to convert P-256 key to multibase", e);
        }
    }

    /**
     * Convert a JWK string to publicKeyMultibase format (Ed25519).
     */
    public static String toPublicKeyMultibase(String publicKeyJwk) {
        return toPublicKeyMultibase(deserializePublicKey(publicKeyJwk));
    }

    /**
     * Compress a P-256 public key to SEC1 compressed format (33 bytes).
     * Format: prefix byte (0x02 for even Y, 0x03 for odd Y) + 32-byte X coordinate.
     */
    static byte[] compressP256PublicKey(ECPublicKey publicKey) {
        byte[] x = toFixedLength(publicKey.getW().getAffineX().toByteArray(), 32);
        byte[] y = publicKey.getW().getAffineY().toByteArray();
        byte prefix = (y[y.length - 1] & 1) == 0 ? (byte) 0x02 : (byte) 0x03;
        byte[] compressed = new byte[33];
        compressed[0] = prefix;
        System.arraycopy(x, 0, compressed, 1, 32);
        return compressed;
    }

    /**
     * Ensure a BigInteger byte array is exactly the target length.
     * Strips leading zero bytes or pads with leading zeros as needed.
     */
    private static byte[] toFixedLength(byte[] bytes, int length) {
        if (bytes.length == length) return bytes;
        byte[] result = new byte[length];
        if (bytes.length > length) {
            // Strip leading zero bytes (from BigInteger.toByteArray() sign extension)
            System.arraycopy(bytes, bytes.length - length, result, 0, length);
        } else {
            // Pad with leading zeros
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
        }
        return result;
    }
}
