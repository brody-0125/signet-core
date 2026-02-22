package work.brodykim.signet;

import work.brodykim.signet.credential.KeyPairManager;
import work.brodykim.signet.credential.Multibase;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyPairManagerTest {

    @Test
    void shouldGenerateEd25519KeyPair() {
        OctetKeyPair keyPair = KeyPairManager.generateEd25519KeyPair();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getKeyID());
        assertNotNull(keyPair.getD()); // private key component
        assertNotNull(keyPair.getX()); // public key component
    }

    @Test
    void shouldSerializeAndDeserializeKeyPair() {
        OctetKeyPair original = KeyPairManager.generateEd25519KeyPair();
        KeyPairManager.SerializedKeyPair serialized = KeyPairManager.serializeKeyPair(original);

        OctetKeyPair restored = KeyPairManager.deserializePrivateKey(serialized.privateJwk());
        assertArrayEquals(original.getDecodedX(), restored.getDecodedX());
        assertArrayEquals(original.getDecodedD(), restored.getDecodedD());

        OctetKeyPair restoredPublic = KeyPairManager.deserializePublicKey(serialized.publicJwk());
        assertArrayEquals(original.getDecodedX(), restoredPublic.getDecodedX());
    }

    @Test
    void publicKeyShouldNotContainPrivateKey() {
        OctetKeyPair keyPair = KeyPairManager.generateEd25519KeyPair();
        KeyPairManager.SerializedKeyPair serialized = KeyPairManager.serializeKeyPair(keyPair);
        assertFalse(serialized.publicJwk().contains("\"d\""));
    }

    // ── P-256 key pair tests ────────────────────────────────────────────────

    @Test
    void shouldGenerateP256KeyPair() {
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getKeyID());
        assertTrue(keyPair.isPrivate(), "Generated key should contain private component");
        assertNotNull(keyPair.toPublicJWK());
    }

    @Test
    void shouldSerializeAndDeserializeP256KeyPair() {
        ECKey original = KeyPairManager.generateP256KeyPair();
        KeyPairManager.SerializedKeyPair serialized = KeyPairManager.serializeKeyPair(original);

        ECKey restored = KeyPairManager.deserializeEcPrivateKey(serialized.privateJwk());
        assertTrue(restored.isPrivate());
        assertEquals(original.getX(), restored.getX());
        assertEquals(original.getY(), restored.getY());

        ECKey restoredPublic = KeyPairManager.deserializeEcPublicKey(serialized.publicJwk());
        assertFalse(restoredPublic.isPrivate());
        assertEquals(original.getX(), restoredPublic.getX());
    }

    @Test
    void p256PublicKeyShouldNotContainPrivateKey() {
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        KeyPairManager.SerializedKeyPair serialized = KeyPairManager.serializeKeyPair(keyPair);
        assertFalse(serialized.publicJwk().contains("\"d\""));
    }

    // ── Multikey (publicKeyMultibase) tests ─────────────────────────────────

    @Test
    void ed25519MultikeyPrefixShouldBeCorrect() {
        OctetKeyPair keyPair = KeyPairManager.generateEd25519KeyPair();
        String multibase = KeyPairManager.toPublicKeyMultibase(keyPair.toPublicJWK());

        assertNotNull(multibase);
        assertTrue(multibase.startsWith("z"), "Multibase should start with 'z' (base58btc)");

        // Decode and check multicodec prefix: 0xed 0x01
        byte[] decoded = Multibase.decodeBase58Btc(multibase);
        assertEquals((byte) 0xed, decoded[0], "Ed25519 multicodec prefix byte 0 must be 0xed");
        assertEquals((byte) 0x01, decoded[1], "Ed25519 multicodec prefix byte 1 must be 0x01");
        assertEquals(34, decoded.length, "Ed25519 multikey should be 2 prefix + 32 key bytes");
    }

    @Test
    void p256MultikeyPrefixShouldBeCorrect() {
        ECKey keyPair = KeyPairManager.generateP256KeyPair();
        String multibase = KeyPairManager.toPublicKeyMultibase(keyPair.toPublicJWK());

        assertNotNull(multibase);
        assertTrue(multibase.startsWith("z"), "Multibase should start with 'z' (base58btc)");

        // Decode and check multicodec varint prefix: 0x80 0x24 (varint for 0x1200)
        byte[] decoded = Multibase.decodeBase58Btc(multibase);
        assertEquals((byte) 0x80, decoded[0], "P-256 multicodec varint byte 0 must be 0x80");
        assertEquals((byte) 0x24, decoded[1], "P-256 multicodec varint byte 1 must be 0x24");
        assertEquals(35, decoded.length, "P-256 multikey should be 2 prefix + 33 compressed key bytes");

        // Compressed key first byte should be 0x02 or 0x03
        byte compressedPrefix = decoded[2];
        assertTrue(compressedPrefix == 0x02 || compressedPrefix == 0x03,
                "Compressed P-256 key must start with 0x02 or 0x03, got: " + compressedPrefix);
    }

    @Test
    void shouldConvertJwkStringToMultibase() {
        OctetKeyPair keyPair = KeyPairManager.generateEd25519KeyPair();
        String fromJwkString = KeyPairManager.toPublicKeyMultibase(keyPair.toPublicJWK().toJSONString());
        String fromKeyObject = KeyPairManager.toPublicKeyMultibase(keyPair.toPublicJWK());
        assertEquals(fromJwkString, fromKeyObject,
                "Converting via JWK string should produce same result as via key object");
    }
}
