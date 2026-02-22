package work.brodykim.signet;

import work.brodykim.signet.credential.Multibase;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class MultibaseTest {

    @Test
    void shouldEncodeAndDecodeRoundTrip() {
        byte[] original = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        String encoded = Multibase.encodeBase58Btc(original);

        assertTrue(encoded.startsWith("z"), "Multibase base58btc must start with 'z'");

        byte[] decoded = Multibase.decodeBase58Btc(encoded);
        assertArrayEquals(original, decoded);
    }

    @Test
    void shouldEncodeEmptyBytes() {
        String encoded = Multibase.encodeBase58Btc(new byte[0]);
        assertEquals("z", encoded);

        byte[] decoded = Multibase.decodeBase58Btc(encoded);
        assertEquals(0, decoded.length);
    }

    @Test
    void shouldEncodeAndDecode64ByteSignature() {
        // Simulate a 64-byte Ed25519 signature
        byte[] signature = new byte[64];
        for (int i = 0; i < 64; i++) {
            signature[i] = (byte) (i * 3 + 17);
        }

        String encoded = Multibase.encodeBase58Btc(signature);
        assertTrue(encoded.startsWith("z"));

        byte[] decoded = Multibase.decodeBase58Btc(encoded);
        assertArrayEquals(signature, decoded);
    }

    @Test
    void shouldHandleLeadingZeroBytes() {
        byte[] data = new byte[]{0, 0, 0, 1, 2, 3};
        String encoded = Multibase.encodeBase58Btc(data);
        byte[] decoded = Multibase.decodeBase58Btc(encoded);
        assertArrayEquals(data, decoded);
    }

    @Test
    void shouldRejectNonMultibaseString() {
        assertThrows(IllegalArgumentException.class, () -> Multibase.decodeBase58Btc("abc"));
        assertThrows(IllegalArgumentException.class, () -> Multibase.decodeBase58Btc(""));
        assertThrows(IllegalArgumentException.class, () -> Multibase.decodeBase58Btc(null));
    }
}
