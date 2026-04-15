package work.brodykim.signet.credential;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.util.Arrays;

/**
 * Defensive zeroization helpers for sensitive key material.
 *
 * <p>Java's garbage collector does not clear heap contents on reclamation, so
 * raw private-key bytes and secret-key objects can linger in memory long after
 * their cryptographic use is complete. That residue is recoverable via heap
 * dumps, core dumps, swap files, or cold-boot attacks.
 *
 * <p>Callers should hold sensitive {@code byte[]} buffers in a {@code try} /
 * {@code finally} and invoke {@link #zero(byte[])} in the finally block.
 * Key objects implementing {@link Destroyable} should be passed to
 * {@link #tryDestroy(Destroyable)} in the same manner; the helper tolerates
 * JDK {@code PrivateKey}/{@code SecretKeySpec} implementations that do not
 * actually support {@code destroy()}.
 */
final class KeyWipe {

    private KeyWipe() {
    }

    /**
     * Overwrite the contents of {@code buf} with zero bytes. Null-safe.
     */
    static void zero(byte[] buf) {
        if (buf != null) {
            Arrays.fill(buf, (byte) 0);
        }
    }

    /**
     * Attempt to destroy {@code d} if it supports destruction. Null-safe.
     * Swallows {@link javax.security.auth.DestroyFailedException} so callers
     * can invoke this in a finally block without masking the real exception
     * and without spamming logs for JDK implementations that do not implement
     * {@code destroy()}.
     */
    static void tryDestroy(Destroyable d) {
        if (d == null || d.isDestroyed()) {
            return;
        }
        try {
            d.destroy();
        } catch (DestroyFailedException ignored) {
        }
    }
}
