package work.brodykim.signet.credential;

import org.junit.jupiter.api.Test;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyWipeTest {

    @Test
    void zeroOverwritesAllBytes() {
        byte[] buf = new byte[]{1, 2, 3, 4, 5};
        KeyWipe.zero(buf);
        assertArrayEquals(new byte[5], buf);
    }

    @Test
    void zeroNullIsSafe() {
        assertDoesNotThrow(() -> KeyWipe.zero(null));
    }

    @Test
    void tryDestroyNullIsSafe() {
        assertDoesNotThrow(() -> KeyWipe.tryDestroy(null));
    }

    @Test
    void tryDestroyInvokesDestroy() {
        RecordingDestroyable d = new RecordingDestroyable(false, false);
        KeyWipe.tryDestroy(d);
        assertTrue(d.destroyCalled);
    }

    @Test
    void tryDestroySkipsAlreadyDestroyed() {
        RecordingDestroyable d = new RecordingDestroyable(true, false);
        KeyWipe.tryDestroy(d);
        assertFalse(d.destroyCalled, "destroy() should not be called when isDestroyed() is true");
    }

    @Test
    void tryDestroySwallowsDestroyFailedException() {
        RecordingDestroyable d = new RecordingDestroyable(false, true);
        assertDoesNotThrow(() -> KeyWipe.tryDestroy(d));
        assertTrue(d.destroyCalled);
    }

    private static final class RecordingDestroyable implements Destroyable {
        private final boolean alreadyDestroyed;
        private final boolean failOnDestroy;
        boolean destroyCalled;

        RecordingDestroyable(boolean alreadyDestroyed, boolean failOnDestroy) {
            this.alreadyDestroyed = alreadyDestroyed;
            this.failOnDestroy = failOnDestroy;
        }

        @Override
        public void destroy() throws DestroyFailedException {
            destroyCalled = true;
            if (failOnDestroy) {
                throw new DestroyFailedException("simulated");
            }
        }

        @Override
        public boolean isDestroyed() {
            return alreadyDestroyed;
        }
    }
}
