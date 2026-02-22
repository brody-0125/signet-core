package work.brodykim.signet.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Shared utility methods for Open Badges builders.
 */
public final class BadgeUtils {

    private BadgeUtils() {}

    /**
     * SHA-256 hash of a string, returned as lowercase hex.
     */
    public static String sha256Hex(String input) {
        byte[] bytes = sha256(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    /**
     * SHA-256 hash of raw bytes.
     */
    public static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * Remove trailing slash from a URL.
     */
    public static String trimTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
