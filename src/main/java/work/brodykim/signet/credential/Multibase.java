package work.brodykim.signet.credential;

/**
 * Minimal multibase implementation supporting base58btc encoding/decoding.
 * Used for OB 3.0 DataIntegrity proof proofValue encoding.
 *
 * @see <a href="https://www.w3.org/TR/controller-document/#multibase-0">Multibase Specification</a>
 */
public final class Multibase {

    private static final char BASE58BTC_PREFIX = 'z';
    private static final String BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final int[] BASE58_INDEXES = new int[128];

    static {
        java.util.Arrays.fill(BASE58_INDEXES, -1);
        for (int i = 0; i < BASE58_ALPHABET.length(); i++) {
            BASE58_INDEXES[BASE58_ALPHABET.charAt(i)] = i;
        }
    }

    private Multibase() {
    }

    public static String encodeBase58Btc(byte[] data) {
        return BASE58BTC_PREFIX + encodeBase58(data);
    }

    public static byte[] decodeBase58Btc(String encoded) {
        if (encoded == null || encoded.isEmpty() || encoded.charAt(0) != BASE58BTC_PREFIX) {
            throw new IllegalArgumentException("Not a valid multibase base58btc string (must start with 'z')");
        }
        return decodeBase58(encoded.substring(1));
    }

    private static String encodeBase58(byte[] input) {
        if (input.length == 0) return "";

        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            zeros++;
        }

        byte[] temp = java.util.Arrays.copyOf(input, input.length);
        char[] encoded = new char[temp.length * 2];
        int outputStart = encoded.length;

        for (int inputStart = zeros; inputStart < temp.length; ) {
            encoded[--outputStart] = BASE58_ALPHABET.charAt(divmod(temp, inputStart, 256, 58));
            if (temp[inputStart] == 0) {
                inputStart++;
            }
        }

        while (outputStart < encoded.length && encoded[outputStart] == '1') {
            outputStart++;
        }
        while (--zeros >= 0) {
            encoded[--outputStart] = '1';
        }

        return new String(encoded, outputStart, encoded.length - outputStart);
    }

    private static byte[] decodeBase58(String input) {
        if (input.isEmpty()) return new byte[0];

        byte[] input58 = new byte[input.length()];
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = c < 128 ? BASE58_INDEXES[c] : -1;
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid base58 character: " + c);
            }
            input58[i] = (byte) digit;
        }

        int zeros = 0;
        while (zeros < input58.length && input58[zeros] == 0) {
            zeros++;
        }

        byte[] decoded = new byte[input.length()];
        int outputStart = decoded.length;

        for (int inputStart = zeros; inputStart < input58.length; ) {
            decoded[--outputStart] = (byte) divmod(input58, inputStart, 58, 256);
            if (input58[inputStart] == 0) {
                inputStart++;
            }
        }

        while (outputStart < decoded.length && decoded[outputStart] == 0) {
            outputStart++;
        }

        return java.util.Arrays.copyOfRange(decoded, outputStart - zeros, decoded.length);
    }

    private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = (int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return (byte) remainder;
    }
}
