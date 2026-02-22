package work.brodykim.signet.core;

/**
 * Lightweight data carrier for alignment information used by badge builders.
 * Maps a BadgeClass/Achievement to an external educational framework or standard.
 *
 * @param targetName        REQUIRED — name of the alignment target
 * @param targetUrl         REQUIRED — URL of the alignment target
 * @param targetDescription optional description
 * @param targetFramework   optional name of the framework
 * @param targetCode        optional code within the framework
 * @param targetType        optional type of target (e.g. {@code ceterms:Credential},
 *                          {@code ceasn:Competency}, {@code CFItem})
 */
public record BadgeAlignment(
        String targetName,
        String targetUrl,
        String targetDescription,
        String targetFramework,
        String targetCode,
        String targetType
) {
    /**
     * Backwards-compatible constructor without targetType.
     */
    public BadgeAlignment(String targetName, String targetUrl,
                          String targetDescription, String targetFramework,
                          String targetCode) {
        this(targetName, targetUrl, targetDescription, targetFramework, targetCode, null);
    }
}
