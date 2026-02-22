package work.brodykim.signet.core;

/**
 * Lightweight data carrier for evidence information.
 * Maps to the Evidence object attached to an OpenBadgeCredential.
 *
 * @param id          optional URL of the evidence
 * @param name        optional display name
 * @param description optional description
 * @param narrative   optional Markdown narrative
 * @param genre       optional genre/category
 * @param audience    optional target audience
 */
public record BadgeEvidence(
        String id,
        String name,
        String description,
        String narrative,
        String genre,
        String audience
) {
    /**
     * Backwards-compatible constructor without audience.
     */
    public BadgeEvidence(String id, String name, String description,
                         String narrative, String genre) {
        this(id, name, description, narrative, genre, null);
    }
}
