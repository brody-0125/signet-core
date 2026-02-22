package work.brodykim.signet.core;

import java.util.List;
import java.util.UUID;

/**
 * Lightweight data carrier for achievement information used by badge builders.
 * Application code should map its own domain model to this record.
 *
 * <p>Per OB 3.0, only {@code id}, {@code name}, and criteria (narrative or URL) are
 * required.  {@code description} is OPTIONAL (not required contrary to OB 2.0).
 *
 * @param id                unique identifier
 * @param name              REQUIRED — display name
 * @param description       optional description
 * @param criteriaNarrative optional Markdown criteria text (at least one of narrative/URL required)
 * @param criteriaUrl       optional URL to human-readable criteria page
 * @param achievementType   optional type from the OB 3.0 achievementType enumeration
 * @param imageUrl          optional badge image URL (simple string form)
 * @param tags              optional searchable tags (maps to {@code tag} / schema.org keywords)
 * @param alignments        optional alignments to external frameworks
 * @param creator           optional URI of the Profile that created this achievement definition
 * @param creditsAvailable  optional number of credits available
 * @param fieldOfStudy      optional field of study
 * @param humanCode         optional human-readable code (e.g. course number)
 * @param inLanguage        optional BCP47 language code
 * @param otherIdentifier   optional additional identifiers
 * @param related           optional related achievements
 * @param resultDescription optional result descriptions (grading criteria)
 * @param specialization    optional area of specialization
 * @param version           optional version of the achievement definition
 */
public record BadgeAchievement(UUID id, String name, String description, String criteriaNarrative, String criteriaUrl,
                               String achievementType, String imageUrl, List<String> tags,
                               List<BadgeAlignment> alignments, String creator, Float creditsAvailable,
                               String fieldOfStudy, String humanCode, String inLanguage,
                               List<BadgeIdentifierEntry> otherIdentifier, List<BadgeRelated> related,
                               List<BadgeResultDescription> resultDescription, String specialization, String version) {
    /**
     * Backwards-compatible constructor: original 9-field form.
     */
    public BadgeAchievement(UUID id, String name, String description, String criteriaNarrative, String criteriaUrl, String achievementType, String imageUrl, List<String> tags, List<BadgeAlignment> alignments) {
        this(id, name, description, criteriaNarrative, criteriaUrl, achievementType, imageUrl, tags, alignments, null, null, null, null, null, null, null, null, null, null);
    }

    /**
     * Backwards-compatible constructor: original 7-field form without criteriaUrl and alignments.
     */
    public BadgeAchievement(UUID id, String name, String description, String criteriaNarrative, String achievementType, String imageUrl, List<String> tags) {
        this(id, name, description, criteriaNarrative, null, achievementType, imageUrl, tags, null, null, null, null, null, null, null, null, null, null, null);
    }
}
