package work.brodykim.signet.core;

/**
 * Data carrier for the OB 3.0 Related object.
 * Links an Achievement to a related Achievement or resource.
 *
 * @param id         REQUIRED — URI of the related resource
 * @param version    optional version
 * @param inLanguage optional BCP47 language code
 */
public record BadgeRelated(
        String id,
        String version,
        String inLanguage
) {
}
