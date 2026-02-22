package work.brodykim.signet.core;

/**
 * Data carrier for the OB 3.0 EndorsementSubject.
 * Used as the {@code credentialSubject} in an EndorsementCredential.
 *
 * @param id                 REQUIRED — URI of the entity being endorsed
 * @param endorsementComment optional Markdown endorsement text
 */
public record BadgeEndorsementSubject(
        String id,
        String endorsementComment
) {
}
