package work.brodykim.signet.core;

/**
 * Data carrier for the OB 3.0 IdentifierEntry object.
 * Represents an additional identifier for a Profile or Achievement.
 *
 * @param identifier     REQUIRED — the identifier value
 * @param identifierType REQUIRED — type of identifier (e.g. {@code sourcedId},
 *                       {@code emailAddress}, {@code sisSourcedId}, {@code ltiUserId})
 */
public record BadgeIdentifierEntry(
        String identifier,
        String identifierType
) {
}
