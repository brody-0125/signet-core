package work.brodykim.signet.core;

import java.util.List;
import java.util.UUID;

/**
 * Lightweight data carrier for issuer/profile information used by badge builders.
 * Application code should map its own domain model to this record.
 *
 * <p>Per OB 3.0, when used as an embedded issuer the required fields are
 * {@code id}, {@code type} (always "Profile"), and {@code name}.
 *
 * @param id              unique identifier
 * @param name            REQUIRED — display name
 * @param url             optional website URL
 * @param email           optional contact email
 * @param description     optional description
 * @param imageUrl        optional logo/image URL (simple string form)
 * @param phone           optional phone number
 * @param address         optional physical address
 * @param otherIdentifier optional additional identifiers
 * @param parentOrg       optional URI of parent organization Profile
 * @param givenName       optional given name (for individual issuers)
 * @param familyName      optional family name (for individual issuers)
 */
public record BadgeIssuer(
        UUID id,
        String name,
        String url,
        String email,
        String description,
        String imageUrl,
        String phone,
        BadgeAddress address,
        List<BadgeIdentifierEntry> otherIdentifier,
        String parentOrg,
        String givenName,
        String familyName
) {
    /**
     * Backwards-compatible constructor: original 6-field form.
     */
    public BadgeIssuer(UUID id, String name, String url, String email,
                       String description, String imageUrl) {
        this(id, name, url, email, description, imageUrl,
                null, null, null, null, null, null);
    }

    /**
     * Backwards-compatible constructor: original 5-field form without imageUrl.
     */
    public BadgeIssuer(UUID id, String name, String url, String email, String description) {
        this(id, name, url, email, description, null,
                null, null, null, null, null, null);
    }
}
