package work.brodykim.signet.credential;

import work.brodykim.signet.core.BadgeAchievement;
import work.brodykim.signet.core.BadgeEvidence;
import work.brodykim.signet.core.BadgeIssuer;
import work.brodykim.signet.core.BadgeResult;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Immutable request object that captures all parameters for building an OpenBadgeCredential.
 * Replaces the telescoping-constructor pattern in {@link CredentialBuilder} with a single,
 * extensible carrier (Java Best Practices §10.3).
 *
 * <p>Use the static {@link #builder(UUID, String, BadgeAchievement, BadgeIssuer)} method
 * to construct instances fluently.
 */
public record CredentialRequest(
        UUID credentialId,
        String recipientEmail,
        String recipientName,
        BadgeAchievement achievement,
        BadgeIssuer issuer,
        Instant issuanceDate,
        Instant validUntil,
        String description,
        String imageUrl,
        List<BadgeEvidence> evidence,
        CredentialBuilder.CredentialStatus credentialStatus,
        boolean includeRefreshService,
        // AchievementSubject extensions (OB 3.0)
        List<BadgeResult> results,
        String activityStartDate,
        String activityEndDate,
        Float creditsEarned,
        String licenseNumber,
        String role,
        String source,
        String term
) {
    /**
     * Create a new builder with the required fields.
     *
     * @param credentialId   unique credential identifier
     * @param recipientEmail recipient email (will be hashed)
     * @param achievement    achievement definition
     * @param issuer         issuer profile
     */
    public static Builder builder(UUID credentialId, String recipientEmail,
                                  BadgeAchievement achievement, BadgeIssuer issuer) {
        return new Builder(credentialId, recipientEmail, achievement, issuer);
    }

    /**
     * Fluent builder for {@link CredentialRequest}.
     */
    public static final class Builder {
        private final UUID credentialId;
        private final String recipientEmail;
        private final BadgeAchievement achievement;
        private final BadgeIssuer issuer;

        private String recipientName;
        private Instant issuanceDate;
        private Instant validUntil;
        private String description;
        private String imageUrl;
        private List<BadgeEvidence> evidence;
        private CredentialBuilder.CredentialStatus credentialStatus;
        private boolean includeRefreshService;
        private List<BadgeResult> results;
        private String activityStartDate;
        private String activityEndDate;
        private Float creditsEarned;
        private String licenseNumber;
        private String role;
        private String source;
        private String term;

        private Builder(UUID credentialId, String recipientEmail,
                        BadgeAchievement achievement, BadgeIssuer issuer) {
            this.credentialId = Objects.requireNonNull(credentialId);
            this.recipientEmail = Objects.requireNonNull(recipientEmail);
            this.achievement = Objects.requireNonNull(achievement);
            this.issuer = Objects.requireNonNull(issuer);
        }

        public Builder recipientName(String recipientName) {
            this.recipientName = recipientName;
            return this;
        }

        public Builder issuanceDate(Instant issuanceDate) {
            this.issuanceDate = issuanceDate;
            return this;
        }

        public Builder validUntil(Instant validUntil) {
            this.validUntil = validUntil;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder imageUrl(String imageUrl) {
            this.imageUrl = imageUrl;
            return this;
        }

        public Builder evidence(List<BadgeEvidence> evidence) {
            this.evidence = evidence;
            return this;
        }

        public Builder credentialStatus(CredentialBuilder.CredentialStatus credentialStatus) {
            this.credentialStatus = credentialStatus;
            return this;
        }

        public Builder includeRefreshService(boolean includeRefreshService) {
            this.includeRefreshService = includeRefreshService;
            return this;
        }

        public Builder results(List<BadgeResult> results) {
            this.results = results;
            return this;
        }

        public Builder activityStartDate(String activityStartDate) {
            this.activityStartDate = activityStartDate;
            return this;
        }

        public Builder activityEndDate(String activityEndDate) {
            this.activityEndDate = activityEndDate;
            return this;
        }

        public Builder creditsEarned(Float creditsEarned) {
            this.creditsEarned = creditsEarned;
            return this;
        }

        public Builder licenseNumber(String licenseNumber) {
            this.licenseNumber = licenseNumber;
            return this;
        }

        public Builder role(String role) {
            this.role = role;
            return this;
        }

        public Builder source(String source) {
            this.source = source;
            return this;
        }

        public Builder term(String term) {
            this.term = term;
            return this;
        }

        public CredentialRequest build() {
            return new CredentialRequest(
                    credentialId, recipientEmail, recipientName, achievement, issuer,
                    issuanceDate != null ? issuanceDate : Instant.now(),
                    validUntil, description, imageUrl, evidence,
                    credentialStatus, includeRefreshService,
                    results, activityStartDate, activityEndDate, creditsEarned,
                    licenseNumber, role, source, term);
        }
    }
}
