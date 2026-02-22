package work.brodykim.signet.credential;

import work.brodykim.signet.core.BadgeAchievement;
import work.brodykim.signet.core.BadgeAddress;
import work.brodykim.signet.core.BadgeAlignment;
import work.brodykim.signet.core.BadgeEvidence;
import work.brodykim.signet.core.BadgeGeoCoordinates;
import work.brodykim.signet.core.BadgeIdentifierEntry;
import work.brodykim.signet.core.BadgeIssuer;
import work.brodykim.signet.core.BadgeRelated;
import work.brodykim.signet.core.BadgeResult;
import work.brodykim.signet.core.BadgeResultDescription;
import work.brodykim.signet.core.BadgeRubricCriterionLevel;
import work.brodykim.signet.core.BadgeUtils;
import work.brodykim.signet.core.OpenBadgesContext;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Builds Open Badges 3.0 (W3C Verifiable Credential) compliant JSON-LD objects.
 *
 * <p>Framework-agnostic: no Spring, no DI container dependency.
 *
 * <p>Credentials include:
 * <ul>
 *   <li>{@code credentialSchema} — always included, pointing to the 1EdTech OB 3.0 JSON schema</li>
 *   <li>{@code credentialStatus} — optional, for 1EdTechRevocationList support</li>
 *   <li>{@code refreshService} — optional, for 1EdTechCredentialRefresh support</li>
 * </ul>
 */
public class CredentialBuilder {

    private final String baseUrl;
    private final String recipientSalt;

    /**
     * @param baseUrl       base URL for badge endpoint IRIs (e.g. "https://example.com")
     * @param recipientSalt salt for recipient email hashing (e.g. "openbadges")
     */
    public CredentialBuilder(String baseUrl, String recipientSalt) {
        this.baseUrl = Objects.requireNonNull(baseUrl, "baseUrl must not be null");
        this.recipientSalt = Objects.requireNonNull(recipientSalt, "recipientSalt must not be null");
    }

    /**
     * Configuration for credential revocation status (1EdTechRevocationList).
     *
     * @param statusListCredential URL of the revocation status list credential
     * @param statusListIndex      index of this credential within the status list
     */
    public record CredentialStatus(String statusListCredential, String statusListIndex) {
    }

    // ── Legacy overloaded methods (kept for backwards compatibility) ────────

    public Map<String, Object> buildCredential(UUID credentialId, String recipientEmail,
                                               String recipientName, BadgeAchievement achievement,
                                               BadgeIssuer issuer) {
        return buildCredential(credentialId, recipientEmail, recipientName, achievement, issuer,
                Instant.now(), null, null, null, null, null, false);
    }

    public Map<String, Object> buildCredential(UUID credentialId, String recipientEmail,
                                               String recipientName, BadgeAchievement achievement,
                                               BadgeIssuer issuer, Instant issuanceDate) {
        return buildCredential(credentialId, recipientEmail, recipientName, achievement, issuer,
                issuanceDate, null, null, null, null, null, false);
    }

    public Map<String, Object> buildCredential(UUID credentialId, String recipientEmail,
                                               String recipientName, BadgeAchievement achievement,
                                               BadgeIssuer issuer, Instant issuanceDate,
                                               Instant validUntil, String credentialDescription,
                                               String credentialImageUrl, List<BadgeEvidence> evidence) {
        return buildCredential(credentialId, recipientEmail, recipientName, achievement, issuer,
                issuanceDate, validUntil, credentialDescription, credentialImageUrl, evidence,
                null, false);
    }

    public Map<String, Object> buildCredential(UUID credentialId, String recipientEmail,
                                               String recipientName, BadgeAchievement achievement,
                                               BadgeIssuer issuer, Instant issuanceDate,
                                               Instant validUntil, String credentialDescription,
                                               String credentialImageUrl, List<BadgeEvidence> evidence,
                                               CredentialStatus credentialStatus,
                                               boolean includeRefreshService) {
        CredentialRequest.Builder reqBuilder = CredentialRequest.builder(
                credentialId, recipientEmail, achievement, issuer);
        if (recipientName != null) reqBuilder.recipientName(recipientName);
        if (issuanceDate != null) reqBuilder.issuanceDate(issuanceDate);
        if (validUntil != null) reqBuilder.validUntil(validUntil);
        if (credentialDescription != null) reqBuilder.description(credentialDescription);
        if (credentialImageUrl != null) reqBuilder.imageUrl(credentialImageUrl);
        if (evidence != null) reqBuilder.evidence(evidence);
        if (credentialStatus != null) reqBuilder.credentialStatus(credentialStatus);
        reqBuilder.includeRefreshService(includeRefreshService);
        return buildCredential(reqBuilder.build());
    }

    // ── Primary entry point using CredentialRequest ─────────────────────────

    /**
     * Build a fully OB 3.0 compliant OpenBadgeCredential from a {@link CredentialRequest}.
     */
    public Map<String, Object> buildCredential(CredentialRequest request) {
        String trimmedBaseUrl = BadgeUtils.trimTrailingSlash(baseUrl);
        String credentialUrl = trimmedBaseUrl + "/credentials/" + request.credentialId();

        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", List.of(OpenBadgesContext.VC_CONTEXT, OpenBadgesContext.OB3_CONTEXT));
        credential.put("id", credentialUrl);
        credential.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        credential.put("issuer", buildEmbeddedIssuerProfile(request.issuer(), trimmedBaseUrl));
        credential.put("validFrom", request.issuanceDate().truncatedTo(ChronoUnit.SECONDS).toString());
        if (request.validUntil() != null) {
            credential.put("validUntil", request.validUntil().truncatedTo(ChronoUnit.SECONDS).toString());
        }
        // OB 3.0: 'name' is REQUIRED on OpenBadgeCredential
        credential.put("name", request.achievement().name());
        if (request.description() != null) {
            credential.put("description", request.description());
        }
        if (request.imageUrl() != null) {
            credential.put("image", Map.of("id", request.imageUrl(), "type", "Image"));
        }
        credential.put("credentialSubject", buildCredentialSubject(request, trimmedBaseUrl));

        // OB 3.0 §8.1: credentialSchema for JSON Schema validation
        credential.put("credentialSchema", List.of(Map.of(
                "id", OpenBadgesContext.OB3_CREDENTIAL_SCHEMA_URL,
                "type", OpenBadgesContext.CREDENTIAL_SCHEMA_TYPE
        )));

        // OB 3.0: credentialStatus for revocation (1EdTechRevocationList)
        if (request.credentialStatus() != null) {
            CredentialStatus cs = request.credentialStatus();
            Map<String, Object> status = new LinkedHashMap<>();
            status.put("id", cs.statusListCredential() + "#" + cs.statusListIndex());
            status.put("type", OpenBadgesContext.REVOCATION_LIST_TYPE);
            status.put("statusListIndex", cs.statusListIndex());
            status.put("statusListCredential", cs.statusListCredential());
            credential.put("credentialStatus", status);
        }

        // OB 3.0: refreshService for credential refresh (1EdTechCredentialRefresh)
        if (request.includeRefreshService()) {
            credential.put("refreshService", Map.of(
                    "id", credentialUrl,
                    "type", OpenBadgesContext.CREDENTIAL_REFRESH_TYPE
            ));
        }

        List<BadgeEvidence> evidence = request.evidence();
        if (evidence != null && !evidence.isEmpty()) {
            credential.put("evidence", evidence.stream().map(this::buildEvidence).toList());
        }
        return credential;
    }

    // ── Issuer profile builders ─────────────────────────────────────────────

    /**
     * Build an issuer Profile for standalone use (e.g., GET /issuers/{id}).
     * Includes @context for standalone JSON-LD document.
     */
    public Map<String, Object> buildIssuerProfile(BadgeIssuer issuer) {
        return buildIssuerProfile(issuer, BadgeUtils.trimTrailingSlash(baseUrl), null);
    }

    /**
     * Build an issuer Profile for standalone use, including publicKeyMultibase if available.
     */
    public Map<String, Object> buildIssuerProfile(BadgeIssuer issuer, String publicKeyMultibase) {
        return buildIssuerProfile(issuer, BadgeUtils.trimTrailingSlash(baseUrl), publicKeyMultibase);
    }

    /**
     * Build an issuer Profile for standalone use. Includes @context.
     */
    public Map<String, Object> buildIssuerProfile(BadgeIssuer issuer, String profileBaseUrl, String publicKeyMultibase) {
        Map<String, Object> embedded = buildEmbeddedIssuerProfile(issuer, profileBaseUrl);
        Map<String, Object> standalone = new LinkedHashMap<>();
        standalone.put("@context", OpenBadgesContext.OB3_CONTEXT);
        standalone.putAll(embedded);

        // OB 3.0: verificationMethod with Multikey type and publicKeyMultibase
        if (publicKeyMultibase != null) {
            String issuerId = profileBaseUrl + "/issuers/" + issuer.id();
            Map<String, Object> verificationMethod = new LinkedHashMap<>();
            verificationMethod.put("id", issuerId + "#key-1");
            verificationMethod.put("type", "Multikey");
            verificationMethod.put("controller", issuerId);
            verificationMethod.put("publicKeyMultibase", publicKeyMultibase);
            standalone.put("verificationMethod", List.of(verificationMethod));
        }

        return standalone;
    }

    // ── Private builders ────────────────────────────────────────────────────

    /**
     * Build an issuer Profile for embedding inside a credential.
     * Does NOT include @context — parent credential provides it.
     */
    private Map<String, Object> buildEmbeddedIssuerProfile(BadgeIssuer issuer, String profileBaseUrl) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", profileBaseUrl + "/issuers/" + issuer.id());
        map.put("type", "Profile");
        map.put("name", issuer.name());
        if (issuer.url() != null) {
            map.put("url", issuer.url());
        }
        if (issuer.email() != null) {
            map.put("email", issuer.email());
        }
        if (issuer.description() != null) {
            map.put("description", issuer.description());
        }
        if (issuer.imageUrl() != null) {
            map.put("image", Map.of("id", issuer.imageUrl(), "type", "Image"));
        }
        if (issuer.phone() != null) {
            map.put("phone", issuer.phone());
        }
        if (issuer.address() != null) {
            map.put("address", buildAddress(issuer.address()));
        }
        List<BadgeIdentifierEntry> otherIds = issuer.otherIdentifier();
        if (otherIds != null && !otherIds.isEmpty()) {
            map.put("otherIdentifier", otherIds.stream().map(this::buildIdentifierEntry).toList());
        }
        if (issuer.parentOrg() != null) {
            map.put("parentOrg", issuer.parentOrg());
        }
        if (issuer.givenName() != null) {
            map.put("givenName", issuer.givenName());
        }
        if (issuer.familyName() != null) {
            map.put("familyName", issuer.familyName());
        }
        return map;
    }

    private Map<String, Object> buildCredentialSubject(CredentialRequest request, String subjectBaseUrl) {
        String hashedEmail = BadgeUtils.sha256Hex(
                request.recipientEmail().toLowerCase().trim() + recipientSalt);

        Map<String, Object> identityObject = new LinkedHashMap<>();
        identityObject.put("type", "IdentityObject");
        identityObject.put("hashed", true);
        identityObject.put("identityHash", "sha256$" + hashedEmail);
        identityObject.put("identityType", "emailAddress");
        identityObject.put("salt", recipientSalt);

        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("type", "AchievementSubject");
        subject.put("identifier", List.of(identityObject));
        if (request.recipientName() != null) {
            subject.put("name", request.recipientName());
        }
        subject.put("achievement", buildAchievement(request.achievement(), subjectBaseUrl));

        // OB 3.0 AchievementSubject extensions
        List<BadgeResult> results = request.results();
        if (results != null && !results.isEmpty()) {
            subject.put("result", results.stream().map(this::buildResult).toList());
        }
        if (request.activityStartDate() != null) {
            subject.put("activityStartDate", request.activityStartDate());
        }
        if (request.activityEndDate() != null) {
            subject.put("activityEndDate", request.activityEndDate());
        }
        if (request.creditsEarned() != null) {
            subject.put("creditsEarned", request.creditsEarned());
        }
        if (request.licenseNumber() != null) {
            subject.put("licenseNumber", request.licenseNumber());
        }
        if (request.role() != null) {
            subject.put("role", request.role());
        }
        if (request.source() != null) {
            subject.put("source", Map.of("id", request.source(), "type", "Profile"));
        }
        if (request.term() != null) {
            subject.put("term", request.term());
        }
        return subject;
    }

    private Map<String, Object> buildAchievement(BadgeAchievement achievement, String achievementBaseUrl) {
        // OB 3.0: 'criteria' is REQUIRED — at least one of criteriaUrl or criteriaNarrative
        Map<String, Object> criteria = buildCriteria(achievement);
        if (criteria == null) {
            throw new IllegalArgumentException(
                    "Achievement criteria is REQUIRED by OB 3.0 spec — provide criteriaUrl or criteriaNarrative");
        }

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", achievementBaseUrl + "/achievements/" + achievement.id());
        map.put("type", "Achievement");
        map.put("name", achievement.name());
        // OB 3.0: 'description' is OPTIONAL (not required)
        if (achievement.description() != null) {
            map.put("description", achievement.description());
        }
        map.put("criteria", criteria);
        if (achievement.achievementType() != null) {
            map.put("achievementType", achievement.achievementType());
        }
        if (achievement.imageUrl() != null) {
            map.put("image", Map.of("id", achievement.imageUrl(), "type", "Image"));
        }
        List<String> tags = achievement.tags();
        if (tags != null && !tags.isEmpty()) {
            map.put("tag", tags);
        }
        List<BadgeAlignment> alignments = achievement.alignments();
        if (alignments != null && !alignments.isEmpty()) {
            map.put("alignment", alignments.stream().map(this::buildAlignment).toList());
        }
        // Extended Achievement fields (OB 3.0)
        if (achievement.creator() != null) {
            map.put("creator", Map.of("id", achievement.creator(), "type", "Profile"));
        }
        if (achievement.creditsAvailable() != null) {
            map.put("creditsAvailable", achievement.creditsAvailable());
        }
        if (achievement.fieldOfStudy() != null) {
            map.put("fieldOfStudy", achievement.fieldOfStudy());
        }
        if (achievement.humanCode() != null) {
            map.put("humanCode", achievement.humanCode());
        }
        if (achievement.inLanguage() != null) {
            map.put("inLanguage", achievement.inLanguage());
        }
        List<BadgeIdentifierEntry> otherIds = achievement.otherIdentifier();
        if (otherIds != null && !otherIds.isEmpty()) {
            map.put("otherIdentifier", otherIds.stream().map(this::buildIdentifierEntry).toList());
        }
        List<BadgeRelated> related = achievement.related();
        if (related != null && !related.isEmpty()) {
            map.put("related", related.stream().map(this::buildRelated).toList());
        }
        List<BadgeResultDescription> resultDescs = achievement.resultDescription();
        if (resultDescs != null && !resultDescs.isEmpty()) {
            map.put("resultDescription", resultDescs.stream().map(this::buildResultDescription).toList());
        }
        if (achievement.specialization() != null) {
            map.put("specialization", achievement.specialization());
        }
        if (achievement.version() != null) {
            map.put("version", achievement.version());
        }
        return map;
    }

    private Map<String, Object> buildCriteria(BadgeAchievement achievement) {
        Map<String, Object> criteria = new LinkedHashMap<>();
        if (achievement.criteriaUrl() != null) {
            criteria.put("id", achievement.criteriaUrl());
        }
        if (achievement.criteriaNarrative() != null) {
            criteria.put("narrative", achievement.criteriaNarrative());
        }
        return criteria.isEmpty() ? null : criteria;
    }

    private Map<String, Object> buildEvidence(BadgeEvidence evidence) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("type", "Evidence");
        if (evidence.id() != null) {
            map.put("id", evidence.id());
        }
        if (evidence.name() != null) {
            map.put("name", evidence.name());
        }
        if (evidence.description() != null) {
            map.put("description", evidence.description());
        }
        if (evidence.narrative() != null) {
            map.put("narrative", evidence.narrative());
        }
        if (evidence.genre() != null) {
            map.put("genre", evidence.genre());
        }
        if (evidence.audience() != null) {
            map.put("audience", evidence.audience());
        }
        return map;
    }

    private Map<String, Object> buildAlignment(BadgeAlignment alignment) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("type", "Alignment");
        map.put("targetName", alignment.targetName());
        map.put("targetUrl", alignment.targetUrl());
        if (alignment.targetDescription() != null) {
            map.put("targetDescription", alignment.targetDescription());
        }
        if (alignment.targetFramework() != null) {
            map.put("targetFramework", alignment.targetFramework());
        }
        if (alignment.targetCode() != null) {
            map.put("targetCode", alignment.targetCode());
        }
        if (alignment.targetType() != null) {
            map.put("targetType", alignment.targetType());
        }
        return map;
    }

    private Map<String, Object> buildResult(BadgeResult result) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("type", "Result");
        if (result.resultDescription() != null) {
            map.put("resultDescription", result.resultDescription());
        }
        if (result.value() != null) {
            map.put("value", result.value());
        }
        if (result.status() != null) {
            map.put("status", result.status());
        }
        if (result.achievedLevel() != null) {
            map.put("achievedLevel", result.achievedLevel());
        }
        List<BadgeAlignment> alignment = result.alignment();
        if (alignment != null && !alignment.isEmpty()) {
            map.put("alignment", alignment.stream().map(this::buildAlignment).toList());
        }
        return map;
    }

    private Map<String, Object> buildResultDescription(BadgeResultDescription rd) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", rd.id());
        map.put("type", "ResultDescription");
        map.put("name", rd.name());
        map.put("resultType", rd.resultType());
        List<String> allowed = rd.allowedValue();
        if (allowed != null && !allowed.isEmpty()) {
            map.put("allowedValue", allowed);
        }
        if (rd.requiredLevel() != null) {
            map.put("requiredLevel", rd.requiredLevel());
        }
        if (rd.requiredValue() != null) {
            map.put("requiredValue", rd.requiredValue());
        }
        List<BadgeRubricCriterionLevel> levels = rd.rubricCriterionLevel();
        if (levels != null && !levels.isEmpty()) {
            map.put("rubricCriterionLevel", levels.stream().map(this::buildRubricCriterionLevel).toList());
        }
        if (rd.valueMax() != null) {
            map.put("valueMax", rd.valueMax());
        }
        if (rd.valueMin() != null) {
            map.put("valueMin", rd.valueMin());
        }
        return map;
    }

    private Map<String, Object> buildRubricCriterionLevel(BadgeRubricCriterionLevel level) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", level.id());
        map.put("type", "RubricCriterionLevel");
        map.put("name", level.name());
        if (level.description() != null) {
            map.put("description", level.description());
        }
        if (level.level() != null) {
            map.put("level", level.level());
        }
        if (level.points() != null) {
            map.put("points", level.points());
        }
        List<BadgeAlignment> alignment = level.alignment();
        if (alignment != null && !alignment.isEmpty()) {
            map.put("alignment", alignment.stream().map(this::buildAlignment).toList());
        }
        return map;
    }

    private Map<String, Object> buildIdentifierEntry(BadgeIdentifierEntry entry) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("type", "IdentifierEntry");
        map.put("identifier", entry.identifier());
        map.put("identifierType", entry.identifierType());
        return map;
    }

    private Map<String, Object> buildRelated(BadgeRelated related) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", related.id());
        map.put("type", "Related");
        if (related.version() != null) {
            map.put("version", related.version());
        }
        if (related.inLanguage() != null) {
            map.put("inLanguage", related.inLanguage());
        }
        return map;
    }

    private Map<String, Object> buildAddress(BadgeAddress address) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("type", "Address");
        if (address.addressCountry() != null) {
            map.put("addressCountry", address.addressCountry());
        }
        if (address.addressCountryCode() != null) {
            map.put("addressCountryCode", address.addressCountryCode());
        }
        if (address.addressLocality() != null) {
            map.put("addressLocality", address.addressLocality());
        }
        if (address.addressRegion() != null) {
            map.put("addressRegion", address.addressRegion());
        }
        if (address.streetAddress() != null) {
            map.put("streetAddress", address.streetAddress());
        }
        if (address.postalCode() != null) {
            map.put("postalCode", address.postalCode());
        }
        if (address.postOfficeBoxNumber() != null) {
            map.put("postOfficeBoxNumber", address.postOfficeBoxNumber());
        }
        BadgeGeoCoordinates geo = address.geo();
        if (geo != null) {
            map.put("geo", Map.of(
                    "type", "GeoCoordinates",
                    "latitude", geo.latitude(),
                    "longitude", geo.longitude()));
        }
        return map;
    }
}
