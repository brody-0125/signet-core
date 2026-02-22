package work.brodykim.signet;

import work.brodykim.signet.core.BadgeAchievement;
import work.brodykim.signet.core.BadgeAlignment;
import work.brodykim.signet.core.BadgeEvidence;
import work.brodykim.signet.core.BadgeIssuer;
import work.brodykim.signet.core.OpenBadgesContext;
import work.brodykim.signet.credential.CredentialBuilder;
import work.brodykim.signet.credential.CredentialBuilder.CredentialStatus;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class CredentialBuilderTest {

    private final CredentialBuilder builder;
    private final BadgeIssuer issuer;
    private final BadgeAchievement achievement;

    CredentialBuilderTest() {
        builder = new CredentialBuilder("https://example.com", "openbadges");

        issuer = new BadgeIssuer(UUID.randomUUID(), "Test Issuer", "https://example.com", "test@example.com", null);

        achievement = new BadgeAchievement(UUID.randomUUID(), "Spring Expert", "Demonstrated Spring expertise",
                "Complete the Spring certification", "Certification", null, List.of("spring", "java"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldBuildCredentialWithCorrectContext() {
        UUID credId = UUID.randomUUID();
        Map<String, Object> credential = builder.buildCredential(credId, "user@example.com", "Test User", achievement, issuer);

        List<String> context = (List<String>) credential.get("@context");
        assertEquals(OpenBadgesContext.VC_CONTEXT, context.get(0), "@context[0] must be VC context");
        assertEquals(OpenBadgesContext.OB3_CONTEXT, context.get(1), "@context[1] must be OB 3.0 context");
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldHaveCorrectTypes() {
        Map<String, Object> credential = builder.buildCredential(UUID.randomUUID(), "user@example.com", null, achievement, issuer);

        List<String> types = (List<String>) credential.get("type");
        assertTrue(types.contains("VerifiableCredential"));
        assertTrue(types.contains("OpenBadgeCredential"));
    }

    @Test
    void shouldUseValidFromInsteadOfIssuanceDate() {
        Map<String, Object> credential = builder.buildCredential(UUID.randomUUID(), "user@example.com", null, achievement, issuer);

        assertNotNull(credential.get("validFrom"));
        assertNull(credential.get("issuanceDate"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludeIssuerProfile() {
        Map<String, Object> credential = builder.buildCredential(UUID.randomUUID(), "user@example.com", null, achievement, issuer);

        Map<String, Object> issuerProfile = (Map<String, Object>) credential.get("issuer");
        assertEquals("Profile", issuerProfile.get("type"));
        assertEquals("Test Issuer", issuerProfile.get("name"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldHashEmailInCredentialSubject() {
        Map<String, Object> credential = builder.buildCredential(UUID.randomUUID(), "USER@example.com", null, achievement, issuer);

        Map<String, Object> subject = (Map<String, Object>) credential.get("credentialSubject");
        assertEquals("AchievementSubject", subject.get("type"));

        assertNull(subject.get("identity"), "Should use 'identifier' not 'identity'");
        List<Map<String, Object>> identifiers = (List<Map<String, Object>>) subject.get("identifier");
        assertNotNull(identifiers);
        assertEquals(1, identifiers.size());

        Map<String, Object> identityObj = identifiers.get(0);
        assertEquals("IdentityObject", identityObj.get("type"));
        assertEquals(true, identityObj.get("hashed"));
        assertTrue(((String) identityObj.get("identityHash")).startsWith("sha256$"));
        assertEquals("emailAddress", identityObj.get("identityType"));
        assertEquals("openbadges", identityObj.get("salt"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludeTagsInAchievement() {
        Map<String, Object> credential = builder.buildCredential(UUID.randomUUID(), "user@example.com", null, achievement, issuer);

        Map<String, Object> subject = (Map<String, Object>) credential.get("credentialSubject");
        Map<String, Object> ach = (Map<String, Object>) subject.get("achievement");
        List<String> tags = (List<String>) ach.get("tag");
        assertTrue(tags.contains("spring"));
        assertTrue(tags.contains("java"));
    }

    @Test
    void shouldIncludeValidUntilWhenProvided() {
        Instant issuanceDate = Instant.parse("2026-01-01T00:00:00Z");
        Instant validUntil = Instant.parse("2027-01-01T00:00:00Z");
        Map<String, Object> credential = builder.buildCredential(
                UUID.randomUUID(), "user@example.com", null, achievement, issuer,
                issuanceDate, validUntil, null, null, null);

        assertEquals(issuanceDate.toString(), credential.get("validFrom"));
        assertEquals(validUntil.toString(), credential.get("validUntil"));
    }

    @Test
    void shouldNotIncludeValidUntilWhenNull() {
        Map<String, Object> credential = builder.buildCredential(UUID.randomUUID(), "user@example.com", null, achievement, issuer);
        assertNull(credential.get("validUntil"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludeCredentialDescriptionAndImage() {
        Map<String, Object> credential = builder.buildCredential(
                UUID.randomUUID(), "user@example.com", null, achievement, issuer,
                Instant.now(), null, "This credential certifies Spring expertise",
                "https://example.com/badge-image.png", null);

        assertEquals("This credential certifies Spring expertise", credential.get("description"));
        Map<String, Object> image = (Map<String, Object>) credential.get("image");
        assertNotNull(image);
        assertEquals("https://example.com/badge-image.png", image.get("id"));
        assertEquals("Image", image.get("type"));
    }

    @Test
    void shouldNotIncludeDescriptionAndImageWhenNull() {
        Map<String, Object> credential = builder.buildCredential(UUID.randomUUID(), "user@example.com", null, achievement, issuer);
        assertNull(credential.get("description"));
        assertNull(credential.get("image"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludeEvidenceWhenProvided() {
        List<BadgeEvidence> evidence = List.of(
                new BadgeEvidence("https://example.com/evidence/1", "Project",
                        "Final project submission", "Built a REST API", "Portfolio")
        );
        Map<String, Object> credential = builder.buildCredential(
                UUID.randomUUID(), "user@example.com", null, achievement, issuer,
                Instant.now(), null, null, null, evidence);

        List<Map<String, Object>> evidenceList = (List<Map<String, Object>>) credential.get("evidence");
        assertNotNull(evidenceList);
        assertEquals(1, evidenceList.size());
        assertEquals("Evidence", evidenceList.get(0).get("type"));
        assertEquals("Project", evidenceList.get(0).get("name"));
        assertEquals("Portfolio", evidenceList.get(0).get("genre"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludeAlignmentInAchievement() {
        BadgeAchievement achievementWithAlignment = new BadgeAchievement(
                UUID.randomUUID(), "Aligned Badge", "A badge aligned to standards",
                "Complete course", "https://example.com/criteria", "Certification",
                null, null,
                List.of(new BadgeAlignment("ISTE Standard", "https://iste.org/standard/1",
                        null, "ISTE", "CT-1"))
        );

        Map<String, Object> credential = builder.buildCredential(
                UUID.randomUUID(), "user@example.com", null, achievementWithAlignment, issuer);

        Map<String, Object> subject = (Map<String, Object>) credential.get("credentialSubject");
        Map<String, Object> ach = (Map<String, Object>) subject.get("achievement");
        List<Map<String, Object>> alignments = (List<Map<String, Object>>) ach.get("alignment");
        assertNotNull(alignments);
        assertEquals(1, alignments.size());
        assertEquals("Alignment", alignments.get(0).get("type"));
        assertEquals("ISTE Standard", alignments.get(0).get("targetName"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludeCriteriaUrlInAchievement() {
        BadgeAchievement achievementWithCriteriaUrl = new BadgeAchievement(
                UUID.randomUUID(), "Test Badge", "A test badge",
                "Pass the exam", "https://example.com/criteria/test", "Certification",
                null, null, null
        );

        Map<String, Object> credential = builder.buildCredential(
                UUID.randomUUID(), "user@example.com", null, achievementWithCriteriaUrl, issuer);

        Map<String, Object> subject = (Map<String, Object>) credential.get("credentialSubject");
        Map<String, Object> ach = (Map<String, Object>) subject.get("achievement");
        Map<String, Object> criteria = (Map<String, Object>) ach.get("criteria");
        assertNotNull(criteria);
        assertEquals("https://example.com/criteria/test", criteria.get("id"));
        assertEquals("Pass the exam", criteria.get("narrative"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludeIssuerImage() {
        BadgeIssuer issuerWithImage = new BadgeIssuer(
                UUID.randomUUID(), "Imaged Issuer", "https://example.com",
                "test@example.com", null, "https://example.com/logo.png"
        );

        Map<String, Object> profile = builder.buildIssuerProfile(issuerWithImage);
        Map<String, Object> image = (Map<String, Object>) profile.get("image");
        assertNotNull(image);
        assertEquals("https://example.com/logo.png", image.get("id"));
        assertEquals("Image", image.get("type"));
    }

    @Test
    void shouldNotIncludeIssuerImageWhenNull() {
        Map<String, Object> profile = builder.buildIssuerProfile(issuer);
        assertNull(profile.get("image"));
    }

    // --- OB 3.0 compliance tests ---

    @Test
    @SuppressWarnings("unchecked")
    void shouldAlwaysIncludeCredentialSchema() {
        Map<String, Object> credential = builder.buildCredential(UUID.randomUUID(), "user@example.com", null, achievement, issuer);

        List<Map<String, Object>> schemas = (List<Map<String, Object>>) credential.get("credentialSchema");
        assertNotNull(schemas, "credentialSchema is required for OB 3.0");
        assertEquals(1, schemas.size());
        assertEquals(OpenBadgesContext.OB3_CREDENTIAL_SCHEMA_URL, schemas.get(0).get("id"));
        assertEquals(OpenBadgesContext.CREDENTIAL_SCHEMA_TYPE, schemas.get(0).get("type"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludeCredentialStatusWhenProvided() {
        CredentialStatus status = new CredentialStatus(
                "https://example.com/credentials/status/1", "42"
        );
        Map<String, Object> credential = builder.buildCredential(
                UUID.randomUUID(), "user@example.com", null, achievement, issuer,
                Instant.now(), null, null, null, null,
                status, false);

        Map<String, Object> credentialStatus = (Map<String, Object>) credential.get("credentialStatus");
        assertNotNull(credentialStatus, "credentialStatus should be present");
        assertEquals("https://example.com/credentials/status/1#42", credentialStatus.get("id"));
        assertEquals(OpenBadgesContext.REVOCATION_LIST_TYPE, credentialStatus.get("type"));
        assertEquals("42", credentialStatus.get("statusListIndex"));
        assertEquals("https://example.com/credentials/status/1", credentialStatus.get("statusListCredential"));
    }

    @Test
    void shouldNotIncludeCredentialStatusWhenNull() {
        Map<String, Object> credential = builder.buildCredential(UUID.randomUUID(), "user@example.com", null, achievement, issuer);
        assertNull(credential.get("credentialStatus"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludeRefreshServiceWhenEnabled() {
        UUID credId = UUID.randomUUID();
        Map<String, Object> credential = builder.buildCredential(
                credId, "user@example.com", null, achievement, issuer,
                Instant.now(), null, null, null, null,
                null, true);

        Map<String, Object> refreshService = (Map<String, Object>) credential.get("refreshService");
        assertNotNull(refreshService, "refreshService should be present");
        assertEquals("https://example.com/credentials/" + credId, refreshService.get("id"));
        assertEquals(OpenBadgesContext.CREDENTIAL_REFRESH_TYPE, refreshService.get("type"));
    }

    @Test
    void shouldNotIncludeRefreshServiceWhenDisabled() {
        Map<String, Object> credential = builder.buildCredential(UUID.randomUUID(), "user@example.com", null, achievement, issuer);
        assertNull(credential.get("refreshService"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludePublicKeyMultibaseInIssuerProfile() {
        String publicKeyMultibase = "z6MkrHKzgsahxBLyNAbLQyB1pcWNYC9GmywiWPgkrvntAZcj";
        Map<String, Object> profile = builder.buildIssuerProfile(issuer, publicKeyMultibase);

        List<Map<String, Object>> verificationMethods = (List<Map<String, Object>>) profile.get("verificationMethod");
        assertNotNull(verificationMethods, "verificationMethod should be present");
        assertEquals(1, verificationMethods.size());

        Map<String, Object> method = verificationMethods.get(0);
        assertEquals("Multikey", method.get("type"));
        assertEquals(publicKeyMultibase, method.get("publicKeyMultibase"));
        assertTrue(((String) method.get("id")).endsWith("#key-1"));
    }

    @Test
    void shouldNotIncludeVerificationMethodWithoutPublicKey() {
        Map<String, Object> profile = builder.buildIssuerProfile(issuer);
        assertNull(profile.get("verificationMethod"));
    }
}
