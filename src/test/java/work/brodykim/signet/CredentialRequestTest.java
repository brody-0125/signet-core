package work.brodykim.signet;

import work.brodykim.signet.core.BadgeAchievement;
import work.brodykim.signet.core.BadgeAlignment;
import work.brodykim.signet.core.BadgeEvidence;
import work.brodykim.signet.core.BadgeIssuer;
import work.brodykim.signet.core.BadgeResult;
import work.brodykim.signet.core.BadgeResultDescription;
import work.brodykim.signet.core.BadgeRubricCriterionLevel;
import work.brodykim.signet.core.OpenBadgesValidator;
import work.brodykim.signet.core.OpenBadgesValidator.ValidationResult;
import work.brodykim.signet.credential.CredentialBuilder;
import work.brodykim.signet.credential.CredentialRequest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class CredentialRequestTest {

    private final CredentialBuilder builder = new CredentialBuilder("https://example.com", "openbadges");
    private final OpenBadgesValidator validator = new OpenBadgesValidator();

    @Test
    void shouldBuildCredentialFromRequest() {
        BadgeIssuer issuer = new BadgeIssuer(UUID.randomUUID(), "Test Issuer", "https://example.com", "test@example.com", null);
        BadgeAchievement achievement = new BadgeAchievement(UUID.randomUUID(), "Spring Expert", "Demonstrated Spring expertise",
                "Complete the Spring certification", "Certification", null, List.of("spring", "java"));

        CredentialRequest request = CredentialRequest.builder(UUID.randomUUID(), "user@example.com", achievement, issuer)
                .recipientName("Test User")
                .description("A test credential")
                .build();

        Map<String, Object> credential = builder.buildCredential(request);
        assertNotNull(credential);
        assertEquals("Test User", ((Map<?, ?>) credential.get("credentialSubject")).get("name"));
        assertEquals("A test credential", credential.get("description"));

        ValidationResult result = validator.validate(credential);
        assertTrue(result.valid(), "Credential from CredentialRequest should be valid: " + result.errors());
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludeResultsInCredential() {
        BadgeIssuer issuer = new BadgeIssuer(UUID.randomUUID(), "Test Issuer", "https://example.com", null, null);
        BadgeResultDescription resultDesc = new BadgeResultDescription(
                "https://example.com/results/1", "Final Grade", "LetterGrade",
                List.of("A", "B", "C", "D", "F"), null, null, null, null, null);
        BadgeAchievement achievement = new BadgeAchievement(UUID.randomUUID(), "Course Badge", null,
                "Complete the course", null, "Course", null, null, null,
                null, null, null, null, null, null, null,
                List.of(resultDesc), null, null);

        BadgeResult result = new BadgeResult("https://example.com/results/1", "A", "Completed", null, null);

        CredentialRequest request = CredentialRequest.builder(UUID.randomUUID(), "user@example.com", achievement, issuer)
                .results(List.of(result))
                .creditsEarned(3.0f)
                .build();

        Map<String, Object> credential = builder.buildCredential(request);
        Map<String, Object> subject = (Map<String, Object>) credential.get("credentialSubject");

        List<Map<String, Object>> results = (List<Map<String, Object>>) subject.get("result");
        assertNotNull(results);
        assertEquals(1, results.size());
        assertEquals("Result", results.get(0).get("type"));
        assertEquals("A", results.get(0).get("value"));

        assertEquals(3.0f, subject.get("creditsEarned"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludeAchievementSubjectExtensions() {
        BadgeIssuer issuer = new BadgeIssuer(UUID.randomUUID(), "Test Issuer", "https://example.com", null, null);
        BadgeAchievement achievement = new BadgeAchievement(UUID.randomUUID(), "License Badge", null,
                "Obtain the license", "License", null, null);

        CredentialRequest request = CredentialRequest.builder(UUID.randomUUID(), "user@example.com", achievement, issuer)
                .activityStartDate("2026-01-01")
                .activityEndDate("2026-06-30")
                .licenseNumber("LIC-12345")
                .role("Student")
                .term("Spring 2026")
                .source("https://example.com/source")
                .build();

        Map<String, Object> credential = builder.buildCredential(request);
        Map<String, Object> subject = (Map<String, Object>) credential.get("credentialSubject");

        assertEquals("2026-01-01", subject.get("activityStartDate"));
        assertEquals("2026-06-30", subject.get("activityEndDate"));
        assertEquals("LIC-12345", subject.get("licenseNumber"));
        assertEquals("Student", subject.get("role"));
        assertEquals("Spring 2026", subject.get("term"));

        Map<String, Object> source = (Map<String, Object>) subject.get("source");
        assertNotNull(source);
        assertEquals("Profile", source.get("type"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludeExtendedAchievementFields() {
        BadgeIssuer issuer = new BadgeIssuer(UUID.randomUUID(), "Test Issuer", "https://example.com", null, null);
        BadgeAchievement achievement = new BadgeAchievement(UUID.randomUUID(), "Advanced Badge", "desc",
                "Complete the course", "https://example.com/criteria", "Course", null, null, null,
                "https://example.com/creator", 3.0f, "Computer Science", "CS-101", "en",
                null, null, null, "Machine Learning", "2.0");

        CredentialRequest request = CredentialRequest.builder(UUID.randomUUID(), "user@example.com", achievement, issuer)
                .build();

        Map<String, Object> credential = builder.buildCredential(request);
        Map<String, Object> subject = (Map<String, Object>) credential.get("credentialSubject");
        Map<String, Object> ach = (Map<String, Object>) subject.get("achievement");

        assertEquals(3.0f, ach.get("creditsAvailable"));
        assertEquals("Computer Science", ach.get("fieldOfStudy"));
        assertEquals("CS-101", ach.get("humanCode"));
        assertEquals("en", ach.get("inLanguage"));
        assertEquals("Machine Learning", ach.get("specialization"));
        assertEquals("2.0", ach.get("version"));

        Map<String, Object> creator = (Map<String, Object>) ach.get("creator");
        assertNotNull(creator);
        assertEquals("Profile", creator.get("type"));
    }

    @Test
    void shouldBuildValidCredentialWithMinimalFields() {
        BadgeIssuer issuer = new BadgeIssuer(UUID.randomUUID(), "Issuer", "https://example.com", null, null);
        BadgeAchievement achievement = new BadgeAchievement(UUID.randomUUID(), "Minimal Badge", null,
                "Do the thing", "Certification", null, null);

        CredentialRequest request = CredentialRequest.builder(UUID.randomUUID(), "user@example.com", achievement, issuer)
                .build();

        Map<String, Object> credential = builder.buildCredential(request);
        ValidationResult result = validator.validate(credential);
        assertTrue(result.valid(), "Minimal CredentialRequest should produce valid credential: " + result.errors());
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIncludeEvidenceWithAudience() {
        BadgeIssuer issuer = new BadgeIssuer(UUID.randomUUID(), "Issuer", "https://example.com", null, null);
        BadgeAchievement achievement = new BadgeAchievement(UUID.randomUUID(), "Badge", null,
                "criteria", "Certification", null, null);
        List<BadgeEvidence> evidence = List.of(
                new BadgeEvidence("https://example.com/ev/1", "Project", "desc",
                        "Completed project", "Portfolio", "Employers")
        );

        CredentialRequest request = CredentialRequest.builder(UUID.randomUUID(), "user@example.com", achievement, issuer)
                .evidence(evidence)
                .build();

        Map<String, Object> credential = builder.buildCredential(request);
        List<Map<String, Object>> evidenceList = (List<Map<String, Object>>) credential.get("evidence");
        assertNotNull(evidenceList);
        assertEquals("Employers", evidenceList.get(0).get("audience"));
    }
}
