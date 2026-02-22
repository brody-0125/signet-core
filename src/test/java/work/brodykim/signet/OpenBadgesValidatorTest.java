package work.brodykim.signet;

import work.brodykim.signet.core.BadgeAchievement;
import work.brodykim.signet.core.BadgeIssuer;
import work.brodykim.signet.core.OpenBadgesContext;
import work.brodykim.signet.core.OpenBadgesValidator;
import work.brodykim.signet.core.OpenBadgesValidator.ValidationResult;
import work.brodykim.signet.credential.CredentialBuilder;
import work.brodykim.signet.jsonld.CachedDocumentLoader;
import work.brodykim.signet.jsonld.JsonLdProcessor;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class OpenBadgesValidatorTest {

    private final OpenBadgesValidator validator = new OpenBadgesValidator();
    private final JsonLdProcessor jsonLdProcessor = new JsonLdProcessor(new CachedDocumentLoader());

    @Test
    void shouldValidateCredentialFromBuilder() {
        CredentialBuilder builder = new CredentialBuilder("https://example.com", "openbadges");
        BadgeIssuer issuer = new BadgeIssuer(UUID.randomUUID(), "Test", "https://example.com", null, null);
        BadgeAchievement achievement = new BadgeAchievement(UUID.randomUUID(), "Badge", "desc",
                "criteria", "Certification", null, null);

        Map<String, Object> credential = builder.buildCredential(UUID.randomUUID(), "user@example.com", "User", achievement, issuer);
        ValidationResult result = validator.validate(credential);

        assertTrue(result.valid(), "Builder output should be valid: " + result.errors());
    }

    @Test
    void shouldFailMissingTypes() {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("@context", List.of("https://www.w3.org/ns/credentials/v2", "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"));
        document.put("type", List.of("VerifiableCredential")); // missing OpenBadgeCredential

        ValidationResult result = validator.validate(document);
        assertFalse(result.valid());
        assertTrue(result.errors().stream().anyMatch(e -> e.contains("OpenBadgeCredential")));
    }

    @Test
    void shouldValidateFullCredential() {
        Map<String, Object> document = buildValidDocument();

        ValidationResult result = validator.validate(document);
        assertTrue(result.valid(), "Should validate full credential: " + result.errors());
    }

    @Test
    void shouldFailWhenContextOrderIsWrong() {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("@context", List.of("https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json", "https://www.w3.org/ns/credentials/v2"));
        document.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));

        ValidationResult result = validator.validate(document);
        assertFalse(result.valid());
        assertTrue(result.errors().stream().anyMatch(e -> e.contains("@context[0]")));
    }

    @Test
    void shouldValidateCredentialStatusWhenPresent() {
        Map<String, Object> document = buildValidDocument();
        document.put("credentialStatus", Map.of(
                "id", "https://example.com/status/1#42",
                "type", OpenBadgesContext.REVOCATION_LIST_TYPE,
                "statusListIndex", "42",
                "statusListCredential", "https://example.com/status/1"
        ));

        ValidationResult result = validator.validate(document);
        assertTrue(result.valid(), "Valid credentialStatus should pass: " + result.errors());
    }

    @Test
    void shouldFailCredentialStatusMissingFields() {
        Map<String, Object> document = buildValidDocument();
        document.put("credentialStatus", Map.of(
                "id", "https://example.com/status/1#42",
                "type", OpenBadgesContext.REVOCATION_LIST_TYPE
        ));

        ValidationResult result = validator.validate(document);
        assertFalse(result.valid());
        assertTrue(result.errors().stream().anyMatch(e -> e.contains("statusListIndex")));
        assertTrue(result.errors().stream().anyMatch(e -> e.contains("statusListCredential")));
    }

    @Test
    void shouldValidateRefreshServiceWhenPresent() {
        Map<String, Object> document = buildValidDocument();
        document.put("refreshService", Map.of(
                "id", "https://example.com/cred/1",
                "type", OpenBadgesContext.CREDENTIAL_REFRESH_TYPE
        ));

        ValidationResult result = validator.validate(document);
        assertTrue(result.valid(), "Valid refreshService should pass: " + result.errors());
    }

    @Test
    void shouldFailRefreshServiceMissingId() {
        Map<String, Object> document = buildValidDocument();
        Map<String, Object> refresh = new LinkedHashMap<>();
        refresh.put("type", OpenBadgesContext.CREDENTIAL_REFRESH_TYPE);
        document.put("refreshService", refresh);

        ValidationResult result = validator.validate(document);
        assertFalse(result.valid());
        assertTrue(result.errors().stream().anyMatch(e -> e.contains("refreshService.id")));
    }

    @Test
    void shouldValidateCredentialSchemaWhenPresent() {
        Map<String, Object> document = buildValidDocument();
        document.put("credentialSchema", List.of(Map.of(
                "id", OpenBadgesContext.OB3_CREDENTIAL_SCHEMA_URL,
                "type", OpenBadgesContext.CREDENTIAL_SCHEMA_TYPE
        )));

        ValidationResult result = validator.validate(document);
        assertTrue(result.valid(), "Valid credentialSchema should pass: " + result.errors());
    }

    @Test
    void shouldFailCredentialSchemaMissingIdOrType() {
        Map<String, Object> document = buildValidDocument();
        Map<String, Object> schema = new LinkedHashMap<>();
        document.put("credentialSchema", List.of(schema));

        ValidationResult result = validator.validate(document);
        assertFalse(result.valid());
        assertTrue(result.errors().stream().anyMatch(e -> e.contains("credentialSchema[0].id")));
        assertTrue(result.errors().stream().anyMatch(e -> e.contains("credentialSchema[0].type")));
    }

    // --- validateFull tests (structural + JSON-LD safe mode) ---

    @Test
    void validateFullPassesForValidCredential() {
        Map<String, Object> document = buildValidDocument();
        ValidationResult result = validator.validateFull(document, jsonLdProcessor);
        assertTrue(result.valid(), "validateFull should pass for valid credential: " + result.errors());
    }

    @Test
    void validateFullFailsForUndefinedTerms() {
        Map<String, Object> document = buildValidDocument();
        document.put("unknownProperty", "test");

        ValidationResult result = validator.validateFull(document, jsonLdProcessor);
        assertFalse(result.valid());
        assertTrue(result.errors().stream().anyMatch(e -> e.contains("safe mode") && e.contains("unknownProperty")));
    }

    @Test
    void validateFullReportsStructuralAndSafeModeErrors() {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("@context", List.of("https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
                "https://www.w3.org/ns/credentials/v2"));
        document.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        document.put("id", "https://example.com/cred/1");
        document.put("badField", "x");

        ValidationResult result = validator.validateFull(document, jsonLdProcessor);
        assertFalse(result.valid());
        assertTrue(result.errors().size() >= 2, "Should have multiple errors: " + result.errors());
    }

    // --- OB 3.0 spec compliance tests ---

    @Test
    void shouldAcceptAchievementCredentialAlias() {
        Map<String, Object> document = buildValidDocument();
        // Replace OpenBadgeCredential with AchievementCredential alias
        document.put("type", List.of("VerifiableCredential", "AchievementCredential"));

        ValidationResult result = validator.validate(document);
        assertTrue(result.valid(),
                "AchievementCredential should be accepted as alias for OpenBadgeCredential: " + result.errors());
    }

    @Test
    void shouldRequireNameOnCredential() {
        Map<String, Object> document = buildValidDocument();
        document.remove("name");

        ValidationResult result = validator.validate(document);
        assertFalse(result.valid());
        assertTrue(result.errors().stream().anyMatch(e -> e.contains("name")),
                "Should require 'name' field: " + result.errors());
    }

    @Test
    void shouldNotRequireAchievementDescription() {
        Map<String, Object> document = buildValidDocument();
        // Achievement without description — should still be valid
        document.put("credentialSubject", Map.of("type", "AchievementSubject", "achievement",
                Map.of("id", "https://example.com/achievement/1", "type", "Achievement",
                        "name", "Test Achievement",
                        "criteria", Map.of("narrative", "Complete the test"))));

        ValidationResult result = validator.validate(document);
        assertTrue(result.valid(),
                "Achievement without description should be valid (description is OPTIONAL in OB 3.0): " + result.errors());
    }

    @Test
    void shouldRequireHashedOnIdentityObject() {
        Map<String, Object> document = buildValidDocument();
        // IdentityObject missing 'hashed' field
        Map<String, Object> badIdentity = new LinkedHashMap<>();
        badIdentity.put("type", "IdentityObject");
        badIdentity.put("identityHash", "sha256$abc123");
        badIdentity.put("identityType", "emailAddress");
        // missing: hashed

        document.put("credentialSubject", Map.of(
                "type", "AchievementSubject",
                "identifier", List.of(badIdentity),
                "achievement", Map.of("id", "https://example.com/achievement/1", "type", "Achievement",
                        "name", "Test", "criteria", Map.of("narrative", "test"))));

        ValidationResult result = validator.validate(document);
        assertFalse(result.valid());
        assertTrue(result.errors().stream().anyMatch(e -> e.contains("hashed")),
                "Should require 'hashed' on IdentityObject: " + result.errors());
    }

    @Test
    void shouldAcceptDidAsValidIri() {
        Map<String, Object> document = buildValidDocument();
        document.put("id", "did:example:123456");

        ValidationResult result = validator.validate(document);
        assertTrue(result.valid(),
                "did: URIs should be accepted as valid IRIs: " + result.errors());
    }

    private Map<String, Object> buildValidDocument() {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("@context", List.of("https://www.w3.org/ns/credentials/v2", "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"));
        document.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        document.put("id", "https://example.com/cred/1");
        document.put("issuer", Map.of("id", "https://example.com/issuer/1", "type", "Profile", "name", "Test"));
        document.put("validFrom", "2026-01-01T00:00:00Z");
        document.put("name", "Test Badge");
        document.put("credentialSubject", Map.of("type", "AchievementSubject", "achievement",
                Map.of("id", "https://example.com/achievement/1", "type", "Achievement",
                        "name", "Test Achievement", "description", "A test achievement",
                        "criteria", Map.of("narrative", "Complete the test"))));
        return document;
    }
}
