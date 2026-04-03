package work.brodykim.signet.examples;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import work.brodykim.signet.core.BadgeAchievement;
import work.brodykim.signet.core.BadgeIssuer;
import work.brodykim.signet.core.OpenBadgesValidator;
import work.brodykim.signet.core.OpenBadgesValidator.ValidationResult;
import work.brodykim.signet.credential.CredentialBuilder;
import work.brodykim.signet.credential.CredentialRequest;
import work.brodykim.signet.jsonld.CachedDocumentLoader;
import work.brodykim.signet.jsonld.JsonLdProcessor;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * OB 3.0 크리덴셜 구조 검증 및 JSON-LD safe mode 검증 예제.
 *
 * <p>{@link OpenBadgesValidator}를 사용하여 크리덴셜의 구조적 유효성을 검증하고,
 * {@code validateFull()}로 JSON-LD 컨텍스트 정합성까지 확인합니다.
 */
public class ValidationExample {

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        OpenBadgesValidator validator = new OpenBadgesValidator();

        System.out.println("=== Validation Example ===");
        System.out.println();

        // ── 1. 유효한 크리덴셜 검증 ────────────────────────────────────

        System.out.println("--- Valid Credential ---");
        Map<String, Object> validCredential = buildValidCredential();
        ValidationResult result = validator.validate(validCredential);
        System.out.println("Valid: " + result.valid());
        if (!result.errors().isEmpty()) {
            System.out.println("Errors: " + result.errors());
        }
        System.out.println();

        // ── 2. 잘못된 문서 검증 (context 순서 오류) ─────────────────────

        System.out.println("--- Invalid: Wrong Context Order ---");
        Map<String, Object> wrongContext = new LinkedHashMap<>();
        wrongContext.put("@context", List.of(
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
                "https://www.w3.org/ns/credentials/v2"));  // 순서가 뒤바뀜
        wrongContext.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        wrongContext.put("id", "https://example.com/cred/bad");
        wrongContext.put("issuer", Map.of("id", "https://example.com/issuer/1", "type", "Profile", "name", "Test"));
        wrongContext.put("validFrom", "2026-01-01T00:00:00Z");
        wrongContext.put("name", "Bad Badge");

        ValidationResult wrongCtxResult = validator.validate(wrongContext);
        System.out.println("Valid: " + wrongCtxResult.valid());
        System.out.println("Errors: " + wrongCtxResult.errors());
        System.out.println();

        // ── 3. 필수 필드 누락 검증 ──────────────────────────────────────

        System.out.println("--- Invalid: Missing Required Fields ---");
        Map<String, Object> missingFields = new LinkedHashMap<>();
        missingFields.put("@context", List.of(
                "https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"));
        missingFields.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        // id, issuer, validFrom 누락

        ValidationResult missingResult = validator.validate(missingFields);
        System.out.println("Valid: " + missingResult.valid());
        System.out.println("Errors: " + missingResult.errors());
        System.out.println();

        // ── 4. JSON-LD Full Validation (safe mode) ──────────────────────

        System.out.println("--- Full Validation (JSON-LD safe mode) ---");
        JsonLdProcessor jsonLdProcessor = new JsonLdProcessor(new CachedDocumentLoader());
        ValidationResult fullResult = validator.validateFull(validCredential, jsonLdProcessor);
        System.out.println("Full validation valid: " + fullResult.valid());
        if (!fullResult.errors().isEmpty()) {
            System.out.println("Errors: " + fullResult.errors());
        }
    }

    private static Map<String, Object> buildValidCredential() {
        BadgeIssuer issuer = new BadgeIssuer(
                UUID.randomUUID(), "Test Issuer",
                "https://example.com", "test@example.com", "A test issuer");
        BadgeAchievement achievement = new BadgeAchievement(
                UUID.randomUUID(), "Test Badge",
                "A test achievement", "Pass the exam",
                "Certification", null, List.of("test"));

        CredentialBuilder builder = new CredentialBuilder("https://example.com", "salt");
        CredentialRequest request = CredentialRequest.builder(
                        UUID.randomUUID(), "user@example.com", achievement, issuer)
                .recipientName("Test User")
                .build();
        return builder.buildCredential(request);
    }
}
