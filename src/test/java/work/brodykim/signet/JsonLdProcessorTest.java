package work.brodykim.signet;

import work.brodykim.signet.jsonld.CachedDocumentLoader;
import work.brodykim.signet.jsonld.JsonLdProcessor;
import org.eclipse.rdf4j.model.Model;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonLdProcessorTest {

    private final JsonLdProcessor processor = new JsonLdProcessor(new CachedDocumentLoader());

    @Test
    void shouldCanonicalizeSimpleCredential() {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", List.of("https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"));
        credential.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        credential.put("id", "https://example.com/cred/1");
        credential.put("issuer", Map.of("id", "https://example.com/issuers/1", "type", "Profile", "name", "Test Issuer"));
        credential.put("validFrom", "2026-01-01T00:00:00Z");
        credential.put("name", "Test Badge");

        byte[] canonical = processor.canonicalize(credential);

        assertNotNull(canonical);
        assertTrue(canonical.length > 0, "Canonical N-Quads should not be empty");

        String nquads = new String(canonical);
        // Should contain RDF triples in N-Quads format
        assertTrue(nquads.contains("<https://example.com/cred/1>"),
                "N-Quads should contain the credential IRI");
    }

    @Test
    void shouldProduceDeterministicOutput() {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", List.of("https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"));
        credential.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        credential.put("id", "https://example.com/cred/1");
        credential.put("issuer", Map.of("id", "https://example.com/issuers/1", "type", "Profile", "name", "Test"));
        credential.put("validFrom", "2026-01-01T00:00:00Z");
        credential.put("name", "Deterministic");

        byte[] first = processor.canonicalize(credential);
        byte[] second = processor.canonicalize(credential);

        assertArrayEquals(first, second, "RDFC-1.0 canonicalization must be deterministic");
    }

    @Test
    void shouldConvertToRdf4jModel() {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", List.of("https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"));
        credential.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        credential.put("id", "https://example.com/cred/1");
        credential.put("issuer", Map.of("id", "https://example.com/issuers/1", "type", "Profile", "name", "Test"));
        credential.put("validFrom", "2026-01-01T00:00:00Z");

        Model model = processor.toRdf4jModel(credential);

        assertNotNull(model);
        assertFalse(model.isEmpty(), "RDF4J model should contain statements");
    }

    @Test
    void shouldProduceDifferentOutputForDifferentDocuments() {
        Map<String, Object> cred1 = new LinkedHashMap<>();
        cred1.put("@context", List.of("https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"));
        cred1.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        cred1.put("id", "https://example.com/cred/1");
        cred1.put("issuer", Map.of("id", "https://example.com/issuers/1", "type", "Profile", "name", "Issuer A"));
        cred1.put("validFrom", "2026-01-01T00:00:00Z");

        Map<String, Object> cred2 = new LinkedHashMap<>();
        cred2.put("@context", List.of("https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"));
        cred2.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        cred2.put("id", "https://example.com/cred/2");
        cred2.put("issuer", Map.of("id", "https://example.com/issuers/2", "type", "Profile", "name", "Issuer B"));
        cred2.put("validFrom", "2026-06-01T00:00:00Z");

        byte[] canonical1 = processor.canonicalize(cred1);
        byte[] canonical2 = processor.canonicalize(cred2);

        assertFalse(java.util.Arrays.equals(canonical1, canonical2),
                "Different documents should produce different canonical forms");
    }

    // --- Safe mode validation tests ---

    @Test
    void safeModePassesForValidCredential() {
        Map<String, Object> credential = buildValidCredential();

        List<String> undefinedTerms = processor.validateSafeMode(credential);

        assertTrue(undefinedTerms.isEmpty(),
                "Valid OB 3.0 credential should have no undefined terms, but found: " + undefinedTerms);
    }

    @Test
    void safeModeDetectsUndefinedTopLevelProperty() {
        Map<String, Object> credential = buildValidCredential();
        credential.put("customField", "some value");

        List<String> undefinedTerms = processor.validateSafeMode(credential);

        assertFalse(undefinedTerms.isEmpty(), "Should detect undefined top-level property");
        assertTrue(undefinedTerms.stream().anyMatch(t -> t.contains("customField")),
                "Should report 'customField' as undefined, found: " + undefinedTerms);
    }

    @Test
    void safeModeDetectsUndefinedNestedProperty() {
        Map<String, Object> credential = buildValidCredential();

        // Add undefined property inside the issuer object
        Map<String, Object> issuer = new LinkedHashMap<>((Map<String, Object>) credential.get("issuer"));
        issuer.put("undefinedIssuerField", "bad");
        credential.put("issuer", issuer);

        List<String> undefinedTerms = processor.validateSafeMode(credential);

        assertFalse(undefinedTerms.isEmpty(), "Should detect undefined nested property");
        assertTrue(undefinedTerms.stream().anyMatch(t -> t.contains("undefinedIssuerField")),
                "Should report 'undefinedIssuerField' as undefined, found: " + undefinedTerms);
    }

    @Test
    void safeModePassesForAllStandardOb3Fields() {
        Map<String, Object> credential = buildFullOb3Credential();

        List<String> undefinedTerms = processor.validateSafeMode(credential);

        assertTrue(undefinedTerms.isEmpty(),
                "Full OB 3.0 credential with all standard fields should pass, but found: " + undefinedTerms);
    }

    @Test
    void safeModeReportsMultipleUndefinedTerms() {
        Map<String, Object> credential = buildValidCredential();
        credential.put("foo", "bar");
        credential.put("baz", 42);

        List<String> undefinedTerms = processor.validateSafeMode(credential);

        assertTrue(undefinedTerms.size() >= 2,
                "Should detect multiple undefined terms, found: " + undefinedTerms);
    }

    @Test
    void safeModeReportsErrorForMissingContext() {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("type", "VerifiableCredential");
        credential.put("id", "https://example.com/cred/1");

        List<String> errors = processor.validateSafeMode(credential);

        assertFalse(errors.isEmpty(), "Should report error for missing @context");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> buildValidCredential() {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", List.of(
                "https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"));
        credential.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        credential.put("id", "https://example.com/cred/1");
        credential.put("issuer", Map.of(
                "id", "https://example.com/issuers/1",
                "type", "Profile",
                "name", "Test Issuer"));
        credential.put("validFrom", "2026-01-01T00:00:00Z");
        credential.put("name", "Test Badge");
        credential.put("credentialSubject", Map.of(
                "type", "AchievementSubject",
                "achievement", Map.of(
                        "id", "https://example.com/achievements/1",
                        "type", "Achievement",
                        "name", "Test Achievement",
                        "description", "A test achievement",
                        "criteria", Map.of("narrative", "Complete the test"))));
        return credential;
    }

    private Map<String, Object> buildFullOb3Credential() {
        Map<String, Object> credential = buildValidCredential();
        credential.put("validUntil", "2027-01-01T00:00:00Z");
        credential.put("description", "A credential-level description");
        credential.put("image", Map.of("id", "https://example.com/image.png", "type", "Image"));
        credential.put("credentialSchema", List.of(Map.of(
                "id", "https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json",
                "type", "1EdTechJsonSchemaValidator2019")));
        credential.put("evidence", List.of(Map.of(
                "type", "Evidence",
                "id", "https://example.com/evidence/1",
                "name", "Project submission")));
        return credential;
    }
}
