package work.brodykim.signet.core;

import work.brodykim.signet.jsonld.JsonLdProcessor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validates the structural integrity of Open Badges 3.0 JSON-LD objects.
 * Performs lightweight checks (not full JSON-LD processing) for:
 * <ul>
 *   <li>Required @context values and ordering (W3C VC Data Model 2.0 §4.1)</li>
 *   <li>Required fields by type (OB 3.0 spec)</li>
 *   <li>IRI format validation</li>
 *   <li>Nested structure validation (issuer, achievement, credentialSchema)</li>
 *   <li>credentialStatus / refreshService type validation</li>
 * </ul>
 */
public class OpenBadgesValidator {

    private static final String VC_CONTEXT = OpenBadgesContext.VC_CONTEXT;
    private static final String OB3_CONTEXT = OpenBadgesContext.OB3_CONTEXT;

    public record ValidationResult(boolean valid, List<String> errors) {
        public static ValidationResult success() {
            return new ValidationResult(true, List.of());
        }

        public static ValidationResult failure(List<String> errors) {
            return new ValidationResult(false, errors);
        }
    }

    /**
     * Validate an OB 3.0 OpenBadgeCredential: structural checks + JSON-LD safe mode.
     * This combines {@link #validate(Map)} structural validation with
     * {@link JsonLdProcessor#validateSafeMode(Map)} to detect undefined terms.
     *
     * @param document the credential document
     * @param jsonLdProcessor processor for JSON-LD safe mode validation
     * @return validation result including both structural and safe mode errors
     */
    public ValidationResult validateFull(Map<String, Object> document, JsonLdProcessor jsonLdProcessor) {
        ValidationResult structural = validate(document);
        List<String> safeModeErrors = jsonLdProcessor.validateSafeMode(document);

        if (structural.valid() && safeModeErrors.isEmpty()) {
            return ValidationResult.success();
        }

        List<String> allErrors = new ArrayList<>(structural.errors());
        for (String term : safeModeErrors) {
            allErrors.add("JSON-LD safe mode: undefined term '" + term + "'");
        }
        return ValidationResult.failure(allErrors);
    }

    /**
     * Validate an OB 3.0 OpenBadgeCredential (W3C Verifiable Credential).
     * Performs structural validation only (no JSON-LD processing).
     */
    @SuppressWarnings("unchecked")
    public ValidationResult validate(Map<String, Object> document) {
        List<String> errors = new ArrayList<>();

        // @context must be an ordered array (W3C VC Data Model 2.0 §4.1):
        //   [0] = VC_CONTEXT (mandatory first)
        //   [1] = OB3_CONTEXT (mandatory second for OB 3.0)
        Object context = document.get("@context");
        if (context instanceof List<?> contextList) {
            if (contextList.size() < 2) {
                errors.add("@context must have at least 2 entries: VC context and OB 3.0 context");
            }
            if (contextList.isEmpty() || !VC_CONTEXT.equals(contextList.get(0))) {
                errors.add("@context[0] must be '" + VC_CONTEXT + "' (W3C VC Data Model 2.0 §4.1)");
            }
            if (contextList.size() < 2 || !OB3_CONTEXT.equals(contextList.get(1))) {
                errors.add("@context[1] must be '" + OB3_CONTEXT + "' (OB 3.0 spec requires it as the second context)");
            }
        } else {
            errors.add("@context must be an array for OB 3.0");
        }

        // type must include VerifiableCredential and OpenBadgeCredential (or AchievementCredential alias)
        Object type = document.get("type");
        if (type instanceof List<?> typeList) {
            if (!typeList.contains("VerifiableCredential")) {
                errors.add("type must include 'VerifiableCredential'");
            }
            // OB 3.0: AchievementCredential is defined as an alias for OpenBadgeCredential
            if (!typeList.contains("OpenBadgeCredential") && !typeList.contains("AchievementCredential")) {
                errors.add("type must include 'OpenBadgeCredential' (or alias 'AchievementCredential')");
            }
        } else {
            errors.add("type must be an array for OB 3.0");
        }

        // OB 3.0: 'name' is REQUIRED on OpenBadgeCredential (not SHOULD)
        validateRequiredFields(document,
                Set.of("id", "issuer", "validFrom", "credentialSubject", "name"), errors);
        validateIri(document, "id", errors);

        // Issuer validation: must be a string IRI or an object with {id, type="Profile", name}
        Object issuer = document.get("issuer");
        if (issuer instanceof String issuerStr) {
            if (!isIri(issuerStr)) {
                errors.add("issuer string must be a valid IRI");
            }
        } else if (issuer instanceof Map<?, ?> issuerMap) {
            if (issuerMap.get("id") == null) {
                errors.add("issuer.id is required");
            } else if (!isIri((String) issuerMap.get("id"))) {
                errors.add("issuer.id must be a valid IRI");
            }
            if (!"Profile".equals(issuerMap.get("type"))) {
                errors.add("issuer.type must be 'Profile'");
            }
            if (issuerMap.get("name") == null) {
                errors.add("issuer.name is required");
            }
        } else if (issuer != null) {
            errors.add("issuer must be a string IRI or object with {id, type, name}");
        }

        // credentialSubject validation
        Object subject = document.get("credentialSubject");
        if (subject instanceof Map<?, ?> subjectMap) {
            if (!"AchievementSubject".equals(subjectMap.get("type"))) {
                errors.add("credentialSubject.type must be 'AchievementSubject'");
            }

            // identifier validation (OB 3.0 §7.2: identifier is an array of IdentityObject)
            Object identifier = subjectMap.get("identifier");
            if (identifier instanceof List<?> identifierList) {
                for (int i = 0; i < identifierList.size(); i++) {
                    Object item = identifierList.get(i);
                    if (item instanceof Map<?, ?> idObj) {
                        if (!"IdentityObject".equals(idObj.get("type"))) {
                            errors.add("credentialSubject.identifier[" + i + "].type must be 'IdentityObject'");
                        }
                        if (idObj.get("identityHash") == null) {
                            errors.add("credentialSubject.identifier[" + i + "].identityHash is required");
                        }
                        if (idObj.get("identityType") == null) {
                            errors.add("credentialSubject.identifier[" + i + "].identityType is required");
                        }
                        // OB 3.0: 'hashed' is REQUIRED on IdentityObject
                        if (idObj.get("hashed") == null) {
                            errors.add("credentialSubject.identifier[" + i + "].hashed is required");
                        }
                    }
                }
            }

            // Achievement validation
            Object achievement = subjectMap.get("achievement");
            if (achievement == null) {
                errors.add("credentialSubject.achievement is required");
            } else if (achievement instanceof Map<?, ?> achievementMap) {
                if (achievementMap.get("id") == null) {
                    errors.add("achievement.id is required");
                }
                if (!"Achievement".equals(achievementMap.get("type"))) {
                    errors.add("achievement.type must be 'Achievement'");
                }
                if (achievementMap.get("name") == null) {
                    errors.add("achievement.name is required");
                }
                // OB 3.0: 'description' is OPTIONAL on Achievement (only id, type, name, criteria are required)
                if (achievementMap.get("criteria") == null) {
                    errors.add("achievement.criteria is required");
                }
            }
        }

        // credentialSchema validation (OB 3.0: recommended for interoperability)
        Object credentialSchema = document.get("credentialSchema");
        if (credentialSchema instanceof List<?> schemaList) {
            for (int i = 0; i < schemaList.size(); i++) {
                if (schemaList.get(i) instanceof Map<?, ?> schemaMap) {
                    if (schemaMap.get("id") == null) {
                        errors.add("credentialSchema[" + i + "].id is required");
                    }
                    if (schemaMap.get("type") == null) {
                        errors.add("credentialSchema[" + i + "].type is required");
                    }
                }
            }
        }

        // credentialStatus validation (if present)
        Object credentialStatus = document.get("credentialStatus");
        if (credentialStatus instanceof Map<?, ?> statusMap) {
            if (statusMap.get("id") == null) {
                errors.add("credentialStatus.id is required");
            }
            if (statusMap.get("type") == null) {
                errors.add("credentialStatus.type is required");
            }
            if (OpenBadgesContext.REVOCATION_LIST_TYPE.equals(statusMap.get("type"))) {
                if (statusMap.get("statusListIndex") == null) {
                    errors.add("credentialStatus.statusListIndex is required for " + OpenBadgesContext.REVOCATION_LIST_TYPE);
                }
                if (statusMap.get("statusListCredential") == null) {
                    errors.add("credentialStatus.statusListCredential is required for " + OpenBadgesContext.REVOCATION_LIST_TYPE);
                }
            }
        }

        // refreshService validation (if present)
        Object refreshService = document.get("refreshService");
        if (refreshService instanceof Map<?, ?> refreshMap) {
            if (refreshMap.get("id") == null) {
                errors.add("refreshService.id is required");
            }
            if (refreshMap.get("type") == null) {
                errors.add("refreshService.type is required");
            }
        }

        return errors.isEmpty() ? ValidationResult.success() : ValidationResult.failure(errors);
    }

    private void validateRequiredFields(Map<String, Object> document, Set<String> requiredFields, List<String> errors) {
        for (String field : requiredFields) {
            if (document.get(field) == null) {
                errors.add("Required field '" + field + "' is missing");
            }
        }
    }

    private void validateIri(Map<String, Object> document, String fieldName, List<String> errors) {
        Object value = document.get(fieldName);
        if (value instanceof String str && !isIri(str)) {
            errors.add(fieldName + " must be a valid IRI (http, https, or urn)");
        }
    }

    private boolean isIri(String value) {
        return value != null && (value.startsWith("http://") || value.startsWith("https://")
                || value.startsWith("urn:") || value.startsWith("did:"));
    }
}
