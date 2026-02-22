package work.brodykim.signet.core;

/**
 * Public constants for Open Badges 3.0 JSON-LD context URLs.
 * Use these when constructing custom JSON-LD documents or validating context arrays.
 */
public final class OpenBadgesContext {

    private OpenBadgesContext() {}

    /** W3C Verifiable Credentials Data Model 2.0 context (must be first in @context array). */
    public static final String VC_CONTEXT = "https://www.w3.org/ns/credentials/v2";

    /** OB 3.0 JSON-LD context (1EdTech Open Badges v3.0.3). */
    public static final String OB3_CONTEXT = "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json";

    /** OB 3.0 AchievementCredential JSON Schema URL for credentialSchema validation. */
    public static final String OB3_CREDENTIAL_SCHEMA_URL =
            "https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json";

    /** 1EdTech JSON Schema validator type for credentialSchema. */
    public static final String CREDENTIAL_SCHEMA_TYPE = "1EdTechJsonSchemaValidator2019";

    /** 1EdTech revocation list type for credentialStatus. */
    public static final String REVOCATION_LIST_TYPE = "1EdTechRevocationList";

    /** 1EdTech credential refresh type for refreshService. */
    public static final String CREDENTIAL_REFRESH_TYPE = "1EdTechCredentialRefresh";

    /** OB 3.0 baking namespace URI for SVG embedding. */
    public static final String OB3_BAKING_NAMESPACE = "https://purl.imsglobal.org/ob/v3p0";
}
