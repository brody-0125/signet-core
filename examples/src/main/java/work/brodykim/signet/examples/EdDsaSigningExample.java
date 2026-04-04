package work.brodykim.signet.examples;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jose.jwk.OctetKeyPair;
import work.brodykim.signet.credential.CredentialSigner;
import work.brodykim.signet.credential.KeyPairManager;
import work.brodykim.signet.jsonld.CachedDocumentLoader;
import work.brodykim.signet.jsonld.JsonLdProcessor;

import work.brodykim.signet.core.OpenBadgesContext;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * EdDSA (Ed25519) DataIntegrity 서명 및 검증 예제.
 *
 * <p>{@code eddsa-rdfc-2022} cryptosuite를 사용하여 RDFC-1.0 정규화 기반의
 * Data Integrity Proof를 생성하고 검증합니다.
 */
public class EdDsaSigningExample {

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

        // 1. Ed25519 키 쌍 생성
        OctetKeyPair keyPair = KeyPairManager.generateEd25519KeyPair();
        String multibase = KeyPairManager.toPublicKeyMultibase(keyPair);
        System.out.println("=== EdDSA (Ed25519) Signing Example ===");
        System.out.println();
        System.out.println("Public Key (multibase): " + multibase);
        System.out.println();

        // 2. 샘플 크리덴셜 구성
        Map<String, Object> credential = buildSampleCredential();

        // 3. CredentialSigner 초기화
        JsonLdProcessor jsonLdProcessor = new JsonLdProcessor(new CachedDocumentLoader());
        CredentialSigner signer = new CredentialSigner(mapper, jsonLdProcessor);

        // 4. DataIntegrity 서명 (eddsa-rdfc-2022)
        Map<String, Object> signed = signer.signWithDataIntegrity(
                credential, keyPair, "https://example.com/issuers/1#key-1");

        System.out.println("[Signed Credential]");
        System.out.println(mapper.writeValueAsString(signed));
        System.out.println();

        // 5. 서명 검증
        boolean valid = signer.verifyDataIntegrity(signed, keyPair.toPublicJWK());
        System.out.println("Verification result: " + valid);
        System.out.println();

        // 6. 변조 감지 시연
        Map<String, Object> tampered = new LinkedHashMap<>(signed);
        tampered.put("name", "Tampered Badge");
        boolean tamperedValid = signer.verifyDataIntegrity(tampered, keyPair.toPublicJWK());
        System.out.println("Tampered document verification: " + tamperedValid);
    }

    private static Map<String, Object> buildSampleCredential() {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", List.of(
                OpenBadgesContext.VC_CONTEXT,
                OpenBadgesContext.OB3_CONTEXT));
        credential.put("type", List.of("VerifiableCredential", "OpenBadgeCredential"));
        credential.put("id", "https://example.com/credentials/1");
        credential.put("issuer", Map.of(
                "id", "https://example.com/issuers/1",
                "type", "Profile",
                "name", "Example Issuer"));
        credential.put("validFrom", "2026-01-01T00:00:00Z");
        credential.put("name", "Example Badge");
        return credential;
    }
}
