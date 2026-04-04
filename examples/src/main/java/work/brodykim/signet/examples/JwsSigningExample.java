package work.brodykim.signet.examples;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jose.jwk.OctetKeyPair;
import work.brodykim.signet.credential.CredentialSigner;
import work.brodykim.signet.credential.KeyPairManager;
import work.brodykim.signet.jsonld.CachedDocumentLoader;
import work.brodykim.signet.jsonld.JsonLdProcessor;

import java.util.Map;

/**
 * JWS (VC-JWT) 서명 및 검증 예제.
 *
 * <p>Ed25519 키를 사용한 JWS compact serialization 방식으로
 * 크리덴셜을 서명하고 검증합니다. URL-safe한 단일 문자열로 전달 가능합니다.
 */
public class JwsSigningExample {

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

        // 1. Ed25519 키 쌍 생성
        OctetKeyPair keyPair = KeyPairManager.generateEd25519KeyPair();
        System.out.println("=== JWS (VC-JWT) Signing Example ===");
        System.out.println();

        // 2. 크리덴셜 구성
        Map<String, Object> credential = Map.of(
                "type", "VerifiableCredential",
                "issuer", "https://example.com/issuers/1",
                "name", "JWS Example Badge"
        );

        System.out.println("[Original Credential]");
        System.out.println(mapper.writeValueAsString(credential));
        System.out.println();

        // 3. CredentialSigner 초기화
        JsonLdProcessor jsonLdProcessor = new JsonLdProcessor(new CachedDocumentLoader());
        CredentialSigner signer = new CredentialSigner(mapper, jsonLdProcessor);

        // 4. JWS 서명 — compact serialization (header.payload.signature)
        String jws = signer.signCredential(credential, keyPair);
        System.out.println("[JWS Token]");
        System.out.println(jws);
        System.out.println();

        // 5. JWS 검증
        boolean valid = signer.verifyCredential(jws, keyPair.toPublicJWK());
        System.out.println("Verification result: " + valid);
        System.out.println();

        // 6. 다른 키로 검증 시도 — 실패해야 함
        OctetKeyPair anotherKey = KeyPairManager.generateEd25519KeyPair();
        boolean wrongKeyValid = signer.verifyCredential(jws, anotherKey.toPublicJWK());
        System.out.println("Wrong key verification: " + wrongKeyValid);
    }
}
