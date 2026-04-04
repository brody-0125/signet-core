package work.brodykim.signet.examples;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import work.brodykim.signet.core.BadgeIssuer;
import work.brodykim.signet.credential.CredentialBuilder;
import work.brodykim.signet.credential.KeyPairManager;
import work.brodykim.signet.credential.KeyPairManager.SerializedKeyPair;

import java.util.Map;
import java.util.UUID;

/**
 * 키 생성, 직렬화, Multibase 변환 예제.
 *
 * <p>Ed25519와 P-256 키 쌍의 전체 라이프사이클을 시연합니다:
 * 생성 → JWK 직렬화 → 역직렬화 → Multibase 인코딩 → 발급자 프로필에 포함.
 */
public class KeyManagementExample {

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

        System.out.println("=== Key Management Example ===");
        System.out.println();

        // ── Ed25519 키 ──────────────────────────────────────────────────

        System.out.println("--- Ed25519 Key Pair ---");
        OctetKeyPair ed25519Key = KeyPairManager.generateEd25519KeyPair();

        // JWK 직렬화
        SerializedKeyPair serialized = KeyPairManager.serializeKeyPair(ed25519Key);
        System.out.println("Public JWK:  " + serialized.publicJwk());
        System.out.println("Private JWK: " + serialized.privateJwk());
        System.out.println();

        // JWK 역직렬화
        OctetKeyPair restored = KeyPairManager.deserializePrivateKey(serialized.privateJwk());
        System.out.println("Deserialized key ID: " + restored.getKeyID());

        // Multibase 인코딩 (z6Mk... 접두사)
        String ed25519Multibase = KeyPairManager.toPublicKeyMultibase(ed25519Key);
        System.out.println("Multibase (Ed25519): " + ed25519Multibase);
        System.out.println();

        // ── P-256 키 ───────────────────────────────────────────────────

        System.out.println("--- P-256 (secp256r1) Key Pair ---");
        ECKey p256Key = KeyPairManager.generateP256KeyPair();

        System.out.println("Public JWK:  " + p256Key.toPublicJWK().toJSONString());
        System.out.println("Private JWK: " + p256Key.toJSONString());
        System.out.println();

        // Multibase 인코딩 (zDna... 접두사)
        String p256Multibase = KeyPairManager.toPublicKeyMultibase(p256Key);
        System.out.println("Multibase (P-256): " + p256Multibase);
        System.out.println();

        // ── 발급자 프로필에 공개키 포함 ──────────────────────────────────

        System.out.println("--- Issuer Profile with Verification Method ---");
        BadgeIssuer issuer = new BadgeIssuer(
                UUID.randomUUID(), "Signet Academy",
                "https://signet-academy.example.com",
                "badges@signet-academy.example.com",
                "디지털 자격증 발급 기관");

        CredentialBuilder builder = new CredentialBuilder(
                "https://signet-academy.example.com", "my-salt");
        Map<String, Object> profile = builder.buildIssuerProfile(issuer, ed25519Multibase);

        System.out.println(mapper.writeValueAsString(profile));
    }
}
