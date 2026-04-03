package work.brodykim.signet.examples;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jose.jwk.OctetKeyPair;
import work.brodykim.signet.core.BadgeAchievement;
import work.brodykim.signet.core.BadgeAlignment;
import work.brodykim.signet.core.BadgeEvidence;
import work.brodykim.signet.core.BadgeIssuer;
import work.brodykim.signet.core.OpenBadgesValidator;
import work.brodykim.signet.core.OpenBadgesValidator.ValidationResult;
import work.brodykim.signet.credential.CredentialBuilder;
import work.brodykim.signet.credential.CredentialRequest;
import work.brodykim.signet.credential.CredentialSigner;
import work.brodykim.signet.credential.KeyPairManager;
import work.brodykim.signet.jsonld.CachedDocumentLoader;
import work.brodykim.signet.jsonld.JsonLdProcessor;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Open Badges 3.0 크리덴셜의 전체 워크플로우를 시연하는 통합 예제.
 *
 * <p>키 생성 → 크리덴셜 빌드 → 구조 검증 → EdDSA 서명 → 검증 → JWS 서명 → 발급자 프로필 출력
 * 순서로 전체 흐름을 보여줍니다.
 */
public class EndToEndExample {

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

        System.out.println("╔══════════════════════════════════════════════╗");
        System.out.println("║   Signet Core — End-to-End Example          ║");
        System.out.println("║   Open Badges 3.0 Verifiable Credentials    ║");
        System.out.println("╚══════════════════════════════════════════════╝");
        System.out.println();

        // ── Step 1: 키 생성 ─────────────────────────────────────────────

        System.out.println("[Step 1] Generating Ed25519 key pair...");
        OctetKeyPair keyPair = KeyPairManager.generateEd25519KeyPair();
        String publicKeyMultibase = KeyPairManager.toPublicKeyMultibase(keyPair);
        System.out.println("  Key ID:    " + keyPair.getKeyID());
        System.out.println("  Multibase: " + publicKeyMultibase);
        System.out.println();

        // ── Step 2: 크리덴셜 빌드 ───────────────────────────────────────

        System.out.println("[Step 2] Building credential...");

        BadgeIssuer issuer = new BadgeIssuer(
                UUID.randomUUID(),
                "Signet Academy",
                "https://signet-academy.example.com",
                "badges@signet-academy.example.com",
                "Open Badges 3.0 디지털 자격증 발급 기관"
        );

        BadgeAchievement achievement = new BadgeAchievement(
                UUID.randomUUID(),
                "Full-Stack Development",
                "풀스택 웹 개발 역량을 입증하는 자격증입니다.",
                "프론트엔드 및 백엔드 프로젝트를 완료해야 합니다.",
                "https://signet-academy.example.com/criteria/fullstack",
                "Certification",
                "https://signet-academy.example.com/badges/fullstack.png",
                List.of("fullstack", "web", "java", "react"),
                List.of(new BadgeAlignment(
                        "ISTE Computational Thinker",
                        "https://www.iste.org/standards/computational-thinker",
                        "Students develop and employ strategies for understanding and solving problems.",
                        "ISTE", "CT-5"))
        );

        List<BadgeEvidence> evidence = List.of(
                new BadgeEvidence(
                        "https://signet-academy.example.com/evidence/capstone",
                        "Capstone Project",
                        "풀스택 캡스톤 프로젝트",
                        "React + Spring Boot 기반의 e-커머스 플랫폼 구축",
                        "Portfolio")
        );

        CredentialBuilder builder = new CredentialBuilder(
                "https://signet-academy.example.com", "signet-salt");

        CredentialRequest request = CredentialRequest.builder(
                        UUID.randomUUID(), "student@example.com", achievement, issuer)
                .recipientName("김개발")
                .description("풀스택 웹 개발 전문가 인증서")
                .imageUrl("https://signet-academy.example.com/badges/fullstack.png")
                .evidence(evidence)
                .build();

        Map<String, Object> credential = builder.buildCredential(request);
        System.out.println(mapper.writeValueAsString(credential));
        System.out.println();

        // ── Step 3: 구조 검증 ───────────────────────────────────────────

        System.out.println("[Step 3] Validating credential structure...");
        OpenBadgesValidator validator = new OpenBadgesValidator();
        ValidationResult validationResult = validator.validate(credential);
        System.out.println("  Structural validation: " + (validationResult.valid() ? "PASS" : "FAIL"));
        if (!validationResult.errors().isEmpty()) {
            validationResult.errors().forEach(e -> System.out.println("    - " + e));
        }
        System.out.println();

        // ── Step 4: EdDSA DataIntegrity 서명 ────────────────────────────

        System.out.println("[Step 4] Signing with EdDSA DataIntegrity (eddsa-rdfc-2022)...");
        JsonLdProcessor jsonLdProcessor = new JsonLdProcessor(new CachedDocumentLoader());
        CredentialSigner signer = new CredentialSigner(mapper, jsonLdProcessor);

        Map<String, Object> signed = signer.signWithDataIntegrity(
                credential, keyPair,
                "https://signet-academy.example.com/issuers/1#key-1");
        System.out.println("  Proof added successfully.");
        System.out.println();

        // ── Step 5: 서명 검증 ───────────────────────────────────────────

        System.out.println("[Step 5] Verifying DataIntegrity signature...");
        boolean diValid = signer.verifyDataIntegrity(signed, keyPair.toPublicJWK());
        System.out.println("  DataIntegrity verification: " + (diValid ? "PASS" : "FAIL"));
        System.out.println();

        // ── Step 6: JWS 서명 ────────────────────────────────────────────

        System.out.println("[Step 6] Signing as JWS (VC-JWT)...");
        String jws = signer.signCredential(credential, keyPair);
        System.out.println("  JWS: " + jws.substring(0, 50) + "...");
        boolean jwsValid = signer.verifyCredential(jws, keyPair.toPublicJWK());
        System.out.println("  JWS verification: " + (jwsValid ? "PASS" : "FAIL"));
        System.out.println();

        // ── Step 7: 발급자 프로필 ───────────────────────────────────────

        System.out.println("[Step 7] Building issuer profile with verification method...");
        Map<String, Object> profile = builder.buildIssuerProfile(issuer, publicKeyMultibase);
        System.out.println(mapper.writeValueAsString(profile));
        System.out.println();

        System.out.println("Done! All steps completed successfully.");
    }
}
