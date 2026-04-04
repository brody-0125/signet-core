package work.brodykim.signet.examples;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import work.brodykim.signet.core.BadgeAchievement;
import work.brodykim.signet.core.BadgeEvidence;
import work.brodykim.signet.core.BadgeIssuer;
import work.brodykim.signet.credential.CredentialBuilder;
import work.brodykim.signet.credential.CredentialRequest;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Open Badges 3.0 크리덴셜을 빌드하는 기본 예제.
 *
 * <p>{@link CredentialBuilder}와 {@link CredentialRequest} 빌더 패턴을 사용하여
 * W3C Verifiable Credential 규격의 JSON-LD 문서를 생성합니다.
 */
public class BasicCredentialExample {

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

        // 1. 발급자(Issuer) 정의
        BadgeIssuer issuer = new BadgeIssuer(
                UUID.randomUUID(),
                "Signet Academy",
                "https://signet-academy.example.com",
                "badges@signet-academy.example.com",
                "Open Badges 3.0 기반 디지털 자격증 발급 기관"
        );

        // 2. 업적(Achievement) 정의
        BadgeAchievement achievement = new BadgeAchievement(
                UUID.randomUUID(),
                "Java Proficiency",
                "자바 프로그래밍 언어에 대한 전문성을 입증합니다.",
                "자바 인증 시험을 통과해야 합니다.",
                "Certification",
                "https://signet-academy.example.com/badges/java.png",
                List.of("java", "programming", "certification")
        );

        // 3. 증거(Evidence) 정의
        List<BadgeEvidence> evidence = List.of(
                new BadgeEvidence(
                        "https://signet-academy.example.com/evidence/project-1",
                        "Final Project",
                        "자바 기반 REST API 최종 프로젝트 제출",
                        "Spring Boot를 활용한 RESTful API 설계 및 구현",
                        "Portfolio"
                )
        );

        // 4. CredentialRequest 빌더로 요청 구성
        CredentialRequest request = CredentialRequest.builder(
                        UUID.randomUUID(),
                        "recipient@example.com",
                        achievement,
                        issuer
                )
                .recipientName("홍길동")
                .description("자바 프로그래밍 전문가 인증서")
                .imageUrl("https://signet-academy.example.com/badges/java.png")
                .evidence(evidence)
                .build();

        // 5. 크리덴셜 빌드
        CredentialBuilder builder = new CredentialBuilder(
                "https://signet-academy.example.com", "my-salt");
        Map<String, Object> credential = builder.buildCredential(request);

        // 6. 결과 출력
        System.out.println("=== Basic Credential Example ===");
        System.out.println();
        System.out.println(mapper.writeValueAsString(credential));
    }
}
