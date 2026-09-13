package work.brodykim.signet;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;
import work.brodykim.signet.core.BadgeAchievement;
import work.brodykim.signet.core.BadgeIssuer;
import work.brodykim.signet.credential.CredentialBuilder;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Isolated("Temporarily changes the JVM default locale")
class RecipientLocaleTest {
    @Test
    void recipientIdentityIsStableAcrossServerLocales() {
        Locale original = Locale.getDefault();
        try {
            CredentialBuilder builder = new CredentialBuilder("https://campus.example", "test-salt");
            UUID id = UUID.randomUUID();
            BadgeAchievement achievement = new BadgeAchievement(UUID.randomUUID(), "Accessibility", "Audit",
                    "Complete a keyboard audit", "Badge", null, List.of());
            BadgeIssuer issuer = new BadgeIssuer(UUID.randomUUID(), "Campus", "https://campus.example", null, null);
            Instant issued = Instant.parse("2026-09-14T00:00:00Z");
            Locale.setDefault(Locale.US);
            var expected = builder.buildCredential(id, "ivan@example.com", null, achievement, issuer, issued);

            for (String languageTag : List.of("en-US", "tr-TR", "az-AZ", "lt-LT")) {
                Locale.setDefault(Locale.forLanguageTag(languageTag));
                assertEquals(expected, builder.buildCredential(id, " IVAN@EXAMPLE.COM ", null,
                        achievement, issuer, issued), "Recipient identity changed for " + languageTag);
            }
        } finally {
            Locale.setDefault(original);
        }
    }
}
