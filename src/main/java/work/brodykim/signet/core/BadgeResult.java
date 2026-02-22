package work.brodykim.signet.core;

import java.util.List;

/**
 * Data carrier for the OB 3.0 Result object.
 * Represents a learner's actual result for an achievement.
 *
 * @param resultDescription URI reference to a {@link BadgeResultDescription#id()}
 * @param value             the result value (score, grade, etc.)
 * @param status            status of the result
 * @param achievedLevel     URI reference to a {@link BadgeRubricCriterionLevel#id()}
 * @param alignment         optional alignments for this result
 */
public record BadgeResult(
        String resultDescription,
        String value,
        String status,
        String achievedLevel,
        List<BadgeAlignment> alignment
) {
}
