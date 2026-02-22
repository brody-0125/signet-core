package work.brodykim.signet.core;

import java.util.List;

/**
 * Data carrier for the OB 3.0 ResultDescription object.
 * Defines the expected results for an Achievement (grading rubric, scoring criteria, etc.).
 *
 * @param id                   REQUIRED — unique identifier URI
 * @param name                 REQUIRED — display name
 * @param resultType           REQUIRED — one of the OB 3.0 result type enumeration values
 *                             (e.g. {@code GradePointAverage}, {@code LetterGrade},
 *                             {@code Percent}, {@code PerformanceLevel}, {@code RubricCriterion},
 *                             {@code ScaledScore}, {@code Status})
 * @param allowedValue         optional ordered list of allowed values
 * @param requiredLevel        optional URI of a required RubricCriterionLevel
 * @param requiredValue        optional required value
 * @param rubricCriterionLevel optional rubric criterion levels
 * @param valueMax             optional maximum value
 * @param valueMin             optional minimum value
 */
public record BadgeResultDescription(
        String id,
        String name,
        String resultType,
        List<String> allowedValue,
        String requiredLevel,
        String requiredValue,
        List<BadgeRubricCriterionLevel> rubricCriterionLevel,
        String valueMax,
        String valueMin
) {}
