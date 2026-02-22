package work.brodykim.signet.core;

import java.util.List;

/**
 * Data carrier for the OB 3.0 RubricCriterionLevel object.
 * Defines a level within a rubric criterion used by ResultDescription.
 *
 * @param id          REQUIRED — unique identifier URI
 * @param name        REQUIRED — display name of the level
 * @param description optional description
 * @param level       optional level identifier
 * @param points      optional point value
 * @param alignment   optional alignments for this level
 */
public record BadgeRubricCriterionLevel(
        String id,
        String name,
        String description,
        String level,
        String points,
        List<BadgeAlignment> alignment
) {}
