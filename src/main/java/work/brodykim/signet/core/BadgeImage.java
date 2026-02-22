package work.brodykim.signet.core;

/**
 * Data carrier for the OB 3.0 Image object.
 * Use this when caption metadata is needed; a plain URL string is also
 * acceptable per the spec but cannot carry a caption.
 *
 * @param id      REQUIRED — URL of the image
 * @param caption optional image caption
 */
public record BadgeImage(
        String id,
        String caption
) {
}
