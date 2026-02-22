package work.brodykim.signet.core;

/**
 * Data carrier for the OB 3.0 GeoCoordinates object.
 *
 * @param latitude  REQUIRED
 * @param longitude REQUIRED
 */
public record BadgeGeoCoordinates(
        double latitude,
        double longitude
) {}
