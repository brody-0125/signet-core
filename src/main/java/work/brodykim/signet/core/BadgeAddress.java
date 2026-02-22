package work.brodykim.signet.core;

/**
 * Data carrier for the OB 3.0 Address object.
 * All fields are optional per the spec.
 */
public record BadgeAddress(
        String addressCountry,
        String addressCountryCode,
        String addressLocality,
        String addressRegion,
        String streetAddress,
        String postalCode,
        String postOfficeBoxNumber,
        BadgeGeoCoordinates geo
) {
}
