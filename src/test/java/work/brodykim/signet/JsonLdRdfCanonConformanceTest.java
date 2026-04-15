package work.brodykim.signet;

import com.apicatalog.rdf.RdfDataset;
import com.apicatalog.rdf.io.nquad.NQuadsReader;
import com.apicatalog.rdf.io.nquad.NQuadsWriter;
import io.setl.rdf.normalization.RdfNormalize;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Conformance tests for RDFC-1.0 canonicalization against a subset of the
 * W3C {@code w3c/rdf-canon} official test vectors (from the {@code rdfc10}
 * directory).
 *
 * <p>These vectors exercise the parts of RDFC-1.0 that are hardest to get
 * right — specifically, blank node relabeling, isomorphic graph
 * identification, and literal handling. A failure here would indicate that
 * the library stack ({@code titanium-rdf-n-quads} for I/O plus
 * {@code io.setl:rdf-urdna} for canonicalization) does not match the W3C
 * spec, which would put every signed credential at risk.
 *
 * <p>We bypass {@link work.brodykim.signet.jsonld.JsonLdProcessor} and drive
 * the same underlying libraries directly with N-Quads input, because the
 * W3C vectors are given as N-Quads rather than JSON-LD. The JSON-LD →
 * RDF step is covered independently by {@link JsonLdProcessorTest}.
 *
 * <p>Source of vectors: <a href="https://github.com/w3c/rdf-canon/tree/main/tests/rdfc10">
 * w3c/rdf-canon {@code tests/rdfc10}</a>. Files live under
 * {@code src/test/resources/rdf-canon/}.
 */
class JsonLdRdfCanonConformanceTest {

    /** Test IDs bundled in {@code src/test/resources/rdf-canon/}. */
    private static final List<String> BUNDLED_TESTS = List.of(
            "001", // empty dataset
            "002", // duplicate property IRI values
            "003", // simple blank node relabeling
            "004", // blank node plus embedding
            "005", // blank node embedding
            "006", // multiple RDF types
            "017", // blank node dual-link non-embedding
            "020", // blank node diamond
            "021", // blank node circle of 2 (isomorphism)
            "043", // literal with language tag
            "053", // RDF Collections (@list)
            "054", // reordering / escaping
            "076"  // duplicate triple removal
    );

    @TestFactory
    Stream<DynamicTest> rdfc10ConformanceVectors() {
        return BUNDLED_TESTS.stream()
                .map(id -> DynamicTest.dynamicTest(
                        "rdfc10 test" + id,
                        () -> runVector(id)));
    }

    private void runVector(String id) throws Exception {
        String input = loadResource("/rdf-canon/test" + id + "-in.nq");
        String expected = loadResource("/rdf-canon/test" + id + "-rdfc10.nq");

        String actual = canonicalize(input);

        assertEquals(expected, actual,
                "RDFC-1.0 canonical output diverged from W3C vector test" + id
                        + ". This indicates either a library-stack regression or a "
                        + "configuration bug — every signature written by this library "
                        + "depends on this canonicalization being correct.");
    }

    /**
     * Parse N-Quads, canonicalize with URDNA2015, serialize back to N-Quads.
     * Mirrors the tail of {@code JsonLdProcessor#canonicalize} (steps 2 and 3).
     */
    private static String canonicalize(String nquads) throws Exception {
        RdfDataset parsed = new NQuadsReader(new StringReader(nquads)).readDataset();
        RdfDataset normalized = RdfNormalize.normalize(parsed);
        StringWriter sw = new StringWriter();
        new NQuadsWriter(sw).write(normalized);
        return sw.toString();
    }

    private static String loadResource(String path) throws IOException {
        try (InputStream is = JsonLdRdfCanonConformanceTest.class.getResourceAsStream(path)) {
            assertNotNull(is, "Missing bundled W3C rdf-canon test vector: " + path);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
