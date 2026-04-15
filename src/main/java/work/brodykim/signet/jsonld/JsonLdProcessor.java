package work.brodykim.signet.jsonld;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.rdf.RdfDataset;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.rdf.RdfResource;
import com.apicatalog.rdf.RdfValue;
import com.apicatalog.rdf.io.nquad.NQuadsWriter;
import io.setl.rdf.normalization.RdfNormalize;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonValue;

import org.eclipse.rdf4j.model.IRI;
import org.eclipse.rdf4j.model.Model;
import org.eclipse.rdf4j.model.Resource;
import org.eclipse.rdf4j.model.Statement;
import org.eclipse.rdf4j.model.Value;
import org.eclipse.rdf4j.model.ValueFactory;
import org.eclipse.rdf4j.model.impl.LinkedHashModel;
import org.eclipse.rdf4j.model.impl.SimpleValueFactory;

import java.io.StringWriter;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * JSON-LD processing using Titanium JSON-LD + RDF4J + URDNA2015.
 *
 * <p>Provides RDFC-1.0 (URDNA2015) canonicalization for Data Integrity proofs:
 * <ol>
 *   <li>Convert JSON-LD document to RDF dataset (Titanium JSON-LD {@code toRdf})</li>
 *   <li>Canonicalize the dataset using URDNA2015 ({@code io.setl:rdf-urdna})</li>
 *   <li>Serialize canonical N-Quads for hashing</li>
 * </ol>
 *
 * <p>Also provides conversion to RDF4J {@link Model} for querying and validation.
 */
public class JsonLdProcessor {

    private final DocumentLoader documentLoader;

    public JsonLdProcessor(DocumentLoader documentLoader) {
        this.documentLoader = documentLoader;
    }

    /**
     * Canonicalize a JSON-LD document using RDFC-1.0 (URDNA2015).
     *
     * @param document JSON-LD document as a {@code Map<String, Object>}
     * @return canonical N-Quads as UTF-8 bytes, suitable for hashing
     */
    public byte[] canonicalize(Map<String, Object> document) {
        try {
            JsonObject jsonObject = mapToJsonObject(document);
            JsonDocument jsonDoc = JsonDocument.of(jsonObject);

            // Step 1: Convert JSON-LD → RDF dataset via Titanium
            RdfDataset dataset = JsonLd.toRdf(jsonDoc)
                    .loader(documentLoader)
                    .get();

            // Step 2: Canonicalize (URDNA2015 / RDFC-1.0)
            RdfDataset normalized = RdfNormalize.normalize(dataset);

            // Step 3: Serialize to canonical N-Quads
            StringWriter sw = new StringWriter();
            new NQuadsWriter(sw).write(normalized);
            return sw.toString().getBytes(StandardCharsets.UTF_8);
        } catch (JsonLdError e) {
            throw new IllegalStateException("JSON-LD processing failed during canonicalization", e);
        } catch (Exception e) {
            throw new IllegalStateException("RDFC-1.0 canonicalization failed", e);
        }
    }

    /**
     * Convert a JSON-LD document to an RDF4J {@link Model}.
     *
     * @param document JSON-LD document as a {@code Map<String, Object>}
     * @return RDF4J model containing all statements
     */
    public Model toRdf4jModel(Map<String, Object> document) {
        try {
            JsonObject jsonObject = mapToJsonObject(document);
            JsonDocument jsonDoc = JsonDocument.of(jsonObject);

            RdfDataset dataset = JsonLd.toRdf(jsonDoc)
                    .loader(documentLoader)
                    .get();

            return convertToRdf4j(dataset);
        } catch (JsonLdError e) {
            throw new IllegalStateException("JSON-LD to RDF conversion failed", e);
        }
    }

    /**
     * Convert Titanium {@link RdfDataset} to RDF4J {@link Model}.
     */
    Model convertToRdf4j(RdfDataset dataset) {
        Model model = new LinkedHashModel();
        ValueFactory vf = SimpleValueFactory.getInstance();

        for (RdfNQuad quad : dataset.toList()) {
            Resource subject = toRdf4jResource(quad.getSubject(), vf);
            IRI predicate = vf.createIRI(quad.getPredicate().getValue());
            Value object = toRdf4jValue(quad.getObject(), vf);

            Optional<RdfResource> graphName = quad.getGraphName();
            if (graphName.isPresent()) {
                Resource graph = toRdf4jResource(graphName.get(), vf);
                model.add(subject, predicate, object, graph);
            } else {
                model.add(subject, predicate, object);
            }
        }
        return model;
    }

    private Resource toRdf4jResource(RdfResource resource, ValueFactory vf) {
        if (resource.isBlankNode()) {
            return vf.createBNode(resource.getValue());
        }
        return vf.createIRI(resource.getValue());
    }

    private Value toRdf4jValue(RdfValue value, ValueFactory vf) {
        if (value.isBlankNode()) {
            return vf.createBNode(value.getValue());
        }
        if (value.isIRI()) {
            return vf.createIRI(value.getValue());
        }
        // Literal
        if (value.isLiteral()) {
            com.apicatalog.rdf.RdfLiteral literal = value.asLiteral();
            if (literal.getLanguage().isPresent()) {
                return vf.createLiteral(literal.getValue(), literal.getLanguage().get());
            }
            String datatype = literal.getDatatype();
            if (datatype != null) {
                return vf.createLiteral(literal.getValue(), vf.createIRI(datatype));
            }
            return vf.createLiteral(literal.getValue());
        }
        return vf.createLiteral(value.getValue());
    }

    /**
     * Validate a JSON-LD document in "safe mode" per W3C VC Data Model 2.0.
     *
     * <p>Safe mode requires that every property in the document is defined by
     * the document's {@code @context}. Properties not mapped to an IRI by the
     * context are considered undefined terms and MUST be rejected.
     *
     * <p>Implementation: expand the document (dropping undefined terms), then
     * compact it back with the same context. Any property present in the
     * original but missing after the round-trip is an undefined term.
     *
     * @param document JSON-LD document as a {@code Map<String, Object>}
     * @return list of undefined term paths (empty if all terms are defined)
     */
    public List<String> validateSafeMode(Map<String, Object> document) {
        try {
            JsonObject original = mapToJsonObject(document);

            JsonValue contextValue = original.get("@context");
            if (contextValue == null) {
                return List.of("Document has no @context");
            }

            // Expand: undefined terms are silently dropped
            JsonArray expanded = JsonLd.expand(JsonDocument.of(original))
                    .loader(documentLoader)
                    .get();

            // Compact back with the same context to restore compact key names
            JsonObject contextWrapper = Json.createObjectBuilder()
                    .add("@context", contextValue)
                    .build();
            JsonObject compacted = JsonLd.compact(
                    JsonDocument.of(expanded),
                    JsonDocument.of(contextWrapper)
            ).loader(documentLoader).get();

            // Compare: find properties dropped during the round-trip
            List<String> undefinedTerms = new ArrayList<>();
            findUndefinedTerms(original, compacted, "", undefinedTerms);
            return undefinedTerms;

        } catch (JsonLdError e) {
            return List.of("JSON-LD processing error: " + e.getMessage());
        }
    }

    private static final Set<String> JSON_LD_KEYWORDS = Set.of(
            "@context", "@id", "@type", "@value", "@language", "@container",
            "@list", "@set", "@reverse", "@index", "@base", "@vocab",
            "@graph", "@nest", "@prefix", "@propagate", "@protected",
            "@direction", "@import", "@included", "@json", "@none");

    private void findUndefinedTerms(JsonObject original, JsonObject compacted,
                                    String path, List<String> undefinedTerms) {
        for (String key : original.keySet()) {
            if (JSON_LD_KEYWORDS.contains(key)) continue;

            String currentPath = path.isEmpty() ? key : path + "." + key;

            if (!compacted.containsKey(key)) {
                undefinedTerms.add(currentPath);
                continue;
            }

            JsonValue origValue = original.get(key);
            JsonValue compValue = compacted.get(key);

            // Recurse into nested objects
            if (origValue.getValueType() == JsonValue.ValueType.OBJECT
                    && compValue.getValueType() == JsonValue.ValueType.OBJECT) {
                findUndefinedTerms(origValue.asJsonObject(), compValue.asJsonObject(),
                        currentPath, undefinedTerms);
            }
            // Recurse into arrays of objects
            else if (origValue.getValueType() == JsonValue.ValueType.ARRAY
                    && compValue.getValueType() == JsonValue.ValueType.ARRAY) {
                JsonArray origArr = origValue.asJsonArray();
                JsonArray compArr = compValue.asJsonArray();
                for (int i = 0; i < Math.min(origArr.size(), compArr.size()); i++) {
                    if (origArr.get(i).getValueType() == JsonValue.ValueType.OBJECT
                            && compArr.get(i).getValueType() == JsonValue.ValueType.OBJECT) {
                        findUndefinedTerms(origArr.get(i).asJsonObject(),
                                compArr.get(i).asJsonObject(),
                                currentPath + "[" + i + "]", undefinedTerms);
                    }
                }
            }
            // Handle compact form wrapping single object in array
            else if (origValue.getValueType() == JsonValue.ValueType.OBJECT
                    && compValue.getValueType() == JsonValue.ValueType.ARRAY) {
                JsonArray compArr = compValue.asJsonArray();
                if (!compArr.isEmpty()
                        && compArr.get(0).getValueType() == JsonValue.ValueType.OBJECT) {
                    findUndefinedTerms(origValue.asJsonObject(),
                            compArr.get(0).asJsonObject(), currentPath, undefinedTerms);
                }
            }
        }
    }

    /**
     * Convert a {@code Map<String, Object>} to a Jakarta {@link JsonObject}.
     */
    @SuppressWarnings("unchecked")
    static JsonObject mapToJsonObject(Map<String, Object> map) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            builder.add(normalizeNfc(entry.getKey()), toJsonValue(entry.getValue()));
        }
        return builder.build();
    }

    private static JsonArray listToJsonArray(List<?> list) {
        JsonArrayBuilder builder = Json.createArrayBuilder();
        for (Object item : list) {
            builder.add(toJsonValue(item));
        }
        return builder.build();
    }

    /**
     * Dispatch a Java value to its Jakarta {@link JsonValue} representation.
     * Strings are NFC-normalized (see {@link #normalizeNfc}); numeric widenings
     * preserve value (Float is routed through {@link BigDecimal} to avoid the
     * lossy {@code double} conversion that plain {@code builder.add(double)}
     * would perform).
     */
    @SuppressWarnings("unchecked")
    private static JsonValue toJsonValue(Object value) {
        if (value == null) {
            return JsonValue.NULL;
        } else if (value instanceof String s) {
            return Json.createValue(normalizeNfc(s));
        } else if (value instanceof Boolean b) {
            return b ? JsonValue.TRUE : JsonValue.FALSE;
        } else if (value instanceof Integer i) {
            return Json.createValue(i);
        } else if (value instanceof Long l) {
            return Json.createValue(l);
        } else if (value instanceof Short sh) {
            return Json.createValue(sh.intValue());
        } else if (value instanceof Byte by) {
            return Json.createValue(by.intValue());
        } else if (value instanceof Double d) {
            return Json.createValue(d);
        } else if (value instanceof Float f) {
            return Json.createValue(BigDecimal.valueOf(f.doubleValue()));
        } else if (value instanceof BigDecimal bd) {
            return Json.createValue(bd);
        } else if (value instanceof BigInteger bi) {
            return Json.createValue(bi);
        } else if (value instanceof Map<?, ?> nested) {
            return mapToJsonObject((Map<String, Object>) nested);
        } else if (value instanceof List<?> list) {
            return listToJsonArray(list);
        }
        throw new IllegalArgumentException(
                "Unsupported JSON-LD value type: " + value.getClass().getName()
                        + ". Supported: null, String, Boolean, numeric primitives, "
                        + "BigDecimal, BigInteger, Map, List.");
    }

    /**
     * Normalize a string to Unicode NFC before canonicalization.
     *
     * <p>RDFC-1.0 assumes input literals are already Unicode-normalized;
     * however, a VC issuer may emit a literal like {@code "é"} as either a
     * pre-composed code point (U+00E9) or as a combining sequence
     * (U+0065 U+0301). Both are semantically identical but produce different
     * N-Quads and therefore different signature hashes. To keep signing and
     * verification deterministic regardless of the caller's source encoding,
     * we apply NFC at the ingress boundary.
     */
    static String normalizeNfc(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        return Normalizer.isNormalized(s, Normalizer.Form.NFC)
                ? s
                : Normalizer.normalize(s, Normalizer.Form.NFC);
    }
}
