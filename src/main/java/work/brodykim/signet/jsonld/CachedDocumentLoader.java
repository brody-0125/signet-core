package work.brodykim.signet.jsonld;

import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.jsonld.JsonLdError;

import java.io.InputStream;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link DocumentLoader} that loads JSON-LD context documents from
 * classpath resources, with an in-memory cache for repeated requests.
 *
 * <p>Bundled contexts:
 * <ul>
 *   <li>{@code https://www.w3.org/ns/credentials/v2} — W3C VC Data Model 2.0</li>
 *   <li>{@code https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json} — OB 3.0</li>
 * </ul>
 *
 * <p><b>Security — signing/verification paths:</b> RDFC-1.0 canonicalization
 * resolves every {@code @context} URL through this loader, and the resulting
 * term definitions determine which IRIs appear in the canonical N-Quads. If
 * a remote loader is injected as a fallback, a network-positioned adversary
 * (or a compromised host) could alter a context document and thereby change
 * the signed bytes for the same credential. For that reason:
 *
 * <ul>
 *   <li>Use the no-arg {@link #CachedDocumentLoader()} on the signing and
 *       verification paths — unknown contexts will fail loudly instead of
 *       being fetched from the network.</li>
 *   <li>Only supply a fallback loader for non-cryptographic use cases
 *       (e.g. schema exploration, debugging), or supply one that pins
 *       context content by hash.</li>
 * </ul>
 */
public class CachedDocumentLoader implements DocumentLoader {

    private static final Map<String, String> CONTEXT_RESOURCES = Map.of(
            "https://www.w3.org/ns/credentials/v2",
            "/jsonld/credentials-v2.jsonld",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            "/jsonld/ob-v3p0-context-3.0.3.json"
    );

    private final Map<String, Document> cache = new ConcurrentHashMap<>();
    private final DocumentLoader fallback;

    public CachedDocumentLoader() {
        this(null);
    }

    public CachedDocumentLoader(DocumentLoader fallback) {
        this.fallback = fallback;
    }

    @Override
    public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {
        String urlStr = url.toString();

        Document cached = cache.get(urlStr);
        if (cached != null) {
            return cached;
        }

        String resourcePath = CONTEXT_RESOURCES.get(urlStr);
        if (resourcePath != null) {
            Document doc = loadFromClasspath(resourcePath, url);
            cache.put(urlStr, doc);
            return doc;
        }

        if (fallback != null) {
            Document doc = fallback.loadDocument(url, options);
            cache.put(urlStr, doc);
            return doc;
        }

        throw new JsonLdError(com.apicatalog.jsonld.JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                "Cannot load context: " + urlStr + " (not bundled and no fallback loader)");
    }

    private Document loadFromClasspath(String path, URI documentUrl) throws JsonLdError {
        try (InputStream is = getClass().getResourceAsStream(path)) {
            if (is == null) {
                throw new JsonLdError(com.apicatalog.jsonld.JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                        "Bundled context resource not found: " + path);
            }
            return JsonDocument.of(is);
        } catch (JsonLdError e) {
            throw e;
        } catch (Exception e) {
            throw new JsonLdError(com.apicatalog.jsonld.JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Failed to read context from classpath: " + path);
        }
    }
}
