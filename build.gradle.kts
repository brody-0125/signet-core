import java.util.zip.ZipFile

plugins {
    `java-library`
    `maven-publish`
}
tasks.register("verifyPublicationNotices") {
    dependsOn("jar", "generatePomFileForMavenPublication")
    doLast {
        ZipFile(tasks.named<Jar>("jar").get().archiveFile.get().asFile).use { jar ->
            for (name in listOf("LICENSE", "NOTICE")) {
                val entry = checkNotNull(jar.getEntry("META-INF/$name")) { "Missing META-INF/$name" }
                check(jar.getInputStream(entry).use { it.readBytes() }.contentEquals(file(name).readBytes()))
            }
        }
        val pom = javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(layout.buildDirectory.file("publications/maven/pom-default.xml").get().asFile)
        val license = pom.getElementsByTagName("license")
        check(license.length == 1 && license.item(0).textContent.contains("https://www.apache.org/licenses/LICENSE-2.0.txt")) {
            "Published POM must declare Apache-2.0"
        }
    }
}

tasks.named("check") { dependsOn("verifyPublicationNotices") }

group = "work.brodykim"
version = "0.1.3"

repositories {
    mavenCentral()
}

dependencies {
    // Jackson for CredentialSigner (ObjectMapper)
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.4")

    // Ed25519 signing (OB v3) — exposed for consumers needing key operations
    api("com.nimbusds:nimbus-jose-jwt:10.7")
    api("com.google.crypto.tink:tink:1.20.0")

    // Titanium JSON-LD 1.1 processor for JSON-LD expansion and toRdf conversion
    api("com.apicatalog:titanium-json-ld:1.7.0")
    // Jakarta JSON Processing provider (required by Titanium JSON-LD)
    implementation("org.eclipse.parsson:parsson:1.1.7")

    // RDF4J for RDF model representation and N-Quads I/O
    implementation("org.eclipse.rdf4j:rdf4j-model:5.2.2")
    implementation("org.eclipse.rdf4j:rdf4j-rio-nquads:5.2.2")

    // URDNA2015 (RDFC-1.0) RDF Dataset Canonicalization using Titanium RDF model
    implementation("io.setl:rdf-urdna:1.4") {
        // Exclude jre8 variant — we use the Jakarta variant (titanium-json-ld)
        exclude(group = "com.apicatalog", module = "titanium-json-ld-jre8")
    }

    // Test — pure JUnit 5, no Spring
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        distribution.set("repo")
                    }
                }
            }
        }
    }
}

tasks.withType<JavaCompile> {
    options.release = 17
    options.compilerArgs.add("-parameters")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.named<Jar>("jar") {
    from(files("LICENSE", "NOTICE")) { into("META-INF") }
}
