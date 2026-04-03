plugins {
    java
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":"))
    // Jackson ObjectMapper — not transitively exposed by signet-core (implementation scope)
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.4")
}

application {
    mainClass.set(
        findProperty("example")?.toString()
            ?: "work.brodykim.signet.examples.EndToEndExample"
    )
}

tasks.withType<JavaCompile> {
    options.release = 17
}
