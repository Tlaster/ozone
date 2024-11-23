import org.jetbrains.dokka.gradle.AbstractDokkaTask
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import sh.christian.ozone.api.generator.ApiReturnType

plugins {
  id("ozone-dokka")
  id("ozone-multiplatform")
  id("ozone-publish")
  id("co.touchlab.kmmbridge")
  id("sh.christian.ozone.generator")
  id("org.jetbrains.kotlinx.binary-compatibility-validator")
}

ozone {
  js()
  jvm()
  ios("BlueskyAPI") {
    project.configurations[exportConfigurationName].extendsFrom(
      project.configurations["${target.name}CompilationApi"]
    )

    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    transitiveExport = true
  }
}

kmmbridge {
  mavenPublishArtifacts()
  spm()
}

dependencies {
  lexicons(project(":lexicons"))
}

lexicons {
  namespace.set("sh.christian.ozone.api.xrpc")

  defaults {
    generateUnknownsForSealedTypes.set(true)
    generateUnknownsForEnums.set(true)
  }

  generateApi("BlueskyApi") {
    packageName.set("sh.christian.ozone")
    withKtorImplementation("XrpcBlueskyApi")
    returnType.set(ApiReturnType.Response)
    exclude("""app\.bsky\.unspecced\..*""")
  }

  generateApi("UnspeccedBlueskyApi") {
    packageName.set("sh.christian.ozone.unspecced")
    withKtorImplementation("XrpcUnspeccedBlueskyApi")
    returnType.set(ApiReturnType.Response)
    include("""app\.bsky\.unspecced\..*""")
  }
}

val generateLexicons = tasks.generateLexicons
tasks.apiDump.configure { dependsOn(generateLexicons) }
tasks.apiCheck.configure { dependsOn(generateLexicons) }

tasks.withType<AbstractDokkaTask>().configureEach {
  dependsOn(tasks.withType<KotlinCompile>())
}
